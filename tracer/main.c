/*
 * phptracer — userspace loader / consumer.
 *
 *  - scans /proc for PHP processes (php-fpm 8.3 workers, apache2+mod_php 7.4)
 *  - resolves executor_globals / sapi_globals runtime addresses
 *    (ELF dynsym st_value + per-pid base from /proc/pid/maps: PIE / DSO)
 *  - feeds the per-pid config map (addresses + version-specific zend
 *    struct offsets) consumed by the BPF programs
 *  - attaches request-boundary uprobes (php_request_startup/shutdown),
 *    the mysqlnd conn_data::query uprobe (address recovered from the
 *    exported method table — the function itself is static & stripped),
 *    and a 99Hz CPU-clock perf_event sampler on every CPU
 *  - consumes the ring buffer, resolves zend_function* -> "Class::method"
 *    via process_vm_readv (cached), writes ndjson to DATA_DIR
 */
#define _GNU_SOURCE /* process_vm_readv */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "phptrace.h"
#include "offsets_php83.h"
#include "offsets_php74.h"

#define BPF_OBJ_PATH_DEFAULT "/opt/phptrace/phptrace.bpf.o"
#define MAX_TRACKED 4096

/* What to look for in /proc and where that binary keeps the PHP runtime. */
struct target_def {
    const char *exe_basename;
    const char *lib_substr; /* NULL: symbols live in the exe itself */
    struct php_offsets off;
};

static const struct target_def targets[] = {
    { "php-fpm", NULL,     PHP83_OFFSETS_INIT },
    { "apache2", "libphp", PHP74_OFFSETS_INIT },
};
#define NTARGETS (sizeof(targets) / sizeof(targets[0]))

static volatile sig_atomic_t stop;
static void on_sigint(int sig) { (void)sig; stop = 1; }

/* ---------------------------------------------------------------- utils */

static long long now_mono_to_wall_off; /* wall_ns = mono_ns + off */

static void init_clock_offset(void)
{
    struct timespec mono, real;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_REALTIME, &real);
    now_mono_to_wall_off =
        (real.tv_sec - mono.tv_sec) * 1000000000LL + (real.tv_nsec - mono.tv_nsec);
}

static unsigned long long wall_ns(unsigned long long mono) {
    return mono + now_mono_to_wall_off;
}

static int read_mem(pid_t pid, unsigned long long addr, void *buf, size_t len)
{
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)addr, .iov_len = len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return n == (ssize_t)len ? 0 : -1;
}

static int read_u64(pid_t pid, unsigned long long addr, unsigned long long *out)
{
    return read_mem(pid, addr, out, sizeof(*out));
}

/* JSON string escaper (also folds control chars). */
static void json_escape(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && o + 6 < outsz; p++) {
        if (*p == '"' || *p == '\\') { out[o++] = '\\'; out[o++] = *p; }
        else if (*p < 0x20) { o += snprintf(out + o, outsz - o, "\\u%04x", *p); }
        else out[o++] = *p;
    }
    out[o] = 0;
}

/* Frame names go into folded stacks: strip separators. */
static void sanitize_frame(char *s)
{
    for (; *s; s++)
        if (*s == ';' || *s == '"' || *s == '\\' || (unsigned char)*s < 0x20)
            *s = '_';
}

/* ------------------------------------------------------------ ELF layer */

struct bin_syms {
    unsigned long long eg;       /* executor_globals st_value (0 if absent) */
    unsigned long long sg;       /* sapi_globals */
    unsigned long long mysqlnd_methods;
};

static int elf_each_symtab(Elf *elf, struct bin_syms *out)
{
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn))) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr))
            continue;
        if (shdr.sh_type != SHT_DYNSYM && shdr.sh_type != SHT_SYMTAB)
            continue;
        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data)
            continue;
        size_t count = shdr.sh_size / shdr.sh_entsize;
        for (size_t i = 0; i < count; i++) {
            GElf_Sym sym;
            if (!gelf_getsym(data, i, &sym))
                continue;
            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || !sym.st_value)
                continue;
            if (!strcmp(name, "executor_globals")) out->eg = sym.st_value;
            else if (!strcmp(name, "sapi_globals")) out->sg = sym.st_value;
            else if (!strcmp(name, "mysqlnd_mysqlnd_conn_data_methods"))
                out->mysqlnd_methods = sym.st_value;
        }
    }
    return out->eg ? 0 : -1;
}

static int resolve_bin_syms(const char *path, struct bin_syms *out)
{
    memset(out, 0, sizeof(*out));
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    int rc = elf ? elf_each_symtab(elf, out) : -1;
    if (elf)
        elf_end(elf);
    close(fd);
    return rc;
}

/* virtual address -> file offset (for manual uprobe placement) */
static long long vaddr_to_file_off(const char *path, unsigned long long vaddr)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    long long ret = -1;
    if (elf) {
        size_t phnum;
        if (!elf_getphdrnum(elf, &phnum)) {
            for (size_t i = 0; i < phnum; i++) {
                GElf_Phdr ph;
                if (!gelf_getphdr(elf, i, &ph))
                    continue;
                if (ph.p_type == PT_LOAD && vaddr >= ph.p_vaddr &&
                    vaddr < ph.p_vaddr + ph.p_filesz) {
                    ret = (long long)(vaddr - ph.p_vaddr + ph.p_offset);
                    break;
                }
            }
        }
        elf_end(elf);
    }
    close(fd);
    return ret;
}

/* Base of the mapping of `path` (as it appears in maps) inside pid:
 * first mapping of that path with file offset 0. */
static unsigned long long find_base(pid_t pid, const char *path)
{
    char mapsp[64];
    snprintf(mapsp, sizeof(mapsp), "/proc/%d/maps", pid);
    FILE *f = fopen(mapsp, "r");
    if (!f)
        return 0;
    char line[512];
    unsigned long long base = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end, off;
        char perms[8], dev[16];
        unsigned long ino;
        char mpath[256] = "";
        int n = sscanf(line, "%llx-%llx %7s %llx %15s %lu %255s",
                       &start, &end, perms, &off, dev, &ino, mpath);
        if (n >= 7 && off == 0 && !strcmp(mpath, path)) {
            base = start;
            break;
        }
    }
    fclose(f);
    return base;
}

/* Find the first mapped file whose path contains `substr` (e.g. "libphp").
 * Writes the in-namespace path to `out`. */
static int find_lib(pid_t pid, const char *substr, char *out, size_t outsz)
{
    char mapsp[64];
    snprintf(mapsp, sizeof(mapsp), "/proc/%d/maps", pid);
    FILE *f = fopen(mapsp, "r");
    if (!f)
        return -1;
    char line[512];
    int rc = -1;
    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, '/');
        if (!p)
            continue;
        p[strcspn(p, "\n")] = 0;
        if (strstr(p, substr)) {
            snprintf(out, outsz, "%s", p);
            rc = 0;
            break;
        }
    }
    fclose(f);
    return rc;
}

/* -------------------------------------------------------- proc tracking */

struct tracked {
    pid_t pid;
    bool alive;
    const struct php_offsets *off;
};

static struct tracked tracked[MAX_TRACKED];
static int ntracked;

static struct tracked *find_tracked(pid_t pid)
{
    for (int i = 0; i < ntracked; i++)
        if (tracked[i].pid == pid)
            return &tracked[i];
    return NULL;
}

/* One entry per distinct PHP binary/DSO we have attached uprobes to. */
struct attached_bin {
    dev_t dev;
    ino_t ino;
    struct bin_syms syms;
};
static struct attached_bin attached_bins[64];
static int nattached_bins;

struct ctx {
    struct bpf_object *obj;
    int procs_fd;
    struct bpf_program *p_req_start, *p_req_end, *p_query, *p_query_ret;
    /* keep links alive */
    struct bpf_link *links[512];
    int nlinks;
};

static void add_link(struct ctx *c, struct bpf_link *l)
{
    if (l && c->nlinks < (int)(sizeof(c->links) / sizeof(c->links[0])))
        c->links[c->nlinks++] = l;
}

/* Attach per-binary uprobes the first time we see a given dev:ino.
 * `access_path` must be openable from this process (/proc/<pid>/exe or
 * /proc/<pid>/root/...); `ns_path` is the path as the target sees it. */
static struct attached_bin *ensure_bin_attached(struct ctx *c, pid_t pid,
                                                const char *access_path,
                                                const char *ns_path,
                                                const struct target_def *tgt)
{
    struct stat st;
    if (stat(access_path, &st))
        return NULL;
    for (int i = 0; i < nattached_bins; i++)
        if (attached_bins[i].dev == st.st_dev && attached_bins[i].ino == st.st_ino)
            return &attached_bins[i];
    if (nattached_bins >= 64)
        return NULL;

    struct attached_bin *b = &attached_bins[nattached_bins];
    if (resolve_bin_syms(access_path, &b->syms)) {
        fprintf(stderr, "phptracer: %s: no executor_globals symbol, skipping\n",
                ns_path);
        return NULL;
    }
    b->dev = st.st_dev;
    b->ino = st.st_ino;

    /* request boundary uprobes, resolved by symbol name (dynsym) */
    LIBBPF_OPTS(bpf_uprobe_opts, uopts, .func_name = "php_request_startup");
    struct bpf_link *l =
        bpf_program__attach_uprobe_opts(c->p_req_start, -1, access_path, 0, &uopts);
    if (!l)
        fprintf(stderr, "phptracer: attach php_request_startup failed: %s\n",
                strerror(errno));
    add_link(c, l);

    LIBBPF_OPTS(bpf_uprobe_opts, uopts2, .func_name = "php_request_shutdown");
    l = bpf_program__attach_uprobe_opts(c->p_req_end, -1, access_path, 0, &uopts2);
    if (!l)
        fprintf(stderr, "phptracer: attach php_request_shutdown failed: %s\n",
                strerror(errno));
    add_link(c, l);

    /* mysqlnd conn_data::query — static fn; recover its address from the
     * exported method table in the live (relocated) process image. */
    if (b->syms.mysqlnd_methods) {
        unsigned long long base = find_base(pid, ns_path);
        unsigned long long fnaddr = 0;
        if (base &&
            !read_u64(pid, base + b->syms.mysqlnd_methods + tgt->off.mysqlnd_m_query,
                      &fnaddr) &&
            fnaddr > 0) {
            long long foff = vaddr_to_file_off(access_path, fnaddr - base);
            if (foff > 0) {
                l = bpf_program__attach_uprobe(c->p_query, false, -1, access_path,
                                               (size_t)foff);
                add_link(c, l);
                struct bpf_link *lr = bpf_program__attach_uprobe(
                    c->p_query_ret, true, -1, access_path, (size_t)foff);
                add_link(c, lr);
                fprintf(stderr,
                        "phptracer: mysqlnd query probe at file offset 0x%llx (%s)\n",
                        foff, l && lr ? "ok" : "FAILED");
            }
        }
    }

    fprintf(stderr, "phptracer: attached to %s (eg=0x%llx sg=0x%llx)\n",
            ns_path, b->syms.eg, b->syms.sg);
    nattached_bins++;
    return b;
}

static void scan_procs(struct ctx *c)
{
    for (int i = 0; i < ntracked; i++)
        tracked[i].alive = false;

    DIR *d = opendir("/proc");
    if (!d)
        return;
    struct dirent *de;
    while ((de = readdir(d))) {
        char *end;
        long pid = strtol(de->d_name, &end, 10);
        if (*end || pid <= 0)
            continue;

        char exe_link[64], exe_path[256];
        snprintf(exe_link, sizeof(exe_link), "/proc/%ld/exe", pid);
        ssize_t n = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (n <= 0)
            continue;
        exe_path[n] = 0;

        const char *bn = strrchr(exe_path, '/');
        bn = bn ? bn + 1 : exe_path;
        const struct target_def *tgt = NULL;
        for (size_t t = 0; t < NTARGETS; t++)
            if (!strncmp(bn, targets[t].exe_basename,
                         strlen(targets[t].exe_basename))) {
                tgt = &targets[t];
                break;
            }
        if (!tgt)
            continue;

        struct tracked *tr = find_tracked(pid);
        if (tr) {
            tr->alive = true;
            continue;
        }

        /* where do the PHP symbols live for this process? */
        char ns_path[256], access_path[512];
        if (tgt->lib_substr) {
            if (find_lib(pid, tgt->lib_substr, ns_path, sizeof(ns_path)))
                continue; /* e.g. apache without mod_php */
            snprintf(access_path, sizeof(access_path), "/proc/%ld/root%s", pid,
                     ns_path);
        } else {
            snprintf(ns_path, sizeof(ns_path), "%s", exe_path);
            snprintf(access_path, sizeof(access_path), "/proc/%ld/exe", pid);
        }

        struct attached_bin *b = ensure_bin_attached(c, pid, access_path, ns_path, tgt);
        if (!b)
            continue;
        unsigned long long base = find_base(pid, ns_path);
        if (!base)
            continue;

        struct proc_cfg cfg = {
            .eg_addr = base + b->syms.eg,
            .sg_addr = b->syms.sg ? base + b->syms.sg : 0,
            .off = tgt->off,
        };
        __u32 key = pid;
        if (!bpf_map_update_elem(c->procs_fd, &key, &cfg, BPF_ANY) &&
            ntracked < MAX_TRACKED) {
            tracked[ntracked].pid = pid;
            tracked[ntracked].alive = true;
            tracked[ntracked].off = &tgt->off;
            ntracked++;
            fprintf(stderr, "phptracer: tracking pid %ld [%s] (eg@0x%llx)\n", pid,
                    tgt->exe_basename, cfg.eg_addr);
        }
    }
    closedir(d);

    /* drop exited pids */
    for (int i = 0; i < ntracked;) {
        if (!tracked[i].alive) {
            __u32 key = tracked[i].pid;
            bpf_map_delete_elem(c->procs_fd, &key);
            tracked[i] = tracked[--ntracked];
        } else {
            i++;
        }
    }
}

/* ----------------------------------------------------- name resolution */

#define CACHE_SLOTS 65536
struct cache_ent {
    unsigned long long key; /* func ptr ^ (pid<<1) */
    char *name;
};
static struct cache_ent cache[CACHE_SLOTS];

static const char *cache_get(unsigned long long key)
{
    for (size_t i = key % CACHE_SLOTS, probes = 0; probes < 64;
         i = (i + 1) % CACHE_SLOTS, probes++) {
        if (!cache[i].name)
            return NULL;
        if (cache[i].key == key)
            return cache[i].name;
    }
    return NULL;
}

static void cache_put(unsigned long long key, const char *name)
{
    for (size_t i = key % CACHE_SLOTS, probes = 0; probes < 64;
         i = (i + 1) % CACHE_SLOTS, probes++) {
        if (!cache[i].name) {
            cache[i].key = key;
            cache[i].name = strdup(name);
            return;
        }
        if (cache[i].key == key)
            return;
    }
}

static int read_zstr(pid_t pid, unsigned long long zs, const struct php_offsets *off,
                     char *buf, size_t bufsz)
{
    unsigned long long len = 0;
    if (read_mem(pid, zs + off->zstr_len, &len, sizeof(len)))
        return -1;
    if (len >= bufsz)
        len = bufsz - 1;
    if (len && read_mem(pid, zs + off->zstr_val, buf, len))
        return -1;
    buf[len] = 0;
    return 0;
}

static const char *resolve_func(pid_t pid, unsigned long long func)
{
    static char out[512];
    if (!func)
        return "<null>";

    struct tracked *tr = find_tracked(pid);
    const struct php_offsets *off = tr ? tr->off : &targets[0].off;

    unsigned long long key = func ^ ((unsigned long long)pid << 1);
    const char *hit = cache_get(key);
    if (hit)
        return hit;

    char name[256] = "", cls[128] = "";
    unsigned long long fname = 0, scope = 0;

    if (read_u64(pid, func + off->func_name, &fname)) {
        return "<gone>"; /* don't cache: process may have just exited */
    }

    if (fname) {
        if (read_zstr(pid, fname, off, name, sizeof(name)))
            snprintf(name, sizeof(name), "<badname>");
        if (!read_u64(pid, func + off->func_scope, &scope) && scope) {
            unsigned long long cn = 0;
            if (!read_u64(pid, scope + off->ce_name, &cn) && cn)
                read_zstr(pid, cn, off, cls, sizeof(cls));
        }
    } else {
        /* main op_array: label with the script file */
        unsigned long long file = 0;
        char fbuf[192] = "";
        if (!read_u64(pid, func + off->oparr_filename, &file) && file)
            read_zstr(pid, file, off, fbuf, sizeof(fbuf));
        const char *b = strrchr(fbuf, '/');
        snprintf(name, sizeof(name), "{main:%s}", b ? b + 1 : fbuf);
    }

    if (cls[0])
        snprintf(out, sizeof(out), "%s::%s", cls, name);
    else
        snprintf(out, sizeof(out), "%s", name);
    sanitize_frame(out);
    cache_put(key, out);
    return out;
}

/* --------------------------------------------------------- event sinks */

static FILE *f_samples, *f_requests, *f_queries;

struct open_req {
    unsigned long long ts;
    char method[MAX_METHOD];
    char uri[MAX_URI];
    bool open;
};
/* pid -> open request (small linear table; php pools are small) */
static struct { pid_t pid; struct open_req req; } open_reqs[MAX_TRACKED];
static int nopen_reqs;

static struct open_req *req_slot(pid_t pid)
{
    for (int i = 0; i < nopen_reqs; i++)
        if (open_reqs[i].pid == pid)
            return &open_reqs[i].req;
    if (nopen_reqs >= MAX_TRACKED)
        return NULL;
    open_reqs[nopen_reqs].pid = pid;
    memset(&open_reqs[nopen_reqs].req, 0, sizeof(struct open_req));
    return &open_reqs[nopen_reqs++].req;
}

/* Fold a leaf-first frame array into a root-first "a;b;c" stack string. */
static void fold_stack(pid_t pid, const unsigned long long *frames, unsigned nframes,
                       char *out, size_t outsz)
{
    size_t o = 0;
    for (int i = (int)nframes - 1; i >= 0; i--) {
        const char *nm = resolve_func(pid, frames[i]);
        size_t l = strlen(nm);
        if (o + l + 2 >= outsz)
            break;
        if (o)
            out[o++] = ';';
        memcpy(out + o, nm, l);
        o += l;
    }
    out[o] = 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    struct ev_hdr *h = data;
    if (len < sizeof(*h))
        return 0;

    switch (h->type) {
    case EV_SAMPLE: {
        struct ev_sample *e = data;
        if (!e->nframes)
            break;
        char stack[8192];
        fold_stack(h->pid, e->frames, e->nframes, stack, sizeof(stack));
        fprintf(f_samples, "{\"ts\":%llu,\"pid\":%u,\"stack\":\"%s\"}\n",
                wall_ns(h->ts), h->pid, stack);
        break;
    }
    case EV_REQ_START: {
        struct ev_req *e = data;
        struct open_req *r = req_slot(h->pid);
        if (r) {
            r->ts = h->ts;
            r->open = true;
            memcpy(r->method, e->method, MAX_METHOD);
            memcpy(r->uri, e->uri, MAX_URI);
        }
        break;
    }
    case EV_REQ_END: {
        struct open_req *r = req_slot(h->pid);
        if (r && r->open) {
            char uri_esc[MAX_URI * 6], m_esc[MAX_METHOD * 6];
            json_escape(r->uri, uri_esc, sizeof(uri_esc));
            json_escape(r->method, m_esc, sizeof(m_esc));
            fprintf(f_requests,
                    "{\"pid\":%u,\"start_ns\":%llu,\"end_ns\":%llu,\"dur_us\":%llu,"
                    "\"method\":\"%s\",\"uri\":\"%s\"}\n",
                    h->pid, wall_ns(r->ts), wall_ns(h->ts),
                    (h->ts - r->ts) / 1000, m_esc, uri_esc);
            r->open = false;
        }
        break;
    }
    case EV_QUERY: {
        struct ev_query *e = data;
        char q_esc[MAX_QUERY * 6];
        json_escape(e->query, q_esc, sizeof(q_esc));
        char stack[8192];
        fold_stack(h->pid, e->frames, e->nframes, stack, sizeof(stack));
        fprintf(f_queries,
                "{\"pid\":%u,\"ts\":%llu,\"dur_us\":%llu,\"query\":\"%s\",\"stack\":\"%s\"}\n",
                h->pid, wall_ns(h->ts), e->dur_ns / 1000, q_esc, stack);
        break;
    }
    }
    return 0;
}

/* -------------------------------------------------------------- perf fd */

static int attach_sampler(struct ctx *c, struct bpf_program *prog, int freq)
{
    int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    int ok = 0;
    for (int cpu = 0; cpu < ncpu; cpu++) {
        struct perf_event_attr attr = {
            .type = PERF_TYPE_SOFTWARE,
            .size = sizeof(attr),
            .config = PERF_COUNT_SW_CPU_CLOCK,
            .sample_freq = (unsigned)freq,
            .freq = 1,
        };
        int fd = syscall(SYS_perf_event_open, &attr, -1, cpu, -1, 0);
        if (fd < 0) {
            fprintf(stderr, "phptracer: perf_event_open cpu%d: %s\n", cpu,
                    strerror(errno));
            continue;
        }
        struct bpf_link *l = bpf_program__attach_perf_event(prog, fd);
        if (!l) {
            close(fd);
            continue;
        }
        add_link(c, l);
        ok++;
    }
    return ok ? 0 : -1;
}

/* ------------------------------------------------------------------ main */

static FILE *open_sink(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "a");
    if (!f) {
        fprintf(stderr, "phptracer: cannot open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    setvbuf(f, NULL, _IOLBF, 1 << 16);
    return f;
}

int main(void)
{
    const char *data_dir = getenv("DATA_DIR") ?: "/data";
    const char *obj_path = getenv("BPF_OBJ") ?: BPF_OBJ_PATH_DEFAULT;
    int freq = atoi(getenv("SAMPLE_FREQ") ?: "99");
    if (freq <= 0)
        freq = 99;

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    elf_version(EV_CURRENT);
    init_clock_offset();

    f_samples = open_sink(data_dir, "samples.ndjson");
    f_requests = open_sink(data_dir, "requests.ndjson");
    f_queries = open_sink(data_dir, "db_queries.ndjson");

    struct ctx c = {0};
    c.obj = bpf_object__open_file(obj_path, NULL);
    if (!c.obj || bpf_object__load(c.obj)) {
        fprintf(stderr, "phptracer: failed to open/load %s\n", obj_path);
        return 1;
    }
    c.procs_fd = bpf_object__find_map_fd_by_name(c.obj, "procs");
    c.p_req_start = bpf_object__find_program_by_name(c.obj, "on_req_start");
    c.p_req_end = bpf_object__find_program_by_name(c.obj, "on_req_end");
    c.p_query = bpf_object__find_program_by_name(c.obj, "on_query");
    c.p_query_ret = bpf_object__find_program_by_name(c.obj, "on_query_ret");
    struct bpf_program *p_sample =
        bpf_object__find_program_by_name(c.obj, "on_sample");
    if (c.procs_fd < 0 || !c.p_req_start || !c.p_req_end || !p_sample) {
        fprintf(stderr, "phptracer: BPF object missing progs/maps\n");
        return 1;
    }

    /* If the loader is not in the global pid namespace (k8s), tell the BPF
     * side our ns so it reports matching pids. Controlled by NS_PIDS=1. */
    if ((getenv("NS_PIDS") ?: "0")[0] == '1') {
        int nfd = bpf_object__find_map_fd_by_name(c.obj, "nscfg");
        struct stat ns;
        if (nfd >= 0 && !stat("/proc/self/ns/pid", &ns)) {
            struct { unsigned long long dev, ino; } v = { ns.st_dev, ns.st_ino };
            __u32 k = 0;
            bpf_map_update_elem(nfd, &k, &v, BPF_ANY);
            fprintf(stderr, "phptracer: ns-scoped pids (dev=%llu ino=%llu)\n",
                    v.dev, v.ino);
        }
    }

    if (attach_sampler(&c, p_sample, freq)) {
        fprintf(stderr, "phptracer: sampler attach failed\n");
        return 1;
    }
    fprintf(stderr, "phptracer: sampling at %d Hz\n", freq);

    int rb_fd = bpf_object__find_map_fd_by_name(c.obj, "events");
    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "phptracer: ring_buffer__new failed\n");
        return 1;
    }

    time_t last_scan = 0;
    while (!stop) {
        time_t now = time(NULL);
        if (now != last_scan) {
            scan_procs(&c);
            last_scan = now;
        }
        int err = ring_buffer__poll(rb, 200 /* ms */);
        if (err < 0 && err != -EINTR)
            break;
    }

    fprintf(stderr, "phptracer: exiting\n");
    ring_buffer__free(rb);
    bpf_object__close(c.obj);
    return 0;
}
