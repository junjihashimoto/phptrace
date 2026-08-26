/*
 * native-tracer — language-agnostic on-CPU sampler.
 *
 * Same methodology as the PHP sampler (99Hz perf_event, ring buffer,
 * fold to "a;b;c" stacks, write samples.ndjson for the existing UI) but
 * the unwinder is *native*: bpf_get_stack captures the user stack via
 * frame pointers, and this process symbolizes each instruction pointer
 * against the target binary / shared libraries' ELF symbol tables.
 *
 * Swap this in for the Zend walker and the whole downstream pipeline
 * (SQLite ingest, flamegraph, call tree, total-time ranking) is reused
 * unchanged — the point being that the approach is app-independent.
 */
#define _GNU_SOURCE
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
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "native.h"

/* from libstdc++, via the C ABI — demangles C++ symbol names */
extern char *__cxa_demangle(const char *mangled, char *buf, size_t *n, int *status);

#define BPF_OBJ_PATH_DEFAULT "/opt/native/native.bpf.o"
#define MAX_TRACKED 8192

static volatile sig_atomic_t stop;
static void on_sigint(int sig) { (void)sig; stop = 1; }

static long long mono_to_wall;
static void init_clock(void)
{
    struct timespec mono, real;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_REALTIME, &real);
    mono_to_wall = (real.tv_sec - mono.tv_sec) * 1000000000LL +
                   (real.tv_nsec - mono.tv_nsec);
}
static unsigned long long wall_ns(unsigned long long m) { return m + mono_to_wall; }

static void sanitize(char *s)
{
    for (; *s; s++)
        if (*s == ';' || *s == '"' || *s == '\\' || (unsigned char)*s < 0x20)
            *s = '_';
}

/* --------------------------------------------------------- ELF symbols */

struct sym { unsigned long long addr, size; char *name; };
struct seg { unsigned long long vaddr, off, filesz; };

struct binsyms {
    dev_t dev; ino_t ino;
    struct sym *syms; int nsyms;
    struct seg segs[32]; int nseg;
    char name[64]; /* basename, for unknown-frame labels */
};

static struct binsyms bins[256];
static int nbins;

static int sym_cmp(const void *a, const void *b)
{
    unsigned long long x = ((const struct sym *)a)->addr;
    unsigned long long y = ((const struct sym *)b)->addr;
    return x < y ? -1 : x > y ? 1 : 0;
}

static void load_syms_from(Elf *elf, struct binsyms *b)
{
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn))) {
        GElf_Shdr sh;
        if (!gelf_getshdr(scn, &sh))
            continue;
        if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM)
            continue;
        Elf_Data *d = elf_getdata(scn, NULL);
        if (!d)
            continue;
        size_t cnt = sh.sh_entsize ? sh.sh_size / sh.sh_entsize : 0;
        for (size_t i = 0; i < cnt; i++) {
            GElf_Sym s;
            if (!gelf_getsym(d, i, &s))
                continue;
            if (GELF_ST_TYPE(s.st_info) != STT_FUNC || !s.st_value)
                continue;
            const char *nm = elf_strptr(elf, sh.sh_link, s.st_name);
            if (!nm || !*nm)
                continue;
            b->syms = realloc(b->syms, (b->nsyms + 1) * sizeof(struct sym));
            b->syms[b->nsyms].addr = s.st_value;
            b->syms[b->nsyms].size = s.st_size;
            b->syms[b->nsyms].name = strdup(nm);
            b->nsyms++;
        }
    }
}

static struct binsyms *get_binsyms(const char *access_path, const char *nm)
{
    struct stat st;
    if (stat(access_path, &st))
        return NULL;
    for (int i = 0; i < nbins; i++)
        if (bins[i].dev == st.st_dev && bins[i].ino == st.st_ino)
            return &bins[i];
    if (nbins >= 256)
        return NULL;

    struct binsyms *b = &bins[nbins];
    memset(b, 0, sizeof(*b));
    b->dev = st.st_dev; b->ino = st.st_ino;
    snprintf(b->name, sizeof(b->name), "%s", nm);

    int fd = open(access_path, O_RDONLY);
    if (fd < 0)
        return NULL;
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf) {
        size_t phn;
        if (!elf_getphdrnum(elf, &phn))
            for (size_t i = 0; i < phn && b->nseg < 32; i++) {
                GElf_Phdr ph;
                if (gelf_getphdr(elf, i, &ph) && ph.p_type == PT_LOAD) {
                    b->segs[b->nseg].vaddr = ph.p_vaddr;
                    b->segs[b->nseg].off = ph.p_offset;
                    b->segs[b->nseg].filesz = ph.p_filesz;
                    b->nseg++;
                }
            }
        load_syms_from(elf, b);
        elf_end(elf);
    }
    close(fd);
    if (b->syms)
        qsort(b->syms, b->nsyms, sizeof(struct sym), sym_cmp);
    nbins++;
    return b;
}

/* file offset within a mapping -> ELF virtual address */
static bool file_off_to_vaddr(struct binsyms *b, unsigned long long foff,
                              unsigned long long *vaddr)
{
    for (int i = 0; i < b->nseg; i++)
        if (foff >= b->segs[i].off && foff < b->segs[i].off + b->segs[i].filesz) {
            *vaddr = b->segs[i].vaddr + (foff - b->segs[i].off);
            return true;
        }
    return false;
}

static const char *sym_lookup(struct binsyms *b, unsigned long long vaddr)
{
    int lo = 0, hi = b->nsyms - 1, best = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (b->syms[mid].addr <= vaddr) { best = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    if (best < 0)
        return NULL;
    struct sym *s = &b->syms[best];
    if (s->size == 0 || vaddr < s->addr + s->size)
        return s->name;
    return NULL;
}

/* ------------------------------------------------------- process maps */

struct mapent {
    unsigned long long start, end, off;
    char path[192];
};
struct pmaps {
    pid_t pid;
    struct mapent *m; int n;
    time_t loaded;
};
static struct pmaps pmaps_cache[MAX_TRACKED];
static int npmaps;

static struct pmaps *load_pmaps(pid_t pid)
{
    struct pmaps *pm = NULL;
    for (int i = 0; i < npmaps; i++)
        if (pmaps_cache[i].pid == pid) { pm = &pmaps_cache[i]; break; }
    time_t now = time(NULL);
    if (pm && now - pm->loaded < 2)
        return pm;
    if (!pm) {
        if (npmaps >= MAX_TRACKED)
            return NULL;
        pm = &pmaps_cache[npmaps++];
        memset(pm, 0, sizeof(*pm));
        pm->pid = pid;
    }
    free(pm->m); pm->m = NULL; pm->n = 0;

    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/maps", pid);
    FILE *f = fopen(p, "r");
    if (!f) { pm->loaded = now; return pm; }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end, off;
        char perms[8], dev[16], path[192] = "";
        unsigned long ino;
        int c = sscanf(line, "%llx-%llx %7s %llx %15s %lu %191s",
                       &start, &end, perms, &off, dev, &ino, path);
        if (c < 6 || perms[2] != 'x' || path[0] != '/')
            continue;
        pm->m = realloc(pm->m, (pm->n + 1) * sizeof(struct mapent));
        pm->m[pm->n].start = start; pm->m[pm->n].end = end; pm->m[pm->n].off = off;
        snprintf(pm->m[pm->n].path, sizeof(pm->m[pm->n].path), "%s", path);
        pm->n++;
    }
    fclose(f);
    pm->loaded = now;
    return pm;
}

/* ------------------------------------------------------- symbolization */

#define CACHE_SLOTS 131072
struct cent { unsigned long long key; char *name; };
static struct cent cache[CACHE_SLOTS];

static const char *cache_get(unsigned long long k)
{
    for (size_t i = k % CACHE_SLOTS, p = 0; p < 48; i = (i + 1) % CACHE_SLOTS, p++) {
        if (!cache[i].name) return NULL;
        if (cache[i].key == k) return cache[i].name;
    }
    return NULL;
}
static void cache_put(unsigned long long k, const char *n)
{
    for (size_t i = k % CACHE_SLOTS, p = 0; p < 48; i = (i + 1) % CACHE_SLOTS, p++) {
        if (!cache[i].name) { cache[i].key = k; cache[i].name = strdup(n); return; }
        if (cache[i].key == k) return;
    }
}

static const char *symbolize(pid_t pid, unsigned long long ip)
{
    static char out[300];
    unsigned long long key = ip ^ ((unsigned long long)pid << 1);
    const char *hit = cache_get(key);
    if (hit)
        return hit;

    struct pmaps *pm = load_pmaps(pid);
    struct mapent *me = NULL;
    if (pm)
        for (int i = 0; i < pm->n; i++)
            if (ip >= pm->m[i].start && ip < pm->m[i].end) { me = &pm->m[i]; break; }
    if (!me)
        return "[unknown]";

    char access[320];
    snprintf(access, sizeof(access), "/proc/%d/root%s", pid, me->path);
    const char *base = strrchr(me->path, '/');
    base = base ? base + 1 : me->path;
    struct binsyms *b = get_binsyms(access, base);

    const char *name = NULL;
    if (b) {
        unsigned long long foff = me->off + (ip - me->start);
        unsigned long long vaddr;
        if (file_off_to_vaddr(b, foff, &vaddr))
            name = sym_lookup(b, vaddr);
    }
    if (name) {
        /* Demangle C++ symbols: _ZN3kvs7Storage3getE... -> kvs::Storage::get(...) */
        char *dem = NULL;
        if (name[0] == '_' && name[1] == 'Z') {
            int st = 0;
            dem = __cxa_demangle(name, NULL, NULL, &st);
            if (st != 0) dem = NULL;
        }
        snprintf(out, sizeof(out), "%s", dem ? dem : name);
        free(dem);
    } else {
        snprintf(out, sizeof(out), "%s+0x%llx", base, ip - me->start);
    }
    sanitize(out);
    cache_put(key, out);
    return out;
}

/* find a symbol by name -> ELF virtual address (0 if absent) */
static unsigned long long sym_addr_by_name(struct binsyms *b, const char *name)
{
    for (int i = 0; i < b->nsyms; i++)
        if (!strcmp(b->syms[i].name, name))
            return b->syms[i].addr;
    return 0;
}

/* ELF virtual address -> file offset (for manual uprobe placement) */
static long long vaddr_to_foff(struct binsyms *b, unsigned long long vaddr)
{
    for (int i = 0; i < b->nseg; i++)
        if (vaddr >= b->segs[i].vaddr && vaddr < b->segs[i].vaddr + b->segs[i].filesz)
            return (long long)(vaddr - b->segs[i].vaddr + b->segs[i].off);
    return -1;
}

/* ----------------------------------------------------- target tracking */

struct ctx {
    struct bpf_object *obj;
    int targets_fd;
    struct bpf_program *p_op_entry, *p_op_ret;
    bool op_attached;
    struct bpf_link *links[512];
    int nlinks;
};

static char probe_func[128];

/* Attach the request-boundary uprobe/uretprobe (surface interface only)
 * to the target's binary at PROBE_FUNC. Done once, on the first discovered
 * target; the BPF side filters by the targets map. */
static void attach_op_probes(struct ctx *c, pid_t pid)
{
    if (c->op_attached || !probe_func[0] || !c->p_op_entry || !c->p_op_ret)
        return;
    char exe[64];
    snprintf(exe, sizeof(exe), "/proc/%d/exe", pid);
    struct binsyms *b = get_binsyms(exe, "target");
    if (!b) return;
    unsigned long long va = sym_addr_by_name(b, probe_func);
    if (!va) {
        fprintf(stderr, "native: probe func '%s' not found (need symbols) — "
                "latency probe disabled\n", probe_func);
        c->op_attached = true; /* don't retry every scan */
        return;
    }
    long long foff = vaddr_to_foff(b, va);
    if (foff < 0) return;
    struct bpf_link *l1 = bpf_program__attach_uprobe(c->p_op_entry, false, -1, exe, (size_t)foff);
    struct bpf_link *l2 = bpf_program__attach_uprobe(c->p_op_ret,   true,  -1, exe, (size_t)foff);
    if (l1 && c->nlinks < 512) c->links[c->nlinks++] = l1;
    if (l2 && c->nlinks < 512) c->links[c->nlinks++] = l2;
    c->op_attached = true;
    fprintf(stderr, "native: latency probe on %s @0x%llx (%s)\n",
            probe_func, foff, l1 && l2 ? "ok" : "FAILED");
}

struct tr { pid_t pid; bool alive; };
static struct tr tracked[MAX_TRACKED];
static int ntr;
static char target_comm[32];

static bool comm_matches(pid_t pid)
{
    char p[64], buf[64] = "";
    snprintf(p, sizeof(p), "/proc/%d/comm", pid);
    FILE *f = fopen(p, "r");
    if (!f) return false;
    if (fgets(buf, sizeof(buf), f)) buf[strcspn(buf, "\n")] = 0;
    fclose(f);
    return strcmp(buf, target_comm) == 0;
}

static void scan(struct ctx *c)
{
    for (int i = 0; i < ntr; i++) tracked[i].alive = false;
    DIR *d = opendir("/proc");
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        char *end; long pid = strtol(de->d_name, &end, 10);
        if (*end || pid <= 0) continue;
        if (!comm_matches(pid)) continue;
        int found = -1;
        for (int i = 0; i < ntr; i++) if (tracked[i].pid == pid) { found = i; break; }
        if (found >= 0) { tracked[found].alive = true; continue; }
        __u32 key = pid; __u8 one = 1;
        if (!bpf_map_update_elem(c->targets_fd, &key, &one, BPF_ANY) && ntr < MAX_TRACKED) {
            tracked[ntr].pid = pid; tracked[ntr].alive = true; ntr++;
            fprintf(stderr, "native: tracking %s pid %ld\n", target_comm, pid);
            attach_op_probes(c, pid);
        }
    }
    closedir(d);
    for (int i = 0; i < ntr;) {
        if (!tracked[i].alive) {
            __u32 key = tracked[i].pid;
            bpf_map_delete_elem(c->targets_fd, &key);
            tracked[i] = tracked[--ntr];
        } else i++;
    }
}

/* ------------------------------------------------------------- events */

static FILE *f_samples;
static FILE *f_requests;

/* JSON string escaper */
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

/* memcached-style op name = first whitespace-delimited token, upper-cased */
static void op_of(const char *cmd, char *op, size_t opsz)
{
    size_t o = 0;
    for (const char *p = cmd; *p && *p != ' ' && *p != '\r' && *p != '\n' && o + 1 < opsz; p++)
        op[o++] = (*p >= 'a' && *p <= 'z') ? (*p - 32) : *p;
    op[o] = 0;
    if (!o) snprintf(op, opsz, "OP");
}

static int handle_span(struct ev_span *e)
{
    char op[32];
    op_of(e->cmd, op, sizeof(op));
    char op_esc[64];
    json_escape(op, op_esc, sizeof(op_esc));
    /* uri = op so the Overview groups by operation (GET/SET/...) and ranks
     * them by total time / P50 / P99, like endpoints on the PHP side. */
    fprintf(f_requests,
            "{\"pid\":%u,\"start_ns\":%llu,\"end_ns\":%llu,\"dur_us\":%llu,"
            "\"method\":\"%s\",\"uri\":\"%s\"}\n",
            e->pid, wall_ns(e->ts), wall_ns(e->ts + e->dur_ns),
            e->dur_ns / 1000, op_esc, op_esc);
    return 0;
}

/* Aggregation: fold each sample and count identical (pid, stack) in memory,
 * flushing one row per distinct stack every flush window. Since distinct
 * stacks converge to a few hundred, the output size (and this table) is
 * bounded by cardinality, NOT by sample count or runtime — constant memory
 * / disk regardless of load. Open-addressed, fixed capacity. */
#define AGG_SLOTS 16384
struct agg_ent {
    unsigned int pid;
    unsigned long long hash;
    char *stack;
    unsigned long long count;
};
static struct agg_ent agg[AGG_SLOTS];
static int agg_used;

static unsigned long long str_hash(unsigned int pid, const char *s)
{
    unsigned long long h = 1469598103934665603ULL ^ pid;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 1099511628211ULL; }
    return h ? h : 1;
}

static void agg_add(unsigned int pid, const char *stack)
{
    unsigned long long h = str_hash(pid, stack);
    for (size_t i = h % AGG_SLOTS, p = 0; p < AGG_SLOTS; i = (i + 1) % AGG_SLOTS, p++) {
        if (!agg[i].stack) {
            if (agg_used >= AGG_SLOTS - 1) return; /* full: drop (bounded) */
            agg[i].pid = pid; agg[i].hash = h;
            agg[i].stack = strdup(stack); agg[i].count = 1;
            agg_used++;
            return;
        }
        if (agg[i].hash == h && agg[i].pid == pid && !strcmp(agg[i].stack, stack)) {
            agg[i].count++;
            return;
        }
    }
}

/* Flush aggregated counts as ndjson rows carrying an "n" (sample count);
 * the ingest sums n, so one row stands in for n raw samples. */
static const char *samples_path;
static unsigned long long max_ndjson_bytes; /* 0 = unlimited */

static void agg_flush(void)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    unsigned long long ts =
        (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
    for (int i = 0; i < AGG_SLOTS; i++) {
        if (!agg[i].stack) continue;
        fprintf(f_samples, "{\"ts\":%llu,\"pid\":%u,\"stack\":\"%s\",\"n\":%llu}\n",
                ts, agg[i].pid, agg[i].stack, agg[i].count);
        free(agg[i].stack);
        agg[i].stack = NULL;
    }
    agg_used = 0;
    fflush(f_samples);
    /* Bound the intermediate file: once consumed into SQLite it is
     * disposable, so truncate past the cap (the ingest resets on shrink).
     * SQLite (retention + max_page_count) remains the durable, bounded store. */
    if (max_ndjson_bytes) {
        long sz = ftell(f_samples);
        if (sz > 0 && (unsigned long long)sz > max_ndjson_bytes) {
            f_samples = freopen(samples_path, "w", f_samples);
            if (f_samples)
                setvbuf(f_samples, NULL, _IOLBF, 1 << 16);
        }
    }
}

static int on_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    if (len < sizeof(unsigned int)) return 0;
    unsigned int kind = *(unsigned int *)data;
    if (kind == EV_SPAN) {
        if (len >= sizeof(struct ev_span)) handle_span((struct ev_span *)data);
        return 0;
    }
    if (len < sizeof(struct ev_nsample)) return 0;
    struct ev_nsample *e = data;
    int nframes = e->nbytes / 8;
    if (nframes <= 0) return 0;
    if (nframes > NST_MAX) nframes = NST_MAX;

    char stack[16384];
    size_t o = 0;
    for (int i = nframes - 1; i >= 0; i--) {
        if (!e->ips[i]) continue;
        const char *nm = symbolize(e->pid, e->ips[i]);
        size_t l = strlen(nm);
        if (o + l + 2 >= sizeof(stack)) break;
        if (o) stack[o++] = ';';
        memcpy(stack + o, nm, l); o += l;
    }
    stack[o] = 0;
    if (o)
        agg_add(e->pid, stack);
    return 0;
}

static int attach_sampler(struct ctx *c, struct bpf_program *prog, int freq)
{
    int ncpu = sysconf(_SC_NPROCESSORS_ONLN), ok = 0;
    for (int cpu = 0; cpu < ncpu; cpu++) {
        struct perf_event_attr attr = {
            .type = PERF_TYPE_SOFTWARE, .size = sizeof(attr),
            .config = PERF_COUNT_SW_CPU_CLOCK, .sample_freq = (unsigned)freq, .freq = 1,
        };
        int fd = syscall(SYS_perf_event_open, &attr, -1, cpu, -1, 0);
        if (fd < 0) continue;
        struct bpf_link *l = bpf_program__attach_perf_event(prog, fd);
        if (!l) { close(fd); continue; }
        if (c->nlinks < 512) c->links[c->nlinks++] = l;
        ok++;
    }
    return ok ? 0 : -1;
}

int main(void)
{
    const char *data_dir = getenv("DATA_DIR") ?: "/data";
    const char *obj = getenv("BPF_OBJ") ?: BPF_OBJ_PATH_DEFAULT;
    snprintf(target_comm, sizeof(target_comm), "%s", getenv("TARGET_COMM") ?: "memcached");
    int freq = atoi(getenv("SAMPLE_FREQ") ?: "99");
    if (freq <= 0) freq = 99;
    unsigned long long max_per_sec = strtoull(getenv("MAX_SAMPLES_PER_SEC") ?: "0", 0, 10);
    int flush_sec = atoi(getenv("FLUSH_SEC") ?: "10");
    if (flush_sec <= 0) flush_sec = 10;
    /* request-boundary latency probe: PROBE_FUNC="" disables it (sampling
     * only). PROBE_SAMPLE=N records 1 in N ops. */
    snprintf(probe_func, sizeof(probe_func), "%s", getenv("PROBE_FUNC") ?: "");
    unsigned long long probe_sample = strtoull(getenv("PROBE_SAMPLE") ?: "1", 0, 10);

    signal(SIGINT, on_sigint); signal(SIGTERM, on_sigint);
    elf_version(EV_CURRENT);
    init_clock();

    static char path[512], rpath[512];
    snprintf(path, sizeof(path), "%s/samples.ndjson", data_dir);
    snprintf(rpath, sizeof(rpath), "%s/requests.ndjson", data_dir);
    samples_path = path;
    max_ndjson_bytes = strtoull(getenv("MAX_NDJSON_MB") ?: "64", 0, 10) * 1024 * 1024;
    f_samples = fopen(path, "a");
    f_requests = fopen(rpath, "a");
    if (!f_samples || !f_requests) { fprintf(stderr, "native: cannot open output\n"); return 1; }
    setvbuf(f_samples, NULL, _IOLBF, 1 << 16);
    setvbuf(f_requests, NULL, _IOLBF, 1 << 16);

    struct ctx c = {0};
    c.obj = bpf_object__open_file(obj, NULL);
    if (!c.obj || bpf_object__load(c.obj)) {
        fprintf(stderr, "native: load %s failed\n", obj); return 1;
    }
    c.targets_fd = bpf_object__find_map_fd_by_name(c.obj, "targets");
    struct bpf_program *prog = bpf_object__find_program_by_name(c.obj, "on_sample");
    c.p_op_entry = bpf_object__find_program_by_name(c.obj, "on_op_entry");
    c.p_op_ret = bpf_object__find_program_by_name(c.obj, "on_op_ret");
    if (c.targets_fd < 0 || !prog) { fprintf(stderr, "native: missing prog/map\n"); return 1; }
    if (attach_sampler(&c, prog, freq)) { fprintf(stderr, "native: attach failed\n"); return 1; }

    /* apply the sample-rate ceiling (0 = unlimited) */
    if (max_per_sec) {
        int rf = bpf_object__find_map_fd_by_name(c.obj, "rlcfg");
        __u32 k = 0;
        if (rf >= 0) bpf_map_update_elem(rf, &k, &max_per_sec, BPF_ANY);
    }
    /* op-sampling ratio for the boundary probe */
    if (probe_sample > 1) {
        int of = bpf_object__find_map_fd_by_name(c.obj, "opcfg");
        __u32 k = 0;
        if (of >= 0) bpf_map_update_elem(of, &k, &probe_sample, BPF_ANY);
    }
    fprintf(stderr,
            "native: sampling '%s' @%dHz cap=%llu/s flush=%ds; latency probe='%s' 1/%llu\n",
            target_comm, freq, max_per_sec, flush_sec,
            probe_func[0] ? probe_func : "(off)", probe_sample);

    int rb_fd = bpf_object__find_map_fd_by_name(c.obj, "events");
    struct ring_buffer *rb = ring_buffer__new(rb_fd, on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "native: ringbuf failed\n"); return 1; }

    time_t last = 0, last_flush = time(NULL);
    while (!stop) {
        time_t now = time(NULL);
        if (now != last) { scan(&c); last = now; }
        if (now - last_flush >= flush_sec) { agg_flush(); last_flush = now; }
        int err = ring_buffer__poll(rb, 200);
        if (err < 0 && err != -EINTR) break;
    }
    agg_flush();
    fprintf(stderr, "native: exiting\n");
    ring_buffer__free(rb);
    bpf_object__close(c.obj);
    return 0;
}
