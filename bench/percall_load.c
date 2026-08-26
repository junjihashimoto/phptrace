/*
 * percall_load — loader/attacher for the per-call (high-frequency) uprobe.
 *
 * Scans /proc for php-fpm processes, resolves the traced binary via
 * /proc/<pid>/exe, and attaches the uprobe by symbol name (from .dynsym of
 * the php-fpm binary). pid=-1 attaches to every process mapping that binary,
 * so all fpm workers are covered.
 *
 * Target symbol (PROBE_FUNC env, default _emalloc):
 *   The task's intent is "fires per PHP function call". On stock php:8.3-fpm
 *   that is NOT achievable with a static uprobe: PHP 8's hybrid VM inlines the
 *   whole userland-call path (ZEND_VM_ENTER), so execute_ex — and every frame
 *   setup helper (zend_init_func_execute_data, ...) — fires exactly ONCE per
 *   request, not once per call (measured). Per-call granularity requires an
 *   in-process extension overriding zend_execute_ex, which a uprobe cannot do.
 *   So to represent the *cost of per-call tracing* we probe a genuinely hot
 *   Zend function: _emalloc fires ~87k times for one /cpu request. That makes
 *   the kernel-uprobe trap overhead dominate CPU-bound throughput — exactly
 *   the money-chart effect — while sampling stays flat and bpftime (userspace)
 *   recovers most of it.
 *
 * The exact same binary + percall.bpf.o drives the bpftime run: under
 * `bpftime load ./percall_load`, libbpf's syscalls are intercepted by
 * bpftime's syscall-server and the program is registered in shared memory
 * instead of the kernel; the agent injected into php-fpm then executes it in
 * userspace. Hence: no kernel-specific attach logic here.
 *
 * Runs until SIGINT/SIGTERM, printing the aggregated call count once a second
 * so the orchestrator can confirm the probe is actually firing.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define BPF_OBJ_PATH_DEFAULT "/opt/percall/percall.bpf.o"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

/* True if the ELF at `path` exports `sym` in its symbol/dynsym table. Used to
 * pick a specific php-fpm binary when several are running: the --enable-dtrace
 * build exports dtrace_execute_ex, the stock build does not. (FPM clobbers
 * /proc/<pid>/environ with its process title, so environ matching is out.) */
static int binary_has_symbol(const char *path, const char *sym)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    int found = 0;
    if (elf) {
        Elf_Scn *scn = NULL;
        while (!found && (scn = elf_nextscn(elf, scn))) {
            GElf_Shdr shdr;
            if (!gelf_getshdr(scn, &shdr))
                continue;
            if (shdr.sh_type != SHT_DYNSYM && shdr.sh_type != SHT_SYMTAB)
                continue;
            Elf_Data *data = elf_getdata(scn, NULL);
            if (!data || !shdr.sh_entsize)
                continue;
            size_t n = shdr.sh_size / shdr.sh_entsize;
            for (size_t i = 0; i < n; i++) {
                GElf_Sym s;
                if (!gelf_getsym(data, i, &s))
                    continue;
                const char *nm = elf_strptr(elf, shdr.sh_link, s.st_name);
                if (nm && !strcmp(nm, sym)) {
                    found = 1;
                    break;
                }
            }
        }
        elf_end(elf);
    }
    close(fd);
    return found;
}

/* Find a php-fpm process; return its pid and fill exe_link. If PHPFPM_MATCH_SYM
 * is set, only match a php-fpm whose binary exports that symbol. */
static int find_phpfpm(char *exe_link, size_t sz)
{
    const char *match_sym = getenv("PHPFPM_MATCH_SYM");
    if (match_sym && !*match_sym)
        match_sym = NULL;
    DIR *d = opendir("/proc");
    if (!d)
        return -1;
    struct dirent *de;
    int found = -1;
    while ((de = readdir(d))) {
        char *end;
        long pid = strtol(de->d_name, &end, 10);
        if (*end || pid <= 0)
            continue;
        char link[64], target[256];
        snprintf(link, sizeof(link), "/proc/%ld/exe", pid);
        ssize_t n = readlink(link, target, sizeof(target) - 1);
        if (n <= 0)
            continue;
        target[n] = 0;
        const char *bn = strrchr(target, '/');
        bn = bn ? bn + 1 : target;
        if (strncmp(bn, "php-fpm", 7) != 0)
            continue;
        snprintf(link, sizeof(link), "/proc/%ld/exe", pid);
        if (match_sym && !binary_has_symbol(link, match_sym))
            continue;
        snprintf(exe_link, sz, "/proc/%ld/exe", pid);
        found = (int)pid;
        break;
    }
    closedir(d);
    return found;
}

static __u64 read_total(int map_fd)
{
    int ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0)
        ncpu = 1;
    __u64 vals[512];
    if ((size_t)ncpu > sizeof(vals) / sizeof(vals[0]))
        ncpu = sizeof(vals) / sizeof(vals[0]);
    __u32 key = 0;
    if (bpf_map_lookup_elem(map_fd, &key, vals))
        return 0;
    __u64 total = 0;
    for (int i = 0; i < ncpu; i++)
        total += vals[i];
    return total;
}

/* sleep ms, waking early if a signal set `stop` (checks every 100ms) */
static void msleep_stop(unsigned long ms)
{
    while (ms > 0 && !stop) {
        unsigned long chunk = ms < 100 ? ms : 100;
        usleep((useconds_t)(chunk * 1000));
        ms -= chunk;
    }
}

int main(void)
{
    const char *obj_path = getenv("BPF_OBJ") ?: BPF_OBJ_PATH_DEFAULT;
    /* Default target: execute_ex (the task's named target). NOTE: on stock
     * PHP 8.3 this fires only ~1x/request (ZEND_VM_ENTER inlines the userland
     * call path) — the loader prints the live counter so you can see this. To
     * exercise real per-call trap cost set PROBE_FUNC=_emalloc (~87k/request).
     * See the file header. */
    const char *probe_func = getenv("PROBE_FUNC") ?: "execute_ex";

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    elf_version(EV_CURRENT);

    /* Two ways to name the traced binary:
     *   - PHPFPM_BIN=/path : attach directly on that path (bpftime run — the
     *     loader and php-fpm share a filesystem, and bpftime resolves symbols
     *     on the real path; php-fpm need not be running yet).
     *   - otherwise scan /proc for a php-fpm process and use /proc/<pid>/exe
     *     (kernel-uprobe run in a pid:host container that can't see the file). */
    char exe_link[256];
    const char *bin_env = getenv("PHPFPM_BIN");
    if (bin_env && *bin_env) {
        snprintf(exe_link, sizeof(exe_link), "%s", bin_env);
        fprintf(stderr, "percall: target binary %s (PHPFPM_BIN)\n", exe_link);
    } else {
        int pid = find_phpfpm(exe_link, sizeof(exe_link));
        if (pid < 0) {
            fprintf(stderr, "percall: no php-fpm process found\n");
            return 1;
        }
        fprintf(stderr, "percall: target php-fpm pid=%d via %s\n", pid, exe_link);
    }

    struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "percall: open %s failed\n", obj_path);
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "percall: load failed: %s\n", strerror(errno));
        return 1;
    }
    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "on_probe_hit");
    int map_fd = bpf_object__find_map_fd_by_name(obj, "call_count");
    if (!prog || map_fd < 0) {
        fprintf(stderr, "percall: missing prog/map\n");
        return 1;
    }
    int work_fd = bpf_object__find_map_fd_by_name(obj, "work_count");

    /* Per-request sampling: SAMPLE_N=10 => trace the work for 1 in 10 requests
     * (the probe still fires on every hit). 0/1 = every request. */
    unsigned long sample_n = strtoul(getenv("SAMPLE_N") ?: "1", 0, 10);
    if (sample_n > 1) {
        int sn_fd = bpf_object__find_map_fd_by_name(obj, "sample_n");
        __u32 k = 0; __u64 v = sample_n;
        if (sn_fd >= 0) bpf_map_update_elem(sn_fd, &k, &v, BPF_ANY);
    }
    const char *req_func = getenv("REQ_FUNC") ?: "php_request_startup";

    /* Attach by symbol name on the traced binary, all processes (pid=-1). */
    LIBBPF_OPTS(bpf_uprobe_opts, uopts, .func_name = probe_func);
    struct bpf_link *link =
        bpf_program__attach_uprobe_opts(prog, -1, exe_link, 0, &uopts);
    if (!link) {
        fprintf(stderr, "percall: attach %s failed: %s\n", probe_func,
                strerror(errno));
        return 1;
    }
    fprintf(stderr, "percall: attached %s uprobe (pid=-1, %s)\n", probe_func,
            exe_link);

    /* request-boundary probe drives the sampling flag (only needed if sampling) */
    struct bpf_link *rlink = NULL;
    if (sample_n > 1) {
        struct bpf_program *rprog =
            bpf_object__find_program_by_name(obj, "on_req_start");
        LIBBPF_OPTS(bpf_uprobe_opts, ropts, .func_name = req_func);
        if (rprog)
            rlink = bpf_program__attach_uprobe_opts(rprog, -1, exe_link, 0, &ropts);
        fprintf(stderr, "percall: sampling 1/%lu via %s (%s)\n", sample_n, req_func,
                rlink ? "ok" : "FAILED");
    }
    fprintf(stderr, "percall: ready\n");
    fflush(stderr);

    /* Duty-cycle: attach for ON_MS, detach for OFF_MS, repeat. During the OFF
     * window the uprobe is removed from the binary => zero probe cost (the
     * function runs pristine). Average overhead scales with the duty ratio,
     * but the ON windows are periodic full per-call bursts. 0/unset = always on. */
    unsigned long on_ms  = strtoul(getenv("DUTY_ON_MS")  ?: "0", 0, 10);
    unsigned long off_ms = strtoul(getenv("DUTY_OFF_MS") ?: "0", 0, 10);
    int duty = (on_ms > 0 && off_ms > 0);

    if (!duty) {
        while (!stop) {
            sleep(1);
            fprintf(stderr, "percall: calls=%llu work=%llu\n",
                    (unsigned long long)read_total(map_fd),
                    work_fd >= 0 ? (unsigned long long)read_total(work_fd) : 0);
            fflush(stderr);
        }
    } else {
        fprintf(stderr, "percall: duty-cycle on=%lums off=%lums\n", on_ms, off_ms);
        fflush(stderr);
        while (!stop) {
            /* ON window: probe currently attached (link != NULL) */
            msleep_stop(on_ms);
            if (link) { bpf_link__destroy(link); link = NULL; }
            fprintf(stderr, "percall: probe OFF (calls=%llu)\n",
                    (unsigned long long)read_total(map_fd));
            fflush(stderr);
            if (stop) break;
            /* OFF window: probe detached, binary pristine */
            msleep_stop(off_ms);
            if (stop) break;
            link = bpf_program__attach_uprobe_opts(prog, -1, exe_link, 0, &uopts);
            fprintf(stderr, "percall: probe ON (%s)\n", link ? "ok" : "reattach FAILED");
            fflush(stderr);
        }
    }

    fprintf(stderr, "percall: final calls=%llu work=%llu\n",
            (unsigned long long)read_total(map_fd),
            work_fd >= 0 ? (unsigned long long)read_total(work_fd) : 0);
    if (link) bpf_link__destroy(link);
    if (rlink) bpf_link__destroy(rlink);
    bpf_object__close(obj);
    return 0;
}
