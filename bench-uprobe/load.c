/*
 * Attach the minimal uprobe to bench_target in the target binary, then wait.
 *
 * Run bare  -> a kernel uprobe (int3) is installed.
 * Run under LD_PRELOAD=libbpftime-syscall-server.so -> the same libbpf calls
 *   are intercepted and registered in bpftime's shared memory instead, so the
 *   target (run under the agent) gets a userspace inline hook.
 * The identical loader thus measures both mechanisms.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

int main(int argc, char **argv)
{
    const char *obj = getenv("BPF_OBJ") ?: "/opt/uprobe/probe.bpf.o";
    const char *bin = argc > 1 ? argv[1] : (getenv("TARGET_BIN") ?: "/opt/uprobe/target");
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    struct bpf_object *o = bpf_object__open_file(obj, NULL);
    if (!o || bpf_object__load(o)) { fprintf(stderr, "load: open/load %s failed\n", obj); return 1; }
    struct bpf_program *p = bpf_object__find_program_by_name(o, "probe");
    if (!p) { fprintf(stderr, "load: no prog\n"); return 1; }

    LIBBPF_OPTS(bpf_uprobe_opts, opts, .func_name = "bench_target", .retprobe = false);
    struct bpf_link *l = bpf_program__attach_uprobe_opts(p, -1, bin, 0, &opts);
    if (!l) { fprintf(stderr, "load: attach uprobe on %s bench_target failed: %s\n",
                      bin, strerror(errno)); return 1; }

    fprintf(stderr, "READY\n");
    fflush(stderr);
    while (!stop) pause();

    bpf_link__destroy(l);
    bpf_object__close(o);
    return 0;
}
