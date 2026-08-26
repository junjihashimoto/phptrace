/*
 * Native on-CPU sampler. perf_event CPU-clock @ freq; for target pids,
 * capture the user-space stack via bpf_get_stack (kernel frame-pointer
 * unwinding) and ship the raw instruction pointers to userspace, which
 * symbolizes them against each binary's ELF symtab.
 *
 * No CO-RE / vmlinux.h needed — only uapi + the stack helper.
 */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "native.h"

char LICENSE[] SEC("license") = "GPL";

/* pids to sample (filled by userspace from /proc scan of TARGET_COMM). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} targets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

/* Token bucket: a hard ceiling on samples/sec across ALL cpus, so the data
 * rate (and thus CPU / ring buffer / disk pressure) is bounded independent
 * of core count. 0 = unlimited. Configured by userspace from
 * MAX_SAMPLES_PER_SEC. */
struct rlcfg { __u64 max_per_sec; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rlcfg);
} rlcfg SEC(".maps");

struct rlstate { __u64 window_start; __u64 count; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rlstate);
} rlstate SEC(".maps");

/* returns 1 if this sample is within budget, 0 to drop */
static __always_inline int rate_ok(void)
{
    __u32 z = 0;
    struct rlcfg *c = bpf_map_lookup_elem(&rlcfg, &z);
    if (!c || !c->max_per_sec)
        return 1;
    struct rlstate *s = bpf_map_lookup_elem(&rlstate, &z);
    if (!s)
        return 1;
    __u64 now = bpf_ktime_get_ns();
    if (now - s->window_start >= 1000000000ULL) { /* new 1s window (benign race) */
        s->window_start = now;
        s->count = 0;
    }
    if (s->count >= c->max_per_sec)
        return 0;
    __sync_fetch_and_add(&s->count, 1);
    return 1;
}

SEC("perf_event")
int on_sample(struct bpf_perf_event_data *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&targets, &pid))
        return 0;
    if (!rate_ok())
        return 0;

    struct ev_nsample *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->kind = EV_SAMPLE;
    e->pid = pid;
    e->ts = bpf_ktime_get_ns();
    long n = bpf_get_stack(ctx, e->ips, sizeof(e->ips), BPF_F_USER_STACK);
    e->nbytes = n > 0 ? (unsigned)n : 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ---- request-boundary latency probe (surface interface only) ---- */

/* sampling: record 1 in N ops (0/1 = all). Bounds recorded volume at high
 * op rates. The uprobe trap still fires per op — this caps data, not trap
 * cost; keeping it to ONE boundary probe (not per-call) is what bounds cost. */
struct opcfg { __u64 sample_n; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct opcfg);
} opcfg SEC(".maps");

struct opstate { __u64 ts; char cmd[MAX_CMD]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);       /* tid */
    __type(value, struct opstate);
} inflight_op SEC(".maps");

/* per-cpu scratch: opstate is too big for the 512B BPF stack */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct opstate);
} opscratch SEC(".maps");

static __u64 op_counter = 0;

SEC("uprobe")
int on_op_entry(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&targets, &pid))
        return 0;

    __u32 z = 0;
    struct opcfg *cfg = bpf_map_lookup_elem(&opcfg, &z);
    if (cfg && cfg->sample_n > 1) {
        __u64 c = __sync_fetch_and_add(&op_counter, 1);
        if (c % cfg->sample_n != 0)
            return 0;   /* not sampled: skip (no span emitted for it) */
    }

    struct opstate *st = bpf_map_lookup_elem(&opscratch, &z);
    if (!st)
        return 0;
    st->ts = bpf_ktime_get_ns();
    st->cmd[0] = 0;
    /* arg2 = command string (memcached process_command_ascii; configurable) */
    const char *cmd = (const char *)PT_REGS_PARM2(ctx);
    if (cmd)
        bpf_probe_read_user_str(st->cmd, sizeof(st->cmd), cmd);

    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    bpf_map_update_elem(&inflight_op, &tid, st, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int on_op_ret(struct pt_regs *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    struct opstate *st = bpf_map_lookup_elem(&inflight_op, &tid);
    if (!st)
        return 0;

    struct ev_span *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->kind = EV_SPAN;
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->ts = st->ts;
        e->dur_ns = bpf_ktime_get_ns() - st->ts;
        __builtin_memcpy(e->cmd, st->cmd, MAX_CMD);
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&inflight_op, &tid);
    return 0;
}
