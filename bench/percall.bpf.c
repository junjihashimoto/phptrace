/*
 * Per-call / high-frequency uprobe benchmark program (+ per-request sampling).
 *
 * A uprobe on a hot php-fpm function (default execute_ex; per-call only under a
 * --enable-dtrace build with USE_ZEND_DTRACE=1). The point is the cost of
 * *taking the probe* on every hit — a kernel uprobe traps into the kernel each
 * time; bpftime runs the same program in userspace, avoiding the trap.
 *
 * Per-request sampling (SAMPLE_N): a second uprobe on the request-boundary
 * function marks 1 in N requests as "sampled". The hot probe then does the
 * representative *work* (a small user-memory read chain, standing in for a
 * stack walk) ONLY for sampled requests — but it still FIRES on every call to
 * check the flag. That is the whole experiment: sampling cuts the per-hit
 * *work*, not the per-hit *fire*, so it recovers throughput only to the extent
 * the work (not the trap/dispatch) was the cost.
 */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* total probe fires (per CPU, summed in userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} call_count SEC(".maps");

/* times the work payload actually ran (== fires when SAMPLE_N<=1) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} work_count SEC(".maps");

/* config: sample 1 in N requests (0/1 = every request) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sample_n SEC(".maps");

/* global request counter + per-thread "this request is sampled" flag */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} req_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);       /* tid */
    __type(value, __u8);
} req_sampled SEC(".maps");

/* request boundary: decide whether this request is sampled */
SEC("uprobe")
int on_req_start(struct pt_regs *ctx)
{
    (void)ctx;
    __u32 k = 0;
    __u64 n = 1;
    __u64 *np = bpf_map_lookup_elem(&sample_n, &k);
    if (np) n = *np;
    __u8 flag = 1;
    if (n > 1) {
        __u64 *c = bpf_map_lookup_elem(&req_counter, &k);
        __u64 cur = 0;
        if (c) cur = __sync_fetch_and_add(c, 1);
        flag = (cur % n == 0) ? 1 : 0;
    }
    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    bpf_map_update_elem(&req_sampled, &tid, &flag, BPF_ANY);
    return 0;
}

SEC("uprobe")
int on_probe_hit(struct pt_regs *ctx)
{
    __u32 k = 0;
    /* fire cost is paid on EVERY hit, sampled or not */
    __u64 *v = bpf_map_lookup_elem(&call_count, &k);
    if (v) (*v)++;

    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    __u8 *f = bpf_map_lookup_elem(&req_sampled, &tid);
    if (f && *f == 0)
        return 0;   /* not sampled: skip the work, but we already fired */

    /* representative per-call work: walk a short pointer chain in the target
     * (stands in for reading the Zend frame). Bounded + guarded. */
    __u64 *w = bpf_map_lookup_elem(&work_count, &k);
    if (w) (*w)++;
    void *p = (void *)PT_REGS_PARM1(ctx);   /* execute_data */
    __u64 buf = 0;
#pragma unroll
    for (int i = 0; i < 6; i++) {
        if (!p) break;
        if (bpf_probe_read_user(&buf, sizeof(buf), p) != 0) break;
        p = (void *)buf;   /* follow the chain */
    }
    return 0;
}
