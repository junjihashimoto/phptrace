/* Full tracing probe: a faithful stand-in for the load-test on_probe_hit
 * (bench/percall.bpf.c) attached to bench_target. Per fire:
 *   - 1 array lookup + increment   (call_count)
 *   - bpf_get_current_pid_tgid     (helper)
 *   - 1 hash lookup by tid         (req_sampled)
 *   - 6 pointer-chain reads        (walk the "frame")
 * This should reproduce, at the per-fire level, the load-test reversal where
 * bpftime is >= kernel despite a ~9x cheaper trampoline: the cost here is
 * helper calls + maps + reads, none of which bpftime makes cheaper.
 * No atomic (ubpf rejects opcode 0xdb). */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} call_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} req_sampled SEC(".maps");

SEC("uprobe/bench_target")
int probe(struct pt_regs *ctx)
{
    __u32 k = 0;
    __u64 *c = bpf_map_lookup_elem(&call_count, &k);
    if (c) (*c)++;

    __u32 tid = bpf_get_current_pid_tgid() & 0xffffffff;
    __u8 *f = bpf_map_lookup_elem(&req_sampled, &tid);
    (void)f;

    void *p = (void *)PT_REGS_PARM1(ctx);
    __u64 buf = 0;
#pragma unroll
    for (int i = 0; i < 6; i++) {
        if (!p) break;
        if (bpf_probe_read_user(&buf, sizeof(buf), p) != 0) break;
        p = (void *)buf;
    }
    return (int)(buf & 7);
}
