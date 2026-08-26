/* Gated probe: check a "sampled" flag FIRST and return BEFORE any read on the
 * not-sampled path. The map value defaults to 0, so every fire here takes the
 * early-return (skip) path — this measures the cost of a fire we DON'T record:
 * entry (trampoline/trap) + 1 map lookup + bail, with NO bpf_probe_read_user.
 *
 * Point: for a sampling tracer that reads only 1/N fires, the OTHER (N-1)/N
 * fires cost only this. bpftime's entry (~77ns) is ~8x cheaper than the kernel
 * int3 trap (~740ns) — so on the skipped majority, bpftime should win big.
 * This isolates that skipped-fire floor per mechanism. No atomic (ubpf). */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} sampled SEC(".maps");

SEC("uprobe/bench_target")
int probe(struct pt_regs *ctx)
{
    __u32 k = 0;
    __u8 *s = bpf_map_lookup_elem(&sampled, &k);
    if (!s || *s == 0)
        return 0;   /* NOT sampled: bail before any read (the common path) */

    /* sampled path (never taken here — flag stays 0): the 6-read frame walk */
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
