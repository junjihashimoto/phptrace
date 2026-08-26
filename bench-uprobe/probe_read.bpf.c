/* Read-helper probe: follow a 6-deep pointer chain in the target via
 * bpf_probe_read_user (stands in for walking a Zend execute_data frame). The
 * measured delta is dominated by 6 read HELPER calls. In bpftime the agent
 * runs in-process, so the read is a near-local memcpy; in the kernel it is
 * copy_from_user. This isolates the read-helper cost per mechanism.
 * NB: the chain head is a loop-invariant arg => cache-hot reads (a lower bound;
 * the real tracer reads a cold, per-call-varying frame). */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe/bench_target")
int probe(struct pt_regs *ctx)
{
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
