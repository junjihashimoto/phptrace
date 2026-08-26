/* Compute-heavy probe: a fixed unrolled arithmetic workload, so the measured
 * delta is dominated by eBPF *VM execution* (not the trampoline). This is
 * where the LLVM JIT should pull ahead of the ubpf interpreter. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe/bench_target")
int probe(void *ctx)
{
    /* xorshift is non-linear so the compiler can't fold the rounds into a
     * single op (a mul-add recurrence gets strength-reduced away). 256
     * rounds ≈ 256*3 real eBPF ALU ops that the VM must actually execute. */
    unsigned long s = (unsigned long)ctx | 1;
#pragma clang loop unroll(full)
    for (int i = 0; i < 256; i++) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
    }
    return (int)(s & 0x7);
}
