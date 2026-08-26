/* Minimal uprobe (empty body) so the measured delta is the uprobe
 * *mechanism* cost (trap/trampoline + dispatch), not VM execution — the same
 * thing the bpftime paper's Table 1 measures.
 *
 * NB: deliberately no atomic/map op. An earlier version used
 * __sync_fetch_and_add, which compiles to the BPF atomic opcode 0xdb — the
 * ubpf *interpreter* rejects it ("unknown opcode 0xdb"), while the LLVM JIT
 * accepts it. That divergence is itself a real ubpf-vs-JIT limitation. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe/bench_target")
int probe(void *ctx)
{
    return 0;
}
