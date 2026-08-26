/* Map-helper probe: 8 map lookups per fire, minimal per-lookup work. The
 * measured delta is dominated by the HELPER-CALL cost (VM -> native boundary +
 * the map implementation). No compute, no memory-read of the target. This is
 * the axis where bpftime's userspace shared-memory maps have no advantage over
 * the kernel's JIT-integrated per-CPU maps. No atomic (ubpf rejects 0xdb). */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} arr SEC(".maps");

SEC("uprobe/bench_target")
int probe(void *ctx)
{
    __u64 acc = 0;
#pragma unroll
    for (__u32 i = 0; i < 8; i++) {
        __u32 k = i;
        __u64 *v = bpf_map_lookup_elem(&arr, &k);
        if (v) { acc += *v; *v = acc; }   /* non-atomic write-back */
    }
    return (int)(acc & 7);
}
