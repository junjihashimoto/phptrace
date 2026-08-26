/*
 * Microbenchmark target: call a hot function in a tight loop and report
 * nanoseconds per call. Running it with/without a uprobe on bench_target
 * isolates the per-fire probe overhead (delta / call).
 *
 * bench_target is noinline + an asm barrier so the call actually happens
 * (not optimized away or inlined) and a probe has a real symbol to hook.
 *
 * arg1 is the head of a small pointer chain (heap) so a read-probe can follow
 * ->next via bpf_probe_read_user (stands in for walking a Zend frame). Probes
 * that don't read the arg simply ignore it; baseline is unaffected (the arg is
 * a loop-invariant constant, built once before timing).
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct node { struct node *next; uint64_t pad; };

__attribute__((noinline)) uint64_t bench_target(uint64_t x)
{
    __asm__ __volatile__("" : : : "memory");
    return x + 1;
}

static double now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

int main(int argc, char **argv)
{
    long iters = argc > 1 ? atol(argv[1]) : 20000000;

    /* build an 8-node pointer chain; pass its head as arg1 */
    struct node *head = NULL;
    for (int i = 0; i < 8; i++) {
        struct node *n = calloc(1, sizeof(*n));
        n->next = head;
        head = n;
    }
    uint64_t arg = (uint64_t)(uintptr_t)head;

    volatile uint64_t s = 0;
    for (long i = 0; i < 2000000; i++) s += bench_target(arg); /* warmup */

    double a = now_ns();
    for (long i = 0; i < iters; i++) s += bench_target(arg);
    double b = now_ns();

    double per = (b - a) / (double)iters;
    fprintf(stderr, "iters=%ld total=%.1fms PER_CALL_NS=%.2f sink=%llu\n",
            iters, (b - a) / 1e6, per, (unsigned long long)s);
    printf("%.2f\n", per);
    return 0;
}
