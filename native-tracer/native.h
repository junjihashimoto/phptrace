/* Shared between native.bpf.c (kernel) and native.c (userspace).
 * A language-agnostic on-CPU sampler + optional request-boundary latency
 * probe: unlike the PHP tracer it walks the *native* user stack
 * (bpf_get_stack, frame pointers) and probes a native boundary function,
 * so it works on memcached / any C/C++ binary. */
#ifndef NATIVE_H
#define NATIVE_H

#define NST_MAX 64    /* max native frames per sample */
#define MAX_CMD 160   /* boundary probe: captured op/command string */

enum ev_kind { EV_SAMPLE = 1, EV_SPAN = 2 };

/* on-CPU sample: raw instruction pointers, symbolized in userspace */
struct ev_nsample {
    unsigned int kind;               /* EV_SAMPLE */
    unsigned int pid;
    unsigned int nbytes;             /* bytes written by bpf_get_stack */
    unsigned int _pad;
    unsigned long long ts;           /* bpf_ktime_get_ns (CLOCK_MONOTONIC) */
    unsigned long long ips[NST_MAX]; /* leaf first */
};

/* request-boundary span: one op's processing latency (surface interface
 * only — a single uprobe/uretprobe pair, NOT per internal call) */
struct ev_span {
    unsigned int kind;               /* EV_SPAN */
    unsigned int pid;
    unsigned long long ts;           /* op start */
    unsigned long long dur_ns;       /* entry -> return */
    char cmd[MAX_CMD];               /* the command/op string (arg) */
};

#endif
