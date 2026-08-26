/*
 * eBPF side of the PHP tracer.
 *
 * No kernel struct access at all — everything read is *userspace* memory of
 * the traced PHP process (bpf_probe_read_user), so no vmlinux.h/CO-RE
 * relocations are needed and the object runs on any ringbuf-capable kernel.
 *
 * Programs:
 *   on_sample       perf_event CPU-clock @99Hz: walk the Zend VM stack
 *                   (executor_globals.current_execute_data chain) and emit
 *                   raw zend_function pointers; names resolve in userspace.
 *   on_req_start    uprobe php_request_startup: read method/URI from
 *                   sapi_globals.request_info.
 *   on_req_end      uprobe php_request_shutdown.
 *   on_query        uprobe mysqlnd conn_data::query (addr resolved by loader).
 *   on_query_ret    uretprobe of the same: emit query + duration.
 */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "phptrace.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);            /* pid */
    __type(value, struct proc_cfg);
} procs SEC(".maps");

/* PID namespace (dev, ino) of the userspace loader. When set, the BPF side
 * reports pids in that namespace so they match the loader's /proc scan
 * (needed under k8s where the agent's pid ns is below the kernel's global
 * one). When zero, falls back to the global pid (bare host / pid:host). */
struct nscfg { __u64 dev; __u64 ino; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct nscfg);
} nscfg SEC(".maps");

static __always_inline __u32 cur_pid(void)
{
    __u32 z = 0;
    struct nscfg *n = bpf_map_lookup_elem(&nscfg, &z);
    if (!n || (!n->dev && !n->ino))
        return bpf_get_current_pid_tgid() >> 32;
    struct bpf_pidns_info info = {};
    long r = bpf_get_ns_current_pid_tgid(n->dev, n->ino, &info, sizeof(info));
    if (r == 0)
        return info.tgid;
    return 0;   /* not in the target ns (e.g. another container) */
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);  /* 4 MiB */
} events SEC(".maps");

/* In-flight mysqlnd query per pid (PHP is single-threaded per process). */
struct qstate {
    __u64 ts;
    __u32 nframes;
    __u64 frames[MAX_FRAMES];
    char query[MAX_QUERY];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct qstate);
} inflight_query SEC(".maps");

/* qstate is too big for the 512-byte BPF stack, so build it in a
 * per-cpu scratch slot before stashing into inflight_query. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct qstate);
} qscratch SEC(".maps");

static __always_inline struct proc_cfg *lookup_cfg(__u32 *pid_out)
{
    __u32 pid = cur_pid();
    *pid_out = pid;
    return bpf_map_lookup_elem(&procs, &pid);
}

SEC("perf_event")
int on_sample(struct bpf_perf_event_data *ctx)
{
    __u32 pid;
    struct proc_cfg *cfg = lookup_cfg(&pid);
    if (!cfg)
        return 0;

    __u64 ed = 0;
    bpf_probe_read_user(&ed, sizeof(ed),
                        (void *)(cfg->eg_addr + cfg->off.eg_current_execute_data));
    if (!ed)
        return 0; /* not executing PHP right now (e.g. fpm master) */

    struct ev_sample *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->hdr.type = EV_SAMPLE;
    e->hdr.pid = pid;
    e->hdr.ts = bpf_ktime_get_ns();

    __u32 n = 0;
    for (int i = 0; i < MAX_FRAMES; i++) {
        if (!ed)
            break;
        __u64 func = 0;
        bpf_probe_read_user(&func, sizeof(func), (void *)(ed + cfg->off.ed_func));
        e->frames[i] = func;
        n = i + 1;
        __u64 prev = 0;
        bpf_probe_read_user(&prev, sizeof(prev), (void *)(ed + cfg->off.ed_prev));
        ed = prev;
    }
    e->nframes = n;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe")
int on_req_start(struct pt_regs *ctx)
{
    __u32 pid;
    struct proc_cfg *cfg = lookup_cfg(&pid);
    if (!cfg || !cfg->sg_addr)
        return 0;

    struct ev_req *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->hdr.type = EV_REQ_START;
    e->hdr.pid = pid;
    e->hdr.ts = bpf_ktime_get_ns();
    e->method[0] = 0;
    e->uri[0] = 0;

    __u64 p = 0;
    bpf_probe_read_user(&p, sizeof(p),
                        (void *)(cfg->sg_addr + cfg->off.sg_request_method));
    if (p)
        bpf_probe_read_user_str(e->method, sizeof(e->method), (void *)p);
    p = 0;
    bpf_probe_read_user(&p, sizeof(p),
                        (void *)(cfg->sg_addr + cfg->off.sg_request_uri));
    if (p)
        bpf_probe_read_user_str(e->uri, sizeof(e->uri), (void *)p);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe")
int on_req_end(struct pt_regs *ctx)
{
    __u32 pid;
    struct proc_cfg *cfg = lookup_cfg(&pid);
    if (!cfg)
        return 0;

    struct ev_req *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    e->hdr.type = EV_REQ_END;
    e->hdr.pid = pid;
    e->hdr.ts = bpf_ktime_get_ns();
    e->method[0] = 0;
    e->uri[0] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* mysqlnd: enum_func_status (*query)(MYSQLND_CONN_DATA *conn,
 *                                    const char *query, size_t query_len) */
SEC("uprobe")
int on_query(struct pt_regs *ctx)
{
    __u32 pid;
    struct proc_cfg *cfg = lookup_cfg(&pid);
    if (!cfg)
        return 0;

    __u32 zero = 0;
    struct qstate *st = bpf_map_lookup_elem(&qscratch, &zero);
    if (!st)
        return 0;
    st->ts = bpf_ktime_get_ns();
    st->query[0] = 0;
    const char *q = (const char *)PT_REGS_PARM2(ctx);
    if (q)
        bpf_probe_read_user_str(st->query, sizeof(st->query), q);

    /* Walk the PHP VM stack now (query call site) — same chain the
     * sampler follows. DB wait is off-CPU so a timer sample rarely lands
     * here; capturing at the uprobe gives the caller reliably. */
    __u64 ed = 0;
    bpf_probe_read_user(&ed, sizeof(ed),
                        (void *)(cfg->eg_addr + cfg->off.eg_current_execute_data));
    __u32 n = 0;
    for (int i = 0; i < MAX_FRAMES; i++) {
        if (!ed)
            break;
        __u64 func = 0;
        bpf_probe_read_user(&func, sizeof(func), (void *)(ed + cfg->off.ed_func));
        st->frames[i] = func;
        n = i + 1;
        __u64 prev = 0;
        bpf_probe_read_user(&prev, sizeof(prev), (void *)(ed + cfg->off.ed_prev));
        ed = prev;
    }
    st->nframes = n;
    bpf_map_update_elem(&inflight_query, &pid, st, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int on_query_ret(struct pt_regs *ctx)
{
    __u32 pid = cur_pid();
    struct qstate *st = bpf_map_lookup_elem(&inflight_query, &pid);
    if (!st)
        return 0;

    struct ev_query *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->hdr.type = EV_QUERY;
        e->hdr.pid = pid;
        e->hdr.ts = st->ts;
        e->dur_ns = bpf_ktime_get_ns() - st->ts;
        e->nframes = st->nframes;
        __builtin_memcpy(e->frames, st->frames, sizeof(e->frames));
        __builtin_memcpy(e->query, st->query, MAX_QUERY);
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&inflight_query, &pid);
    return 0;
}
