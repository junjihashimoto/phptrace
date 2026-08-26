# bench — probe-overhead comparison (task #8)

Measures request throughput and latency of the demo app under four
instrumentation conditions, to quantify what each style of eBPF tracing costs:

| # | condition          | what runs                                                        | target        |
|---|--------------------|------------------------------------------------------------------|---------------|
| 1 | `baseline`         | nothing (tracer + loadgen + ui stopped)                          | `nginx`       |
| 2 | `sampling`         | the main `tracer` service (99 Hz perf_event stack sampler)       | `nginx`       |
| 3 | `percall-kuprobe`  | a **kernel** uprobe fired every hit — `execute_ex` and `_emalloc`| `nginx`       |
| 4 | `percall-bpftime`  | the **same** eBPF program run in **userspace** by bpftime        | `nginx-bench` |
| 5 | `*@dtrace`         | conditions 3+4 for `execute_ex` on a **--enable-dtrace** PHP     | `nginx-dtrace`|

Output: `data/bench.json` (machine-readable) and `data/bench.txt` (table).

## The probe target: `execute_ex` vs `_emalloc` (important)

The task names `execute_ex` as a probe that "fires per PHP function call".
**On stock `php:8.3-fpm` a static uprobe on `execute_ex` fires only ~once per
request, not once per call** — PHP 8's hybrid VM inlines the entire userland
call path (`ZEND_VM_ENTER`), so no exported symbol fires per userland call
(measured, and confirmed by `fire_count` in `bench.json`: ~1 × request count).
Per-call granularity needs an in-process extension that overrides
`zend_execute_ex`, which a uprobe cannot do. So `execute_ex` as a uprobe adds
**no measurable overhead** — an important, counter-intuitive result on its own.

To actually exercise **per-call trap cost** we also probe a genuinely hot Zend
function: **`_emalloc`**, which fires ~87 k times for a single `/cpu` request.
There the kernel-uprobe trap overhead dominates CPU-bound throughput (the
money-chart effect) while a 99 Hz sampler stays flat and bpftime (userspace, no
trap) recovers most of the loss.

`run.sh` therefore runs conditions 3 and 4 for **both** targets
(`PROBES="execute_ex _emalloc"`), and every percall row records
`fire_count` = probe hits during the measured window, so "did the uprobe attach
and fire?" is answerable directly from `bench.json`. The probe is set via
`PROBE_FUNC` (compose env on `percall` / `php-bench`).

### `@dtrace`: the faithful per-call `execute_ex` (the 2024 repro)

There *is* a way to make `execute_ex` fire per call: build PHP with
`--enable-dtrace` and start it with `USE_ZEND_DTRACE=1`. Then `zend_startup`
sets `zend_execute_ex = dtrace_execute_ex`, so the VM's fast-path check
`zend_execute_ex == execute_ex` is false and it takes the **per-call** path —
`dtrace_execute_ex` fires the DTrace fcall probe and calls `execute_ex` for
every userland call. A uprobe on `execute_ex` then fires per call (measured:
tens of thousands per `/cpu` request). This is exactly the 2024 prod shape,
where the distro PHP package was dtrace-enabled.

The official `php:8.3-fpm` image is dtrace-**disabled**, so `bench/Dockerfile.dtrace`
rebuilds PHP `--enable-dtrace` (bench-only; the main app image is untouched).
`run.sh` condition 5 brings up `php-dtrace` (env `USE_ZEND_DTRACE=1`) behind
`nginx-dtrace` and measures `execute_ex@dtrace` under both the kernel uprobe and
bpftime, plus a `baseline-dtrace` row (the dtrace build itself is marginally
different even before probes). `fire_count` on these rows is the proof: with the
env set it is tens of thousands per request; without it, ~1.

Both conditions load the identical `percall.bpf.o` (`SEC("uprobe")`, increment a
per-CPU counter). Only the execution engine differs: kernel vs bpftime userspace
VM.

## Measurement hygiene / caveat

This is a **saturated microbenchmark**: on `/fast` the app already does ~10k+
rps, so the box is CPU-bound and *any* extra CPU consumer depresses rps. `run.sh`
stops `tracer`, `loadgen` **and** `ui` during measurement (and restores them
after) so those don't contaminate results. Even so, treat absolute rps as
relative, not production numbers. `run.sh` sweeps two concurrencies
(`CONNS="16 4"`); the `-c4` rows are less saturated and closer to the production
story — compare conditions *within* a concurrency, not across.

## Usage

From the host (needs `docker` + `docker compose`; the load generator runs in a
container — nothing is installed on the host):

```sh
bash bench/run.sh
```

Knobs (env):

```sh
DUR=30s WARMUP=5 CONN=16 RUN_BPFTIME=1 bash bench/run.sh
```

* `DUR` — measurement window per endpoint (default `30s`)
* `WARMUP` — warmup seconds before each measurement (default `5`)
* `CONN` — concurrent connections, oha `-c` (default `16`)
* `RUN_BPFTIME` — `1` to attempt condition 4 (default), `0` to skip it

A quick smoke run:

```sh
DUR=5s WARMUP=3 RUN_BPFTIME=0 bash bench/run.sh
```

`run.sh` stops `tracer` and `loadgen` during measurement (they add noise),
brings up exactly the service each condition needs, and **restores** the stack
(`tracer` + `loadgen` back up, bench services down) on exit. It never touches
`php`/`nginx`/`mysql`/`ui`.

### Condition 4 only, by hand

```sh
docker compose --profile bench build php-bench          # compiles bpftime (slow)
docker compose --profile bench up -d php-bench nginx-bench
docker run --rm --network phptrace_default phptrace-load \
  -c 'oha --no-tui --output-format json -z 30s -c 16 http://nginx-bench/cpu'
docker compose --profile bench down            # or: stop php-bench nginx-bench
```

## Files

| file                 | purpose                                                        |
|----------------------|----------------------------------------------------------------|
| `percall.bpf.c`      | the eBPF program (uprobe → per-CPU counter)                    |
| `percall_load.c`     | libbpf loader/attacher (kernel **and** bpftime)               |
| `Makefile`           | builds `percall.bpf.o` + `percall_load`                       |
| `Dockerfile`         | condition 3 image (kernel uprobe, privileged, `pid:host`)     |
| `Dockerfile.bpftime` | condition 4 image: builds bpftime + php-fpm under the agent   |
| `Dockerfile.load`    | `oha` load-generator image                                    |
| `fpm-bench.conf`     | php-fpm pool for the bpftime target (static, 4 workers)       |
| `nginx.conf`         | nginx-bench → php-bench:9000                                  |
| `bpftime-entry.sh`   | starts loader (syscall-server) then php-fpm (agent)          |
| `bpftime_run.sh`     | builds/starts + verifies condition 4; degrades gracefully    |
| `run.sh`             | orchestrator: runs all four, writes `bench.{json,txt}`        |

## bpftime notes

Built from source (`Dockerfile.bpftime`) for **linux/arm64** with the ubpf
interpreter (`-DBPFTIME_LLVM_JIT=OFF`) — no LLVM dependency, and the glibc of
the `.so`s matches the `php:8.3-fpm` runtime (both bookworm). If bpftime fails
to build or the agent cannot inject into php-fpm on this kernel, `run.sh` still
produces conditions 1–3 and records condition 4 as
`{"status":"unavailable","reason": ...}` in `bench.json`.

## Results summary

Numbers from one run (Docker Desktop / linuxkit, arm64; `data/bench.txt` has
the full table, `data/` is git-ignored — regenerate with `bash run.sh`).
Baseline is **opcache on, JIT off** (`opcache.jit_buffer_size=0`) — the typical
production config — so the overhead is measured against a properly-optimized
PHP, not a strawman. The **CPU-bound `/cpu` at c=16** row is the one that
matters (a KVS/APM workload's real cost); `/fast` is near-noise.

| condition (`/cpu`, c=16)        | RPS | P99 | fire_count | vs baseline |
|---------------------------------|-----|-----|-----------:|-------------|
| `baseline`                      | 345 | 58 ms  | —          | —                          |
| `sampling` (99 Hz, **本命**)    | 333 | 68 ms  | —          | **RPS −3 % / P99 +18 %**   |
| `percall-kuprobe execute_ex`    | 345 | 59 ms  | 2 633      | ~none *(see below)*        |
| `percall-kuprobe execute_ex@dtrace` | **36** | **697 ms** | 20 055 262 | **RPS ÷10 · P99 ×12** |
| `percall-bpftime execute_ex@dtrace` | 166 | 127 ms | 87 875 754 | RPS ÷2 · P99 ×2.2          |

### What the numbers say

1. **Sampling is nearly free and flat.** 99 Hz stack sampling costs ~3 % RPS /
   +18 % P99 on a CPU-bound endpoint, and its cost is *independent of load*
   (fixed rate). This is the design the tracer ships.

2. **`execute_ex` only fires per-call under dtrace.** PHP 8's VM inlines
   userland calls (`DO_UCALL`/`DO_ICALL`), so a uprobe on `execute_ex` fires
   **~once per request** (2 633 hits ≈ the request count) and costs almost
   nothing — but it *sees almost nothing*. Only a `--enable-dtrace` build
   started with `USE_ZEND_DTRACE=1` re-points `zend_execute_ex` at
   `dtrace_execute_ex`, which fires **per userland call** (20 M hits). The
   fire_count column makes this visible: **2 633 vs 20 000 000** for the same
   probe on the same endpoint.

3. **Per-call tracing is catastrophic — and this reproduces the 2024 incident.**
   Real per-call `execute_ex@dtrace` drops throughput to **1/10** and inflates
   P99 **12×**. This is the "we doubled production P99" story, quantified.

4. **bpftime softens per-call but doesn't rescue it.** Running the identical
   per-call program in userspace (inline binary rewrite, no kernel trap) is
   ~**4.6× the RPS and ~5.5× better P99** than the kernel uprobe (166 vs 36 rps,
   127 vs 697 ms) — impressive, but still ÷2 RPS vs baseline. bpftime lowers the
   *per-probe unit cost*; it doesn't make per-call-of-everything cheap.

**Orthogonality (easy to conflate):** *kernel-uprobe vs bpftime* is the probe
**delivery** mechanism; *dtrace on/off* is what decides whether `execute_ex`
fires **per-call** at all. `percall-bpftime execute_ex@dtrace` = bpftime
cheaply delivering a probe that fires per-call *because of* dtrace. Without
`@dtrace`, bpftime on `execute_ex` also sees only ~1 hit/request.

### Per-request sampling — does thinning per-call tracing help? (`SAMPLE_N`)

Can you keep per-call tracing but only pay for 1 in N requests? A
request-boundary probe (`php_request_startup`) flags 1/N requests; the hot
`execute_ex@dtrace` probe does the representative **work** (a 6-deep user-memory
read, standing in for a stack read) only for flagged requests — but still
**fires** on every call to check the flag. Here the hot probe does *real work*,
unlike the counter-only handler in the table above, so numbers differ.
(`/cpu`, c=16, 10 s; regenerate with `SAMPLE_N=… bash run.sh` after building the
bench images.)

| delivery | SAMPLE_N | RPS | P99 | fires   | work    |
|----------|---------:|----:|----:|--------:|--------:|
| kernel   | 1        | 41.7 | 578 ms | 30.9 M | 31.1 M |
| kernel   | 10       | 40.7 | 599 ms | 31.5 M |  3.6 M |
| kernel   | 100      | 41.2 | 575 ms | 32.1 M |  0.32 M|
| bpftime  | 1        | 37.7 | 650 ms | 28.7 M | 28.7 M |
| bpftime  | 10       | 39.0 | 623 ms | 28.2 M | 28.2 M |
| bpftime  | 100      | 38.0 | 619 ms | 29.1 M | 29.1 M |

1. **On the kernel, sampling cuts the *work* but not the *fire* — so it can't
   recover throughput.** `work` drops N× (31 M → 3.6 M → 0.32 M) yet `fires`
   stays ~31 M and **RPS stays pinned at ~41** (baseline ~350). The int3 trap is
   paid on every call regardless of whether that request is sampled.

2. **At SN=1 (work every call), delivery barely matters** — kernel ~41, ubpf
   ~38, and (below) LLVM-JIT ~38. The per-call **work here is 6× `bpf_probe_
   read_user` = *helper* calls** (fixed compiled C in the runtime), and it
   *dominates* the per-hit cost, hiding the trap-vs-dispatch difference. (This
   corrects an earlier guess that ubpf's *interpreter* was the cause — see the
   JIT section: JIT doesn't speed helpers, only bytecode dispatch, so it's ~38
   too.)

**Bottom line (this section):** on the kernel, per-request thinning does *not*
bound overhead — the trap is per-fire. The sampler's *time*-based thinning does
(fixed rate, no per-call probe). But whether thinning helps at all depends on
the delivery's per-fire cost — see the LLVM-JIT section, where it does.

### bpftime LLVM-JIT on arm64 — where per-request sampling *does* work

Rebuilt bpftime with its LLVM backend (`-DBPFTIME_LLVM_JIT=ON`,
`bench/Dockerfile.bpftime-jit` + `Dockerfile.dtrace-jit`). arm64 was *not* a
blocker: install an LLVM dev toolchain + point `-DLLVM_DIR` at it, and add the
`libllvm19` runtime lib. Runtime log confirms `Using VM: llvm` (JIT, not ubpf);
`fires` in the tens-to-hundreds of millions confirm per-call execution.

| delivery      | SAMPLE_N | RPS   | P99    | fires   | work   |
|---------------|---------:|------:|-------:|--------:|-------:|
| bpftime-JIT   | 1        | 38.3  | 629 ms | 34.1 M  | 34.1 M |
| bpftime-JIT   | 100      | **130.9** | 178 ms | 117.2 M | 0.64 M |
| *(ref)* kernel| 1 / 100  | 41.7 / 41.2 | | 31 M | |

Two findings, one of them the payoff of this whole thread:

1. **JIT did *not* give bpftime a blanket win for realistic per-call work**
   (38 vs kernel 41 at SN=1). JIT accelerates the eBPF *bytecode dispatch*, not
   the *helpers* the program calls — and this payload is helper-bound.

2. **But per-request sampling recovers throughput on bpftime, not on the
   kernel.** Skipping the work for 99 % of requests takes bpftime-JIT from
   **38 → 131 rps** even while it *fires* 117 M times — because its per-fire
   cost is cheap and the skipped cost was real work. The kernel stays pinned
   at ~41 at every SN: the int3 trap is paid on every fire, so there's nothing
   to recover. (This also resolves the ubpf caveat above — under the JIT build
   the cross-program sample flag gates correctly.)

**Grand bottom line:** *kernel-uprobe* per-call tracing is unrecoverable — the
trap dominates and sampling can't dent it. *bpftime* per-call tracing *is*
tunable — cheap fires mean per-request sampling trades coverage for throughput
(38→131). But neither beats the design that needs no per-call probe at all:
99 Hz *time* sampling, flat ~3 % regardless of code shape.

### The fair competitor: in-process selective hooking (Observer API)

"Trace everything with an eBPF uprobe" is a strawman — no real APM does that.
The honest competitor is **selective in-process hooking**, and its production
form is the PHP **Observer API** (`zend_observer_fcall_register`, what Datadog's
ddtrace uses). `bench/observer/apmobs.c` is a minimal such extension; it decides
*once per function* (cached) whether to attach begin/end, and — unlike hooking
`zend_execute_ex` — does **not** disable the VM's call specialization.
(`/cpu`, c=16, 10 s, opcache-on/JIT-off; `OBS_ALL`/`OBS_FUNCS` select scope.)

| condition                                  | RPS  | P99   | vs baseline |
|--------------------------------------------|-----:|------:|-------------|
| baseline (extension loaded, observes none) | 346.9| 58 ms | —           |
| observer, **selective** (4 functions)      | 340.1| 61 ms | −2 %        |
| observer, **all** userland calls           | 336.6| 60 ms | −3 %        |
| *(ref)* 99 Hz sampling                     | 333  | 68 ms | −3 %        |
| *(ref)* uprobe `execute_ex@dtrace` per-call| **36** | **697 ms** | **÷10** |

The headline: **the Observer API observing *every* userland call costs ~3 %** —
about the same as 99 Hz sampling, and **~10× cheaper than the eBPF per-call
uprobe**. So per-call tracing is *not* inherently catastrophic — the eBPF
disaster is specific to (a) the kernel trap and (b) dtrace-mode's VM
de-optimization. Done in-process the right way, per-call is cheap. (This is the
begin/end *floor*: apmobs only counts the call; a real tracer's span-building
work adds to it.)

So the real tradeoff between our sampler and the ddtrace-style competitor is
**not overhead** (both ~3 %) — it's:

- **deployment**: eBPF sampler is *out-of-process*, attaches to a running,
  unmodified php-fpm (target untouched, no extension, no restart); the Observer
  API is an *in-process* extension in every worker (a bug there can crash FPM).
- **data**: sampler is statistical + on-CPU only (needs boundary uprobes for
  off-CPU/latency); the Observer API gives exact per-call enter/exit spans.
- **coverage vs cost shape**: sampling cost is flat and code-shape-independent;
  selective hooking is cheap for boundary functions but grows toward per-call
  as you widen the set — you must know what to hook.

**Takeaway for the design:** get exhaustive coverage from **sampling** (reads
the Zend VM stack directly — needs neither dtrace nor per-call probes), and use
**boundary uprobes** (request start/end, mysqlnd) for the latency breakdown.
Per-call tracing is only viable at all with bpftime, and even then it's a
"staging/canary" tool, not something to leave on in production.

### Duty-cycle the probe (attach/detach in time) — recovers the average, not the tail

If per-request thinning can't dodge the kernel trap (it fires every call), the
only way to make a per-call kernel uprobe cheap is to *remove* it when you're
not looking: attach for a short window, detach for a longer one, repeat.
`percall_load.c` does this with `DUTY_ON_MS`/`DUTY_OFF_MS` (both 0 = always on).
During off-windows the probe is gone → zero cost → throughput returns to
baseline. (`execute_ex@dtrace`, /cpu, c=16, 20 s.)

| condition                    | RPS   | p50   | p99    | p999   | max    |
|------------------------------|------:|------:|-------:|-------:|-------:|
| baseline (no probe)          | 357.0 | 45 ms | 57 ms  | 59 ms  | 61 ms  |
| always-on per-call           | 40.1  | 394 ms| 617 ms | 695 ms | 695 ms |
| duty 10 % (1 s on / 9 s off) | 319.0 | 46 ms | **283 ms** | 524 ms | 605 ms |
| duty 2.5 % (250 ms / 9.75 s) | 343.8 | 46 ms | 59 ms  | **285 ms** | 300 ms |

**Average recovers; the tail stays lumpy.** As duty drops, avg RPS climbs back
to 90–96 % of baseline and p50 returns to ~45 ms — but the on-windows are
periodic ÷9 bursts, so the tail spikes persist: at 10 % duty p99 is 283 ms (~5×
baseline) and max 605 ms; even at 2.5 % duty, where p99 recovers, p999/max still
show ~300 ms cliffs. This is the core downside of duty-cycling vs 99 Hz *time*
sampling, which spreads the same average cost **evenly** and keeps p99 flat.

Trade-off summary — three ways to "trace less":

| method                    | fires per call? | overhead shape        | can miss | gives full single trace |
|---------------------------|-----------------|-----------------------|----------|--------------------------|
| per-request (`SAMPLE_N`)  | yes (always)    | ~flat, but floor stays| no (all reqs fire) | no |
| duty-cycle (attach/detach)| only when on    | **lumpy** (tail spikes)| off-windows | **yes** (during on) |
| 99 Hz time sampling (ship)| no probe at all | flat ~3 %, no spikes  | off-CPU only | no |

Duty-cycle's one real advantage: during an on-window you get *complete* per-call
traces (statistical sampling never yields a single complete trace). Its price is
periodic tail spikes + blind off-windows — fine for "record everything for 1 s
occasionally", bad for a latency-SLO service.

### Can an inline/early guard cut the per-fire cost? No — the register save is the floor

Follow-up to the sampling sweep: since per-request thinning skips the eBPF
program's *work* but still *fires*, would a guard placed *early* (at bpftime's
listener entry, before running the eBPF program) push the floor lower? Measured
on bpftime-**JIT** (`Using VM: llvm`), `execute_ex@dtrace`, /cpu c=16, 10 s:

| SAMPLE_N | RPS | fires  | work  | meaning                              |
|---------:|----:|-------:|------:|--------------------------------------|
| 1        | 38  | 34.1 M | 34.1 M| work every fire                      |
| 100      | 136 | 121 M  | 146 k | work skipped 99.9 %                  |
| 100000   | **128** | 117 M | 1 | **floor: fire + ctx-save only, ~no work** |

baseline ≈ 345. **SAMPLE_N=100 (136) already sits at the SAMPLE_N=100000 floor
(128)** — once the program's work is skipped, the eBPF run is no longer the
bottleneck; **frida-gum's per-fire CPU-context save/restore + listener call is**,
paid on all ~12 M `execute_ex` calls/s. A guard at the listener entry can only
skip the eBPF-VM run (already negligible at SN≥100), **not** the context save —
so it cannot beat ~130 (≈38 % of baseline). (We therefore did not bother
patching the listener; the floor measurement proves it futile.)

**Irreducible-floor, one line:** bpftime is cheaper *per fire* than a kernel
trap, but "cheaper" ≠ free — a full CPU-context save on every fire caps
per-call tracing at ~⅓ baseline no matter how trivial the handler.

To go below the ~130 floor you must not pay the save per fire:
1. **hand-rolled minimal-save inline hook** (save only clobbered regs + guard
   inline) — replaces frida's Interceptor; the "decide near, don't jump to a
   full-context trampoline" idea in its complete form. Real work, out of scope.
2. **duty-cycle** — remove the hook when idle (no fire, no save); measured above.
3. **don't fire at all → 99 Hz time sampling** — the shipped design reads the
   Zend VM stack on a timer, so there is no per-call probe and no per-fire save.

So the whole per-call story closes: kernel-uprobe (trap) and bpftime (frida
ctx-save) both have a per-fire floor far below baseline; you tune *where* you
pay (per-request work skip, duty-cycle time windows) but you cannot erase the
fire. Only sampling — which never installs a per-call probe — has no such floor.
