#!/usr/bin/env bash
#
# Bench orchestrator: measures request throughput + latency under four probe
# conditions and writes /data/bench.json + /data/bench.txt.
#
#   1. baseline          no tracing at all
#   2. sampling          the 99Hz perf_event sampler (main `tracer` service)
#   3. percall-kuprobe   a kernel uprobe, fired every hit — run for TWO targets:
#                          execute_ex  (task default; ~1 hit/req on PHP 8.3, so
#                                       ~no overhead — ZEND_VM_ENTER inlining)
#                          _emalloc    (~87k hits/req; real per-call trap cost)
#   4. percall-bpftime   the SAME program in userspace via bpftime, both targets
#
# Every percall row carries fire_count = probe hits during the measured window,
# so "did the uprobe actually attach & fire" is answerable from bench.json.
#
# Runs from the HOST (needs docker + docker compose). Load is generated inside a
# container (oha), never on the host. The main demo stack (php/nginx/mysql) is
# never brought down; tracer, loadgen and ui are stopped during measurement
# (they compete for CPU on this saturated microbenchmark) and restored on exit.
#
# Env: DUR=30s WARMUP=5 CONNS="16 4" RUN_BPFTIME=1 PROBES="execute_ex _emalloc"
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
COMPOSE="docker compose -f $ROOT/docker-compose.yml"
NET="phptrace_default"
LOAD_IMG="phptrace-load"

DUR="${DUR:-30s}"
WARMUP="${WARMUP:-5}"
CONNS="${CONNS:-16 4}"
RUN_BPFTIME="${RUN_BPFTIME:-1}"
RUN_DTRACE="${RUN_DTRACE:-1}"
PROBES="${PROBES:-execute_ex _emalloc}"
ENDPOINTS="${ENDPOINTS:-/fast /cpu}"

RESULTS=()
log() { printf '\033[1;36m[bench]\033[0m %s\n' "$*" >&2; }

ensure_load_img() {
  docker image inspect "$LOAD_IMG" >/dev/null 2>&1 || {
    log "building load image ($LOAD_IMG)"
    docker build -q -f "$HERE/Dockerfile.load" -t "$LOAD_IMG" "$HERE" >/dev/null; }
}

# Cumulative probe hits reported by a loader (percall / php-bench) in its logs.
read_counter() {
  $COMPOSE --profile bench logs "$1" 2>/dev/null | grep -o 'calls=[0-9]*' | tail -1 | grep -o '[0-9]*'
}

# measure <name> <base-url> <probe|none> <counter-svc|->
measure() {
  local name="$1" base="$2" probe="$3" csvc="$4" conn ep obj c0 c1 fc
  for conn in $CONNS; do
    for ep in $ENDPOINTS; do
      log "  warmup ${WARMUP}s  $name[$probe] c$conn $ep"
      docker run --rm --network "$NET" "$LOAD_IMG" -c \
        "oha --no-tui -z ${WARMUP}s -c $conn '$base$ep' >/dev/null 2>&1" || true
      c0=0; [ "$csvc" != "-" ] && { c0=$(read_counter "$csvc"); c0=${c0:-0}; }
      log "  measure ${DUR}  $name[$probe] c$conn $ep"
      obj=$(docker run --rm --network "$NET" "$LOAD_IMG" -c \
        "oha --no-tui --output-format json -z $DUR -c $conn '$base$ep' 2>/dev/null | \
         jq -c --arg n '$name' --arg e '$ep' --arg p '$probe' --argjson c $conn '{
           name:\$n, probe:\$p, endpoint:\$e, conn:\$c,
           rps:(.summary.requestsPerSec*10|round/10),
           p50_ms:(.latencyPercentiles.p50*1000000|round/1000),
           p99_ms:(.latencyPercentiles.p99*1000000|round/1000),
           success:.summary.successRate
         }'")
      [ -z "$obj" ] && obj="{\"name\":\"$name\",\"probe\":\"$probe\",\"endpoint\":\"$ep\",\"conn\":$conn,\"error\":\"no result\"}"
      if [ "$csvc" != "-" ]; then
        c1=$(read_counter "$csvc"); c1=${c1:-0}
        fc=$((c1 - c0)); [ "$fc" -lt 0 ] && fc=0
        obj="${obj%\}},\"fire_count\":$fc}"   # splice into the compact object
      fi
      log "    $obj"
      RESULTS+=("$obj")
    done
  done
}

wait_percall_ready() {
  local i
  for i in $(seq 1 30); do
    $COMPOSE --profile bench logs percall 2>/dev/null | grep -q "percall: ready" && return 0
    sleep 1
  done
  return 1
}

# Wait until an nginx target serves /fast (200). Arg: base URL.
wait_http() {
  local base="$1" i code
  for i in $(seq 1 40); do
    code=$(docker run --rm --network "$NET" curlimages/curl:latest \
             -s -o /dev/null -w '%{http_code}' --max-time 5 "$base/fast" 2>/dev/null || echo 000)
    [ "$code" = "200" ] && return 0
    sleep 1
  done
  return 1
}

cleanup() {
  log "restoring stack (tracer/loadgen/ui up, bench services down)"
  unset PROBE_FUNC PHPFPM_MATCH_SYM AGENT_MODE
  $COMPOSE --profile bench stop percall php-bench nginx-bench php-dtrace nginx-dtrace >/dev/null 2>&1 || true
  $COMPOSE --profile bench rm -f percall php-bench nginx-bench php-dtrace nginx-dtrace >/dev/null 2>&1 || true
  $COMPOSE up -d tracer loadgen ui >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ----------------------------------------------------------------- run
ensure_load_img
log "stopping tracer + loadgen + ui for a quiet baseline"
$COMPOSE stop tracer loadgen ui >/dev/null 2>&1 || true
$COMPOSE --profile bench stop percall php-bench nginx-bench >/dev/null 2>&1 || true
sleep 2

# 1. baseline
log "condition 1: baseline (no tracing)"
measure "baseline" "http://nginx" "none" "-"

# 2. sampling
log "condition 2: sampling (99Hz perf_event)"
$COMPOSE up -d tracer >/dev/null 2>&1; sleep 4
measure "sampling" "http://nginx" "none" "-"
$COMPOSE stop tracer >/dev/null 2>&1

# 3. percall kernel uprobe — one pass per probe target
for probe in $PROBES; do
  log "condition 3: percall kernel uprobe [$probe]"
  export PROBE_FUNC="$probe"
  $COMPOSE --profile bench up -d --build --force-recreate percall >/dev/null 2>&1
  if wait_percall_ready; then
    measure "percall-kuprobe" "http://nginx" "$probe" "percall"
  else
    log "percall loader [$probe] never became ready"
    RESULTS+=("{\"name\":\"percall-kuprobe\",\"probe\":\"$probe\",\"status\":\"unavailable\",\"reason\":\"loader not ready\"}")
  fi
  $COMPOSE --profile bench stop percall >/dev/null 2>&1
  unset PROBE_FUNC
done

# 4. percall bpftime — one pass per probe target
if [ "$RUN_BPFTIME" = "1" ]; then
  for probe in $PROBES; do
    log "condition 4: percall bpftime [$probe]"
    export PROBE_FUNC="$probe"
    if bash "$HERE/bpftime_run.sh"; then
      measure "percall-bpftime" "http://nginx-bench" "$probe" "php-bench"
    else
      reason=$(cat "$ROOT/data/bpftime_status.txt" 2>/dev/null || echo "bpftime run failed")
      log "bpftime [$probe] unavailable: $reason"
      RESULTS+=("{\"name\":\"percall-bpftime\",\"probe\":\"$probe\",\"status\":\"unavailable\",\"reason\":\"$reason\"}")
    fi
    $COMPOSE --profile bench stop php-bench nginx-bench >/dev/null 2>&1
    unset PROBE_FUNC
  done
else
  RESULTS+=('{"name":"percall-bpftime","status":"skipped","reason":"RUN_BPFTIME=0"}')
fi

# 5. dtrace: the FAITHFUL per-call execute_ex reproduction ------------
# php-dtrace is php-fpm built --enable-dtrace; with USE_ZEND_DTRACE=1,
# zend_execute_ex := dtrace_execute_ex and execute_ex fires per userland call.
if [ "$RUN_DTRACE" = "1" ]; then
  log "condition 5: dtrace stack (execute_ex fires per call)"
  export AGENT_MODE=0; unset PROBE_FUNC PHPFPM_MATCH_SYM
  $COMPOSE --profile bench up -d --build --force-recreate php-dtrace nginx-dtrace >/dev/null 2>&1
  if wait_http "http://nginx-dtrace"; then
    # 5a. baseline on the dtrace build itself (no probe)
    measure "baseline-dtrace" "http://nginx-dtrace" "none" "-"

    # 5b. kernel uprobe on execute_ex of the dtrace binary (per-call!)
    log "condition 5b: percall kernel uprobe [execute_ex@dtrace]"
    export PROBE_FUNC="execute_ex" PHPFPM_MATCH_SYM="dtrace_execute_ex"
    $COMPOSE --profile bench up -d --force-recreate percall >/dev/null 2>&1
    if wait_percall_ready; then
      measure "percall-kuprobe" "http://nginx-dtrace" "execute_ex@dtrace" "percall"
    else
      RESULTS+=('{"name":"percall-kuprobe","probe":"execute_ex@dtrace","status":"unavailable","reason":"loader not ready"}')
    fi
    $COMPOSE --profile bench stop percall >/dev/null 2>&1
    unset PHPFPM_MATCH_SYM

    # 5d. sampling (99Hz) on the SAME dtrace build — fair vs the dtrace baseline
    # (controls the JIT-off confound: all dtrace rows share one binary).
    log "condition 5d: sampling@dtrace (99Hz on the dtrace build)"
    $COMPOSE up -d tracer >/dev/null 2>&1; sleep 4
    measure "sampling-dtrace" "http://nginx-dtrace" "none" "-"
    $COMPOSE stop tracer >/dev/null 2>&1

    # 5c. bpftime userspace uprobe on execute_ex of the dtrace binary
    if [ "$RUN_BPFTIME" = "1" ]; then
      log "condition 5c: percall bpftime [execute_ex@dtrace]"
      export AGENT_MODE=1 PROBE_FUNC="execute_ex"
      $COMPOSE --profile bench up -d --force-recreate php-dtrace nginx-dtrace >/dev/null 2>&1
      if wait_http "http://nginx-dtrace"; then
        measure "percall-bpftime" "http://nginx-dtrace" "execute_ex@dtrace" "php-dtrace"
      else
        RESULTS+=('{"name":"percall-bpftime","probe":"execute_ex@dtrace","status":"unavailable","reason":"php-dtrace+agent not ready"}')
      fi

      # 5e. bpftime + per-request soft-sampling (1/N): the hook still FIRES on
      # every call, but the eBPF work runs only for 1 in N requests. Shows how
      # much per-request sampling recovers (data/work down, trap cost stays).
      log "condition 5e: bpftime execute_ex@dtrace + soft-sampling 1/10"
      export AGENT_MODE=1 PROBE_FUNC="execute_ex" SAMPLE_N=10
      $COMPOSE --profile bench up -d --force-recreate php-dtrace nginx-dtrace >/dev/null 2>&1
      if wait_http "http://nginx-dtrace"; then
        measure "percall-bpftime-soft" "http://nginx-dtrace" "execute_ex@dtrace+soft1/10" "php-dtrace"
      else
        RESULTS+=('{"name":"percall-bpftime-soft","probe":"execute_ex@dtrace+soft1/10","status":"unavailable","reason":"not ready"}')
      fi
      unset SAMPLE_N
      export AGENT_MODE=0
    fi
  else
    log "php-dtrace never served /fast"
    RESULTS+=('{"name":"baseline-dtrace","status":"unavailable","reason":"php-dtrace not ready"}')
  fi
  $COMPOSE --profile bench stop php-dtrace nginx-dtrace >/dev/null 2>&1
  unset AGENT_MODE PROBE_FUNC
fi

# ----------------------------------------------------------------- emit
OUT_JSON="$ROOT/data/bench.json"; OUT_TXT="$ROOT/data/bench.txt"
{
  printf '{\n  "generated": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "params": {"duration": "%s", "warmup_s": %s, "conns": "%s"},\n' "$DUR" "$WARMUP" "$CONNS"
  printf '  "note": "execute_ex fires ~1x/request on PHP 8.3 (VM inlining); _emalloc is the per-call proxy. fire_count = probe hits during the measured window.",\n'
  printf '  "conditions": [\n'
  for i in "${!RESULTS[@]}"; do
    sep=","; [ "$i" -eq $(( ${#RESULTS[@]} - 1 )) ] && sep=""
    printf '    %s%s\n' "${RESULTS[$i]}" "$sep"
  done
  printf '  ]\n}\n'
} > "$OUT_JSON"
log "wrote $OUT_JSON"

docker run --rm -v "$ROOT/data:/data" "$LOAD_IMG" -c '
  printf "%-16s %-12s %-6s %-6s %10s %8s %8s %14s\n" condition probe conn endpoint rps p50_ms p99_ms fire_count
  printf "%-16s %-12s %-6s %-6s %10s %8s %8s %14s\n" ---------------- ------------ ----- ------ ---------- -------- -------- --------------
  jq -r ".conditions[] | select(.rps) | [.name,.probe,(.conn|tostring),.endpoint,(.rps|tostring),(.p50_ms|tostring),(.p99_ms|tostring),((.fire_count // \"-\")|tostring)] | @tsv" /data/bench.json |
  while IFS=$(printf "\t") read -r n pr c e r p50 p99 fc; do
    printf "%-16s %-12s %-6s %-6s %10s %8s %8s %14s\n" "$n" "$pr" "$c" "$e" "$r" "$p50" "$p99" "$fc"
  done
  echo
  jq -r ".conditions[] | select(.status) | \"NOTE  \(.name) [\(.probe // \"-\")]: \(.status) — \(.reason)\"" /data/bench.json
' | tee "$OUT_TXT"
log "wrote $OUT_TXT"
