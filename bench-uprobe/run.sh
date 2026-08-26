#!/bin/bash
# Per-fire uprobe overhead DECOMPOSITION on THIS machine.
#
# For each probe variant, measure per-call ns for:
#   baseline (no probe) / kernel uprobe / bpftime ubpf / bpftime LLVM JIT
# The delta over baseline is the per-fire cost of that (probe, mechanism).
#
# Probe variants isolate WHERE the cost lives:
#   probe       empty (return 0)        -> trampoline / dispatch only
#   probe_map   8 array lookups         -> map HELPER-call cost
#   probe_read  6 probe_read_user       -> read HELPER-call cost
#   probe_full  1 arr +pid +1 hash +6rd -> realistic tracing probe (load-test shape)
#   probe_heavy 768 ALU (xorshift)      -> pure VM execution (JIT vs interp)
#
# Reconciles the paradox: bpftime wins big on `probe` (trampoline) but the
# real tracer is `probe_full`, dominated by helpers/maps/reads that bpftime
# does NOT make cheaper -> the trampoline advantage evaporates.
set -u
ITERS="${ITERS:-20000000}"
DIR=/opt/uprobe
BT="${BPFTIME_DIR:-/opt/bpftime}"
SYSCALL="$BT/libbpftime-syscall-server.so"
AGENT="$BT/libbpftime-agent.so"
PROBES="${PROBES:-probe probe_map probe_read probe_full probe_heavy}"
LOG=/tmp/run.log
: > "$LOG"

one() { "$DIR/target" "$ITERS" 2>>"$LOG"; }
med3() { printf '%s\n%s\n%s\n' "$(one)" "$(one)" "$(one)" | sort -n | sed -n 2p; }
delta() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.1f", b-a}'; }

# measure kernel uprobe for the currently-exported BPF_OBJ; echoes per-call ns or ""
meas_kernel() {
  "$DIR/load" "$DIR/target" 2>/tmp/kl.log &
  local KL=$! ok=""
  for _ in $(seq 1 50); do grep -q READY /tmp/kl.log && { ok=1; break; }; kill -0 $KL 2>/dev/null || break; sleep 0.2; done
  if [ -z "$ok" ]; then kill $KL 2>/dev/null; echo ""; return; fi
  local R; R=$(med3); kill $KL 2>/dev/null; wait $KL 2>/dev/null; echo "$R"
}

# measure bpftime for VM $1 and currently-exported BPF_OBJ; echoes per-call ns or ""
meas_bpftime() {
  local vm="$1"
  rm -f /dev/shm/bpftime* 2>/dev/null
  LD_PRELOAD="$SYSCALL" BPFTIME_VM_NAME="$vm" BPFTIME_LOG_OUTPUT=console "$DIR/load" "$DIR/target" 2>/tmp/bl.log &
  local BL=$! ok=""
  for _ in $(seq 1 50); do grep -q READY /tmp/bl.log && { ok=1; break; }; kill -0 $BL 2>/dev/null || break; sleep 0.2; done
  if [ -z "$ok" ]; then sed 's/^/    /' /tmp/bl.log | tail -4 >>"$LOG"; kill $BL 2>/dev/null; echo ""; return; fi
  export LD_PRELOAD="$AGENT" BPFTIME_VM_NAME="$vm"
  local R; R=$(med3)
  unset LD_PRELOAD BPFTIME_VM_NAME
  kill $BL 2>/dev/null; wait $BL 2>/dev/null; echo "$R"
}

echo "iters=$ITERS  (per-call ns, median of 3; +delta over baseline)"
BASE=$(med3)
printf "baseline (no probe): %s ns\n" "$BASE"
echo "-------------------------------------------------------------------------"
printf "%-12s %14s %16s %16s\n" "probe" "kernel uprobe" "bpftime ubpf" "bpftime llvm"
echo "-------------------------------------------------------------------------"

for pr in $PROBES; do
  export BPF_OBJ="$DIR/$pr.bpf.o"
  KU=$(meas_kernel)
  UB=$(meas_bpftime ubpf)
  LL=$(meas_bpftime llvm)
  fmt() { [ -n "$1" ] && printf "%s (+%s)" "$1" "$(delta "$BASE" "$1")" || printf "%s" "--"; }
  printf "%-12s %14s %16s %16s\n" "$pr" "$(fmt "$KU")" "$(fmt "$UB")" "$(fmt "$LL")"
done
unset BPF_OBJ
echo "-------------------------------------------------------------------------"
echo "read: empty=trampoline only (bpftime wins); full=realistic tracer (helpers dominate)"
