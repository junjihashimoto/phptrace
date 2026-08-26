#!/usr/bin/env bash
# Bring up the bpftime bench target (php-bench under the agent + nginx-bench)
# and verify it actually serves traffic with the userspace uprobe installed.
# Exit 0 when ready; on failure write the reason to data/bpftime_status.txt
# and exit 1 so run.sh degrades to a 3-condition comparison.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
COMPOSE="docker compose -f $ROOT/docker-compose.yml"
STATUS="$ROOT/data/bpftime_status.txt"

fail() { echo "$1" > "$STATUS"; echo "bpftime_run: FAIL: $1" >&2; exit 1; }

echo "bpftime_run: building php-bench (this compiles bpftime; first run is slow)" >&2
if ! $COMPOSE --profile bench build php-bench >/tmp/bpftime_build.log 2>&1; then
  tail -20 /tmp/bpftime_build.log >&2
  fail "bpftime build failed (see /tmp/bpftime_build.log)"
fi

echo "bpftime_run: starting php-bench + nginx-bench (probe=${PROBE_FUNC:-execute_ex})" >&2
$COMPOSE --profile bench up -d --force-recreate php-bench nginx-bench >/tmp/bpftime_up.log 2>&1 || {
  tail -20 /tmp/bpftime_up.log >&2; fail "compose up php-bench/nginx-bench failed"; }

# Wait for php-fpm (under the agent) to accept fastcgi via nginx-bench.
ready=0
for i in $(seq 1 30); do
  code=$(docker run --rm --network phptrace_default curlimages/curl:latest \
           -s -o /dev/null -w '%{http_code}' --max-time 5 http://nginx-bench/fast 2>/dev/null || echo 000)
  if [ "$code" = "200" ]; then ready=1; break; fi
  sleep 1
done
[ "$ready" = "1" ] || { $COMPOSE --profile bench logs php-bench 2>&1 | tail -30 >&2; \
  fail "php-bench never served /fast (agent injection likely broke php-fpm)"; }

# Confirm the userspace probe is actually firing: hit /cpu, then check the
# loader's counter line in the php-bench logs.
docker run --rm --network phptrace_default curlimages/curl:latest \
  -s -o /dev/null --max-time 15 http://nginx-bench/cpu 2>/dev/null || true
sleep 2
calls=$($COMPOSE --profile bench logs php-bench 2>&1 | grep -o 'calls=[0-9]*' | tail -1 | grep -o '[0-9]*')
calls="${calls:-0}"
echo "bpftime_run: userspace probe counter=$calls" >&2
if [ "$calls" -gt 0 ] 2>/dev/null; then
  echo "ok: bpftime interpreter, userspace uprobe on _emalloc, calls=$calls" > "$STATUS"
  echo "bpftime_run: ready (calls=$calls)" >&2
  exit 0
fi

# Served traffic but the probe didn't fire — report honestly; run.sh will still
# be able to measure, but note the probe was not confirmed. Treat as unavailable
# so the money-chart isn't misattributed.
fail "php-bench served traffic but userspace probe never fired (counter=0)"
