#!/bin/sh
# Weighted random load against the demo app, CONCURRENCY parallel loops.
BASE_URL="${BASE_URL:-http://nginx}"
CONCURRENCY="${CONCURRENCY:-3}"

worker() {
  while :; do
    r=$(( $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 100 ))
    if   [ "$r" -lt 30 ]; then ep=/fast
    elif [ "$r" -lt 50 ]; then ep=/slow
    elif [ "$r" -lt 75 ]; then ep=/db
    elif [ "$r" -lt 90 ]; then ep=/cpu
    else ep=/mixed; fi
    curl -s -o /dev/null --max-time 10 "$BASE_URL$ep$EP_SUFFIX" || true
    # jitter 0-200ms so requests don't sync up
    sleep "0.$(( $(od -An -N1 -tu1 /dev/urandom | tr -d ' ') % 2 ))$(( $(od -An -N1 -tu1 /dev/urandom | tr -d ' ') % 10 ))"
  done
}

echo "loadgen: $CONCURRENCY workers -> $BASE_URL"
i=0
while [ "$i" -lt "$CONCURRENCY" ]; do
  worker &
  i=$((i + 1))
done
wait
