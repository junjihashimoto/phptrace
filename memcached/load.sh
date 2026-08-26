#!/bin/sh
# memcached load: prime keys, then hammer GETs (exercises the on-CPU hot
# path — protocol parse, hash, assoc_find, item_get) plus periodic SETs.
# Uses busybox nc; runs CONCURRENCY parallel connections.
H="${MC_HOST:-memcached}"
P="${MC_PORT:-11211}"
CONCURRENCY="${CONCURRENCY:-4}"

prime() {
  { i=0
    while [ "$i" -lt 300 ]; do
      printf 'set k%d 0 0 32\r\n%032d\r\n' "$i" "$i"
      i=$((i + 1))
    done
    printf 'quit\r\n'
  } | nc "$H" "$P" >/dev/null 2>&1
}

worker() {
  while :; do
    { i=0
      while [ "$i" -lt 800 ]; do
        printf 'get k%d\r\n' "$((i % 300))"
        if [ "$((i % 20))" -eq 0 ]; then
          printf 'set k%d 0 0 32\r\n%032d\r\n' "$((i % 300))" "$i"
        fi
        i=$((i + 1))
      done
      printf 'quit\r\n'
    } | nc "$H" "$P" >/dev/null 2>&1 || true
  done
}

echo "memcached-load: priming $H:$P"
prime
echo "memcached-load: $CONCURRENCY workers"
i=0
while [ "$i" -lt "$CONCURRENCY" ]; do
  worker &
  i=$((i + 1))
done
wait
