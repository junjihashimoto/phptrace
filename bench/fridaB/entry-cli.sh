#!/bin/sh
# Design B (Frida) — fork-free substrate. php-fpm forks workers without exec,
# and frida-gadget's runtime does not survive that fork (workers SIGSEGV on the
# first inherited hook). PHP's built-in server (`php -S`) is single-process, so
# the gadget loads per-process and Interceptor attach/detach works. We launch
# WORKERS single-process servers (ports 8001..800N), each with its own gadget +
# agent, and nginx load-balances across them — matching the 4-worker fpm setup.
set -e

export USE_ZEND_DTRACE="${USE_ZEND_DTRACE:-1}"
SAMPLE_N="${SAMPLE_N:-1}"
WORKERS="${WORKERS:-4}"
GADGET="${GADGET:-1}"

sed "s/__SAMPLE_N__/${SAMPLE_N}/" /opt/fridaB/agent.js.tmpl > /opt/fridaB/agent.js
echo "fridaB-cli-entry: SAMPLE_N=${SAMPLE_N} WORKERS=${WORKERS} GADGET=${GADGET} USE_ZEND_DTRACE=${USE_ZEND_DTRACE}"

i=1
while [ "$i" -le "$WORKERS" ]; do
  port=$((8000 + i))
  if [ "$GADGET" = "1" ]; then
    env LD_PRELOAD=/opt/fridaB/frida-gadget.so \
      php -S 0.0.0.0:$port -t /var/www/html /var/www/html/index.php &
  else
    php -S 0.0.0.0:$port -t /var/www/html /var/www/html/index.php &
  fi
  i=$((i+1))
done
wait
