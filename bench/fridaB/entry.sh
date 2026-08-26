#!/bin/sh
# Design B (Frida) entrypoint. Templates SAMPLE_N into the agent, enables the
# dtrace per-call VM path, and LD_PRELOADs frida-gadget into php-fpm so each
# worker runs agent.js (per-request attach/detach of dtrace_execute_ex).
set -e

export USE_ZEND_DTRACE="${USE_ZEND_DTRACE:-1}"
SAMPLE_N="${SAMPLE_N:-1}"

# Template N into the agent (agent.js is copied to a writable path).
sed "s/__SAMPLE_N__/${SAMPLE_N}/" /opt/fridaB/agent.js.tmpl > /opt/fridaB/agent.js

echo "fridaB-entry: SAMPLE_N=${SAMPLE_N} USE_ZEND_DTRACE=${USE_ZEND_DTRACE} GADGET=${GADGET:-0}"
php -i | grep -i 'dtrace' || true

if [ "${GADGET:-1}" = "1" ]; then
  echo "fridaB-entry: starting php-fpm under frida-gadget"
  exec env LD_PRELOAD=/opt/fridaB/frida-gadget.so php-fpm --nodaemonize
else
  echo "fridaB-entry: starting plain php-fpm (no gadget)"
  exec php-fpm --nodaemonize
fi
