#!/bin/sh
# Entrypoint for the php-dtrace container.
#
# The php-fpm here is built --enable-dtrace. With USE_ZEND_DTRACE=1, zend_startup
# points zend_execute_ex at dtrace_execute_ex, so the VM takes the per-call path
# (no ZEND_VM_ENTER inlining) and execute_ex fires once per userland function
# call — the faithful 2024 prod repro.
#
# Two modes:
#   AGENT_MODE unset/0  : plain php-fpm. The kernel-uprobe (percall) container
#                         attaches from outside (pid:host).
#   AGENT_MODE=1        : run the percall loader under bpftime's syscall-server,
#                         then php-fpm under the bpftime agent (userspace uprobe).
set -e

export USE_ZEND_DTRACE="${USE_ZEND_DTRACE:-1}"
export BPFTIME_VM_NAME="${BPFTIME_VM_NAME:-ubpf}"

echo "dtrace-entry: USE_ZEND_DTRACE=$USE_ZEND_DTRACE AGENT_MODE=${AGENT_MODE:-0} PROBE_FUNC=${PROBE_FUNC:-execute_ex}"
php -i | grep -i 'dtrace' || true

if [ "${AGENT_MODE:-0}" = "1" ]; then
  BPFTIME_DIR="${BPFTIME_DIR:-/opt/bpftime}"
  echo "dtrace-entry: starting percall loader under bpftime syscall-server"
  LD_PRELOAD="$BPFTIME_DIR/libbpftime-syscall-server.so" \
    PHPFPM_BIN="${PHPFPM_BIN:-/usr/local/sbin/php-fpm}" \
    /opt/percall/percall_load &
  sleep 3
  echo "dtrace-entry: starting php-fpm under bpftime agent"
  exec env LD_PRELOAD="$BPFTIME_DIR/libbpftime-agent.so" php-fpm --nodaemonize
else
  echo "dtrace-entry: starting plain php-fpm (external kernel uprobe expected)"
  exec php-fpm --nodaemonize
fi
