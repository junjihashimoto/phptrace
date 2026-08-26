#!/bin/sh
# Entrypoint for the php-bench container (condition 4).
#
# bpftime's model: run the LOADER under the syscall-server first (it registers
# the eBPF program + uprobe target in shared memory), then start the TARGET
# under the agent (which installs the userspace hook). Both processes live in
# this one container and share /dev/shm, so no cross-container wiring needed.
set -e

BPFTIME_DIR="${BPFTIME_DIR:-/opt/bpftime}"
SYSCALL_SO="$BPFTIME_DIR/libbpftime-syscall-server.so"
AGENT_SO="$BPFTIME_DIR/libbpftime-agent.so"
# Built with the ubpf interpreter; the agent defaults to the absent llvm VM.
export BPFTIME_VM_NAME="${BPFTIME_VM_NAME:-ubpf}"

echo "bpftime-entry: syscall-server=$SYSCALL_SO agent=$AGENT_SO"
ls -l "$BPFTIME_DIR" || true

# 1. Loader under the syscall-server. PHPFPM_BIN makes it resolve _emalloc on
#    the real binary path without needing a running php-fpm yet.
echo "bpftime-entry: starting percall loader under syscall-server"
LD_PRELOAD="$SYSCALL_SO" PHPFPM_BIN="${PHPFPM_BIN:-/usr/local/sbin/php-fpm}" \
  /opt/percall/percall_load &
LOADER_PID=$!

# Give the loader time to create the shm maps + register the attachment.
sleep 3
if ! kill -0 "$LOADER_PID" 2>/dev/null; then
  echo "bpftime-entry: loader exited early — bpftime load failed" >&2
  exit 1
fi

# 2. php-fpm under the agent (foreground; keeps the container alive).
echo "bpftime-entry: starting php-fpm under bpftime agent"
exec env LD_PRELOAD="$AGENT_SO" php-fpm --nodaemonize
