#!/usr/bin/env bash
# Spin up a single-node kind cluster, load the locally-built images, and
# deploy the phptrace agent (DaemonSet) + an unprivileged PHP demo workload.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=phptrace

echo "==> building images (php demo, tracer, ui)"
docker compose build php >/dev/null
docker build -t phptrace-tracer:latest ./tracer >/dev/null
docker build -t phptrace-ui:latest -f ui/Dockerfile . >/dev/null
# tag the compose-built php image under a stable name for k8s
docker tag phptrace-php:latest phptrace-php:latest 2>/dev/null || \
  docker build -t phptrace-php:latest ./app >/dev/null

echo "==> creating kind cluster '$CLUSTER'"
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || \
  kind create cluster --config k8s/kind-config.yaml

echo "==> loading images into the cluster"
kind load docker-image --name "$CLUSTER" \
  phptrace-tracer:latest phptrace-ui:latest phptrace-php:latest

# NOTE on kind + pid namespaces: kind nests pid namespaces (VM-init >
# kind-node > pod), so the kernel's global pids (what BPF reports) don't
# match the agent's /proc view. The agent runs with NS_PIDS=1 to translate
# via bpf_get_ns_current_pid_tgid, and the demo pods set hostPID so they
# share the node ns. On a REAL k8s node the node ns IS the init ns, so
# neither is needed — an ordinary app pod is traced with no changes.

echo "==> applying manifests"
kubectl apply -f k8s/00-namespace.yaml
kubectl apply -f k8s/10-demo.yaml
kubectl apply -f k8s/20-agent.yaml

echo "==> waiting for rollout"
kubectl -n phptrace rollout status deploy/mysql --timeout=180s
kubectl -n phptrace rollout status deploy/php-demo --timeout=120s
kubectl -n phptrace rollout status ds/phptrace-agent --timeout=180s

cat <<EOF

Ready.  UI:  http://localhost:8092/
        (the DaemonSet is now sampling the unprivileged php-demo pods)

  kubectl -n phptrace get pods
  kubectl -n phptrace logs ds/phptrace-agent -c tracer
  open http://localhost:8092/flame

Tear down:  kind delete cluster --name $CLUSTER
EOF
