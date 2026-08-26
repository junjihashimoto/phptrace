# phptrace on Kubernetes

eBPF PHP APM をクラスタに載せる、プロファイラの定番形 **DaemonSet**。
1ノード1エージェントが、そのノードで動く php-fpm を `hostPID` 経由で自動発見して
サンプリング・トレースする(Parca / Pyroscope eBPF / Datadog agent と同じ形)。

```
┌─ DaemonSet phptrace-agent (1 pod/node) ────────────────┐
│  tracer(privileged): 99Hz perf_event + uprobe          │
│    → /data/*.ndjson                     ┐ emptyDir 共有 │
│  ui(lean-tea): ndjson → SQLite → Web UI ┘ :8080         │
└────────────────────────────────────────────────────────┘
        ▲ hostPID で全podのプロセスを観測
┌───────┴──────────── traced (unprivileged) ─────────────┐
│  php-demo (nginx + php-fpm 8.3) + mysql + loadgen       │
└────────────────────────────────────────────────────────┘
```

## 動かす (kind, 単一ノード)

```sh
./k8s/deploy.sh          # kind作成 → イメージload → apply → rollout待ち
open http://localhost:8092/       # UI (Overview / Flamegraph / Queries)

kubectl -n phptrace get pods
kubectl -n phptrace logs ds/phptrace-agent -c tracer   # php-fpm発見ログ
kind delete cluster --name phptrace                    # 撤去
```

## 設計ポイント

- **DaemonSet + privileged + hostPID** — compose の `privileged` / `pid:host` が
  そのまま pod spec に対応。BPF は BTF/CO-RE 非依存(手動オフセット +
  `bpf_probe_read_user`)なので、BTF の無い古いカーネルのノードでも動く
- **コンテナ跨ぎのシンボル解決** — `/proc/<pid>/root` と `process_vm_readv` で
  各 pod のバイナリ/メモリに届く。hostPID + privileged が前提
- **被トレースアプリは無改変** — 実ノードでは php-demo 側に sidecar も権限も不要。
  エージェントが勝手に見つけてトレースする

## kind 固有の注意: PID 名前空間の入れ子

kind は PID 名前空間を入れ子にする(VM-init > kind-node > pod)。カーネル/BPF が
報告するグローバル PID と、エージェント(kind-node ns)の `/proc` が見る PID が
ずれる。本デモではこれを2つで吸収している:

- エージェント: `NS_PIDS=1` → `bpf_get_ns_current_pid_tgid` で自分の名前空間の
  PID に変換(`tracer/phptrace.bpf.c` の `cur_pid`)
- php-demo: `hostPID: true` でノード ns を共有

**実 k8s ノードでは両方とも不要**。ノードの PID 名前空間が init 名前空間そのものなので、
グローバル PID がそのまま一致し、通常の(hostPID なし・非特権の)アプリ pod を
無改変でトレースできる。`NS_PIDS` を外せばそのまま実ノード向け構成になる。

## 本番展開の残タスク(README ルート参照)

- 異種 PHP バージョンのオフセット選択(`gen_offsets` をバージョン毎に生成)
- 全社横断: 各ノード SQLite → Parquet エクスポート → 中央 DuckDB 集約
- PodSecurity: privileged namespace か SCC(OpenShift)
