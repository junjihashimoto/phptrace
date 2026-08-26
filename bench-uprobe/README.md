# bench-uprobe — uprobe 発火単価のマイクロベンチ

kernel uprobe / bpftime(ubpf インタプリタ)/ bpftime(LLVM JIT)の
**1発火あたりのオーバーヘッド**を同一マシンで実測する。ユーザー空間 eBPF の
arm64 実測値は世に乏しいので自前で測るためのもの。結果は `RESULTS.md`。

## 構成

- `target.c` — `bench_target()`(noinline)をタイトループで呼び、ns/call を出力
- `probe.bpf.c` — 最小 uprobe(`return 0`)。機構コストを測る(atomic は使わない
  — ubpf が opcode 0xdb を弾くため)
- `probe_heavy.bpf.c` — xorshift 256ラウンド。VM 実行コスト(ubpf vs JIT)を測る
- `load.c` — libbpf で `bench_target` に uprobe を attach。bare 実行で kernel
  uprobe、`LD_PRELOAD=libbpftime-syscall-server.so` で bpftime に登録
- `run.sh` — baseline / kernel / bpftime(ubpf)/ bpftime(llvm)を計測して表示
- `Dockerfile` — bpftime をソースビルド(`--build-arg JIT=ON|OFF`)+ 上記一式

## 使い方

```sh
docker build -t phptrace-uprobe-bench:latest .                    # JIT(llvm VM)
docker build --build-arg JIT=OFF -t phptrace-uprobe-bench:ubpf .  # ubpf VM
docker run --rm --privileged phptrace-uprobe-bench:latest   # baseline+kernel+llvm
docker run --rm --privileged phptrace-uprobe-bench:ubpf     # baseline+kernel+ubpf
```

`ITERS` 環境変数でループ回数を調整。privileged が必須(perf_event / BPF)。

## 注意

- JIT ON ビルドには llvm VM のみ、JIT OFF には ubpf VM のみ同梱される。
  `BPFTIME_VM_NAME` で選び、同梱されていない VM を指定するとフックが設置されず
  overhead が +0ns になる(= 測定ミスのサイン)。
- 絶対値は環境依存(ここは Apple Silicon の linuxkit VM)。比の方が移植性が高い。
