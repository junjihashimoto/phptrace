# uprobe per-call レイテンシ実測

kernel uprobe / bpftime(ubpf インタプリタ)/ bpftime(LLVM JIT)の
**発火あたりのオーバーヘッド**を同一マシンで実測したもの。
ユーザー空間 eBPF の arm64 数値は公表が乏しいので自前で測った。

## 環境

- Apple Silicon 上の **Docker Desktop linuxkit カーネル 6.10 / arm64**(VM内)
- 20,000,000 回ループ、median of 3、`bench_target()`(noinline)を計測
- bpftime は master をソースビルド(LLVM JIT は LLVM≥15 必須 → Debian trixie / LLVM 19)
- **注意**: 絶対値は環境依存(VM・Apple Silicon)。x86 実機では論文値寄りになるはず。
  移植性があるのは *比* の方(kernel:bpftime ≈ 9倍 等)。

## ① 機構コスト(最小プローブ `return 0`)

| 方式 | per-fire | baseline差 | kernel比 |
|---|---|---|---|
| baseline(プローブ無) | 0.77 ns | — | — |
| kernel uprobe | ~785 ns | +784 | 1x |
| bpftime (ubpf) | ~85 ns | +84 | **約9倍速** |
| bpftime (LLVM JIT) | ~82 ns | +81 | 約9.5倍速 |

→ トレース用の小さいプローブでは **ubpf ≒ JIT**。トランポリン機構コストが
支配的で VM 実行差は誤差。効きどころは **kernel uprobe に対する ~9倍**。

## ①-b 発火コストの分解 — 「per-fire は安いのに負荷テストで負ける」の正体(arm64, 2026-08-20)

`return 0` の空プローブは **トランポリンだけ**を測る。実トレーサは map ルックアップと
`bpf_probe_read_user`(フレーム辿り)を含む。プローブを段階的に重くして per-fire を分解:

| probe | 内容 | kernel uprobe | bpftime ubpf | bpftime llvm |
|---|---|---|---|---|
| `probe` | 空(`return 0`) | 744ns (+743) | 78ns (+77) | 77ns (+76) |
| `probe_map` | array ルックアップ×8 | 767ns (+766) | 119ns (+118) | 115ns (+114) |
| `probe_read` | `probe_read_user`×6 | 799ns (+798) | **1202ns (+1201)** | **1198ns (+1198)** |
| `probe_full` | 実トレーサ相当(arr+pid+hash+read×6) | 786ns (+785) | **1208ns (+1208)** | **1199ns (+1198)** |
| `probe_gated` | サンプル判定→read前に return(間引いた発火) | 736ns (+735) | **83ns (+83)** | **87ns (+86)** |
| `probe_heavy` | 純計算 768 ALU | ── | 513ns (+512) | 408ns (+407) |

> `probe_gated` は「pid/サンプルで絞り、記録しない発火では read を走らせない」設計の単価
> (別 run, baseline 0.78ns)。**間引いた発火は bpftime ~83ns vs kernel ~736ns = 約9倍 bpftime が安い**。
> read の重さ(~1160ns)は「記録する 1/N の発火」だけが払う。→ **bpftime の本当のスイートスポットは
> "高頻度・大半を安くゲート・少数だけ read"(=サンプリング)**。ただし §5 で見た通り、実 php-fpm 負荷
> (/cpu, 16並行)ではこの 83ns 入口優位が消え、soft-sampling でも RPS は回復しなかった(実効 per-fire
> が微ベンチの ~10倍 = frida/共有map競合/キャッシュ)。**微ベンチの per-fire を本番容量に外挿すると外す**。

per-op 単価(delta を回数で割る):

| ヘルパー | kernel | bpftime | 比 |
|---|---|---|---|
| map ルックアップ | ~3ns | ~5ns | ほぼ互角 |
| **`bpf_probe_read_user`** | **~9ns**(copy_from_user) | **~187ns** | **約20倍** |

**読み取れること**:
1. **逆転の犯人は `bpf_probe_read_user` 一択**。map は両方安く差がつかない。bpftime の
   read 1回は kernel の約20倍高く(in-process なのに高い=フォルトガード付き読み実装)、
   6回で 1.1µs 食ってトランポリンで浮いた ~700ns を飲み込む。
2. **`probe_full`(実トレーサ)は負荷テストの逆転を per-fire で再現**: bpftime 1199-1208ns
   vs kernel 786ns ≈ **1.5倍遅い** → 負荷テスト `/cpu` の `kernel 45 rps > bpftime 36/39 rps`
   と符合。`probe_full ≈ probe_read`(read が支配、map/pid はほぼ無視できる)。
3. **JIT が効くのは純計算だけ**(`probe_heavy` 408 vs 513 = 1.26倍)。read 支配のプローブでは
   ubpf≒llvm(read はネイティブ helper 呼び出しで VM 非依存)→ **トレース用途で JIT の有無は
   ほぼ効かない**を再確認。
4. 含意: **「親ポインタだけ記録して後で復元」= read を 6→1 回に削る**設計は、bpftime では
   read 単価が高いぶん特に効く(per-fire ~1200ns → ~300ns 目安)。
   `probe_heavy` の kernel 値が `──` なのは、完全アンロールした 768-op ループを kernel 版
   loader が設置できなかったため(ubpf/llvm の比較が目的なので影響なし)。

### なぜ bpftime の read が ~20倍高いのか — 機構を確定(ソース + strace, 2026-08-21)

`bpf_probe_read_user` → `bpftime_probe_read`(runtime/src/bpf_helper.cpp)。実装は
コンパイル時フラグ **`ENABLE_PROBE_READ_CHECK`(cmake デフォルト ON)** で2択:
- **ON(既定・我々のビルド)**: `syscall(SYS_process_vm_readv, ...)` = **read ごとに1 syscall**。
  不正アドレスは -EFAULT で返り**ホストを即死させない**(フォルトセーフ)。
- **OFF**: 生 `memcpy`(~3ns, in-process)。ただし不正ポインタでホストプロセスが segfault。

strace で実証(probe_read、agent 注入下): `process_vm_readv` が **全 syscall 時間の 99.77%**、
302,329 回 ÷ 6 ≈ bench_target 1回あたり **ちょうど 6 回**(= read 1回 = syscall 1回)。

機構の要点(= LT のオチ):
- **kernel uprobe**: int3 トラップで**一度**カーネルに入場(~740ns、高い)→ 以降 `copy_from_user`
  は**カーネル内なので ~9ns**。入場料を read 全部で償却。
- **bpftime**: インラインフックで安く入場(~77ns、トラップ無し・ユーザ空間のまま)→ しかし
  `bpf_probe_read_user` は **process_vm_readv syscall で毎回カーネルへ入り直す**(~187ns、
  モード遷移=レジスタ退避+KPTI+Spectre緩和)。6段辿りなら kernel は 1入場+6激安コピー、
  bpftime は 6 syscall。→ 「入口9倍速」が「合計1.5倍遅」に反転。
- コンテキストスイッチ(プロセス切替)は無い。効くのは **user↔kernel モード遷移(syscall)**で
  あって、キャッシュ云々ではない。
- これは**安全 vs 速度のビルドスイッチ**: `ENABLE_PROBE_READ_CHECK=OFF` なら read は memcpy で
  bpftime が read 重プローブでも勝つが、不正フレームポインタで本番 php-fpm が落ちる
  = 「ランタイム注入=本番リスク」に直結。

### 「セグフォ無しで安全に読む」3択 — どれも無料ではない(≒技術的限界)

注入先(in-process)から**不正かもしれないユーザ空間ポインタ**を読む方法は3つ。どれも一長一短:

| 方法 | ハッピーパス単価 | 安全性 | 難点 |
|---|---|---|---|
| ① `process_vm_readv` syscall(bpftime 既定) | ~187ns(**read毎に syscall**) | ◎ 不正でも -EFAULT | 速度が出ない |
| ② 生 `memcpy`(`READ_CHECK=OFF`) | ~数ns | ✕ 不正ポインタで**ホスト即死** | 本番で使えない |
| ③ SIGSEGV ハンドラ + `sigsetjmp(savesigs=0)` + memcpy | ~数ns(**syscall無し**) | ○ フォルト時のみ longjmp で回復 | 注入先での**地雷**(後述) |

- kernel の `copy_from_user` が速くて安全なのは、**CPU の例外テーブル**でフォルトを無配送回復
  できるから(既に kernel モードにいる特権)。**ユーザ空間は自分の命令を例外テーブルに登録できない**
  → ①syscall で肩代わりさせるか、③シグナルで例外テーブルを自作するか、の二択になる。
- ③は原理的には「syscall 無しで安全」を達成できる(copy_from_user のユーザ空間版)が、**注入先で
  SIGSEGV を握るのは地雷**: jmp_buf はスレッドローカル必須、host 自身の SIGSEGV/JIT/ASAN/
  userfaultfd ハンドラと共存(チェーン)が必要、async-signal-safety 制約。bpftime が①を既定に
  するのはこの堅牢性のため。
- **結論(LT のオチ候補)**: 「bpftime が遅い」の正体は、**in-process ユーザ空間トレースが
  "カーネルのタダで堅牢なフォルト回復(例外テーブル)" を失うこと**。スマートな回避策(③)は
  存在するが「注入先で安全に握るのが難しい」= ほぼ本質的なトレードオフ。read 回数を減らす
  (親ポインタのみ記録)方が現実的な逃げ道。
- **実測で確定(`READ_CHECK=OFF` 再ビルド = memcpy 経路, arm64, 2026-08-21)**:

  | probe | kernel | bpftime ON(syscall) | bpftime OFF(memcpy) |
  |---|---|---|---|
  | 空 | 784ns | 78ns | 78ns |
  | +read×6 | 823ns | **1202ns**(1.5倍遅) | **90ns**(9倍速) |
  | 実トレーサ相当 | 851ns | **1208ns**(1.5倍遅) | **108ns**(8倍速) |

  read 単価は **~187ns(syscall)→ ~2ns(memcpy)= 約90分の1**。OFF では bpftime が probe_full で
  kernel に **~8倍勝つ**(1.5倍負け → 8倍勝ちに反転)。**逆転は 100% `process_vm_readv` syscall が原因**
  で、VM・トランポリン・map は無関係と確定。= 上の「速いか安全か」トレードオフが唯一の分岐点。

## ② VM 実行コスト(計算重プローブ = xorshift 256ラウンド ≒ 768 ALU命令)

| 方式 | 合計 | VM実行分(−85ns) | op単価 |
|---|---|---|---|
| bpftime (ubpf) | 516 ns | ~431 ns | ~0.56 ns/op |
| bpftime (LLVM JIT) | 411 ns | ~326 ns | ~0.42 ns/op |

→ 重い処理でようやく JIT が **~1.3倍**速い。「インタプリタは桁違いに遅い」
という通説よりずっと小さい(ubpf は速い computed-goto インタプリタ)。
JIT の真価は計算重 eBPF(パケット処理等)でのみ現れる。

## ③ 機能差(実測で発見)

**ubpf インタプリタは BPF atomic 命令(opcode 0xdb)を未サポート**。
`__sync_fetch_and_add` を含むプローブは
`Failed to load insn: unknown opcode 0xdb` でロード失敗し、フックが設置されない。
LLVM JIT は対応。→ ubpf を使うなら map 更新は非 atomic にする必要がある。

## クロスアーキ実測(発火単価 ns、median of 3)

| | arm64 / Apple Silicon・linuxkit VM (6.10) | x86_64 実機 pan (6.18) | 論文 x86 |
|---|---|---|---|
| baseline(プローブ無) | 0.77 | 1.63 | — |
| **kernel uprobe** | **~785** | **~1345** | 3224 |
| bpftime ubpf(最小プローブ) | ~85 | ~236 | — |
| bpftime llvm(最小プローブ) | ~82 | ~236 | 314 |
| bpftime ubpf(重プローブ 768 ALU) | ~519 | ~694 | — |
| bpftime llvm(重プローブ 768 ALU) | ~417 | ~747 | — |

**kernel : bpftime 比**(最小プローブ):arm64 ≈ **9.6x**、x86 ≈ **5.7x**、論文 ≈ 10.3x。

**重プローブ JIT vs ubpf(median of 5, 再現確認)**: arm64 は **JIT が 1.24倍速い**(417<519)、
**x86 は ubpf の方が速い**(694<747)= **JIT が負ける**。JIT 優位はアーキ依存で小さく、
x86 の ALU 主体プローブでは逆転する。「JIT は常に速い」は成り立たない。

### 読み取れること

1. **絶対値は環境で大きく動く**(kernel uprobe 785 / 1345 / 3224 ns で ~4倍)。
   「uprobe は 1発 N ns」と単一値で語るのは誤解のもと。効くのは *比*。
2. **kernel → bpftime で 5〜10倍**速くなる(環境依存だが常に大きい)。x86 pan は
   kernel uprobe 自体が比較的安い(1345ns)ため比は 5.7倍と小さめ。
3. **最小プローブでは ubpf ≒ JIT**(arm64 も x86 も、機構コストが支配的で VM 実行差は誤差)。
4. **重プローブでも両者は ~10〜25% 内**。arm64 は JIT が僅かに速い(411 vs 516)、
   x86 は逆転して見えるが差は誤差レベル(順序は run 間で安定しない)。
   → **トレース用途で JIT の有無はほぼ効かない**。JIT の真価はもっと重い eBPF
   (パケット処理等)でのみ。
5. bpftime ユーザ空間 uprobe は **root 不要**で動く(frida インライン書き換え)。
   一方 kernel uprobe の測定は root(perf/uprobe)が要る。
6. ubpf インタプリタは **atomic 命令(opcode 0xdb)未サポート**(実測で発見)。

> x86(pan)の測定環境: NixOS 26.05 / kernel 6.18。docker 無しのため bpftime は
> `nix develop`(LLVM 19)でソースビルド。NixOS 固有の躓き: cmake が `/bin/bash`
> をハードコード(NixOS に存在しない)→ `bash` に置換して解決。

## 再現

```sh
cd bench-uprobe
docker build -t phptrace-uprobe-bench:latest .              # JIT版(llvm VM)
docker build --build-arg JIT=OFF -t phptrace-uprobe-bench:ubpf .  # ubpf版
docker run --rm --privileged phptrace-uprobe-bench:latest   # kernel + llvm
docker run --rm --privileged phptrace-uprobe-bench:ubpf     # kernel + ubpf
# 計算重プローブは BPF_OBJ=/opt/uprobe/probe_heavy.bpf.o で load を起動
```

- JIT ON ビルドには **llvm VM のみ**、JIT OFF ビルドには **ubpf VM のみ**同梱される
  (`BPFTIME_VM_NAME` で選択、無い VM を指定するとフック未設置=+0ns になる)
