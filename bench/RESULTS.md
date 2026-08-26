# 負荷ベンチの知見(RPS / レスポンスタイム)

`bench/run.sh` による負荷テスト(oha, 同時16, 15s, median)。生データは
`data/bench*.txt`(gitignore)。ここは LT 用の要点。

## 1. per-call オーバーヘッドは「ユーザランド呼び出し回数 × CPU余裕」で決まる

同じ per-call `execute_ex@dtrace`(全ユーザランド呼び出しで発火)でも、
エンドポイントの性質で桁違い:

| endpoint | 性質 | 呼出/req | baseline | per-call@dtrace(kernel) |
|---|---|---|---|---|
| /cpu | CPU律速・呼出密 | ~37,000 | 357 rps / P99 56ms | **45 rps / P99 530ms**(1/8) |
| /framework | DB/IO律速・呼出密(実FW) | ~1,270 | 53 rps / P99 392ms | 54 rps / P99 389ms(~0%) |
| /api | DB/IO律速・呼出疎(薄い) | ~28 | 53 rps / P99 399ms | 53 rps / P99 401ms(~0%) |
| /fast | noop | ~1.5 | 12880 rps | ~0% |

- per-call の重さ ≈ 呼出回数 × トラップ単価。`/framework` は呼出密でも
  **DB待ち中は worker がCPUを空ける=CPUに余裕**があるので耐える。
- `/cpu` は **100% CPU律速 + 呼出密**で余裕ゼロ → 飽和して RPS 1/8。
- **2024年の本番事故 = 呼出密(フレームワークのオートロード等)× ピークのCPU飽和**が
  揃った条件。まさに「一番負荷が高い=APMが欲しい時」に一番効いてしまう。

## 2. 対照実験(JIT交絡を切る)— /cpu

dtraceビルド上で比較(全条件 JIT off を共有し、変数をプローブだけに):

| 条件 | RPS | P99 |
|---|---|---|
| 1. baseline(stock, JIT on) | 357 | 56ms |
| 2. dtrace, uprobe無 | 353 | 58ms |
| 3. + kernel uprobe(per-call) | 45 | 530ms |
| 4a. + bpftime ubpf(per-call) | 36 | 669ms |
| 4b. + bpftime LLVM JIT(per-call) | 39 | 628ms |
| 5. + サンプリング(99Hz) | 352 | 57ms |
| 6. + bpftime soft-sampling 1/10 | 37 | 685ms |

- **1→2 ≈ 差なし**: dtraceビルド(JIT無効化+dtrace_execute_ex経路)自体はタダ。
  事故の原因は「ビルド」でも「JIT off」でもなく **uprobeが毎呼び出し発火すること**だけ。
- **5 サンプリングは平坦**(357→352)。呼出密でもCPU律速でも一定。
- **6 soft-sampling は回復しない**(36→37): per-request サンプリングは記録量/work は
  減らせても、**発火(トラップ)単価は消せない**。/cpu はトラップ支配なので無効。

## 3. kernel vs bpftime(ubpf/JIT)— プローブの重さで逆転する

| | マイクロベンチ 最小プローブ(`return 0`) | 負荷テスト /cpu(実work・全発火) |
|---|---|---|
| kernel uprobe | ~785 ns(基準) | **45 rps** |
| bpftime ubpf | ~85 ns(**9倍速**) | 36 rps |
| bpftime LLVM JIT | ~82 ns | 39 rps |

- **軽いプローブ**(トレース境界1点)→ bpftime 圧勝(トランポリン機構コスト支配、
  kernel の 9倍速)。
- **重いプローブ**(全関数スタックwalk等)→ VM実行コストが支配 → **カーネルの方が速い
  ことすらある**(カーネルは eBPF を**カーネル内JIT**、bpftime-ubpf はインタプリタ)。
  bpftime-JIT は ubpf より ~7% マシだが kernel には届かず。
- 教訓: 「bpftime は常に10倍速い」ではない。**軽いプローブでのみ機構優位が出る**。

## 4. bpftime のランタイム注入は環境依存でハングしうる(arm64 で実測、x86 では再現せず)

bpftime agent を php-fpm に注入(AGENT_MODE=1)した状態で **arm64(Apple Silicon /
Docker Desktop linuxkit)** では:

| endpoint | 結果(arm64 / Docker) |
|---|---|
| /fast, /cpu | 200(動く) |
| **/framework, /api(PDO/MySQL)** | **000 / 10s タイムアウト(ハング)** |

ユーザ空間注入 + mysqlnd のソケットI/O が干渉してハング。docs.md で懸念した
「ランタイム注入 = 本番リスク」が**ある環境で実際に起きた**という実測。

### x86_64 実機で切り分け完了(2026-08-19, pan / NixOS 6.18)= **どの構成でも再現せず**

nix のみ(system 変更なし)で arm64 に寄せて再現。PHP 8.4.24(pdo_mysql+mysqlnd)
+ MariaDB 11.4.12 + bpftime(commit 2a45936)を LD_PRELOAD 注入、**全条件で
`execute_ex` フック設置を確認**(agent ログ `matched=true`/`Attach successfully`、
php-fpm はワーカーが fork 継承 = 稼働ワーカーの `/proc/PID/maps` に agent.so と
frida トランポリンを確認):

| 構成 | VM | 結果 |
|---|---|---|
| CLI, PDO SELECT ×5 | llvm | 全完走(EXIT=0 / 0.1s) |
| CLI, prepared 50 クエリ | llvm | 完走(`queries=50 totalrows=150`) |
| **php-fpm, 300 req @ 並行32(8 workers)** | llvm | **300/300 OK・ハング0 / 0.7s** |
| CLI, PDO(JIT=OFF ubpf 専用ビルド) | ubpf | 完走(EXIT=0 / 0.06s) |
| **php-fpm, 300 req @ 並行32** | ubpf | **300/300 OK・ハング0 / 0.7s** |

`timeout 20` ラッパ下で 124(タイムアウト)は一度も出ず。

→ **ハングは arm64/Docker 固有**。php-fpm でも並行負荷でも VM(llvm/ubpf)でもなく、
**アーキ or Docker linuxkit VM が要因**(そこまでの切り分けは未了だが、
少なくとも fpm/負荷/VM は要因から除外できた)。**確実なのは「arm64 の一環境で
実際にハングした」事実と「x86 実機ではどの構成でも再現しない」事実**。
本番の主流は x86_64 なので、このハングは主に **arm64 開発機(Mac)固有の注意点**。

補足: ubpf は「フック未設置=無音の +0ns」ではなく、server 側 console ログを
効かせると JIT=ON ビルドでも本物の ubpf フックが設置される(初回の +0ns 観測は
logger-reset のアーティファクトだった)。JIT=OFF 専用ビルドでも同じく設置・完走を確認。

## 5. READ_CHECK=OFF は「速い」どころか実負荷で php-fpm をクラッシュさせる(2026-08-21)

マイクロベンチ(bench-uprobe §①-b)で「`ENABLE_PROBE_READ_CHECK=OFF`(生 memcpy)なら
bpftime が read 重プローブでも 8倍速」と出た。**では実負荷で本当に速くなるのか**を検証
(/cpu, oha 並行16, per-call `execute_ex`, arm64):

| /cpu 条件 | RPS | P99 | 備考 |
|---|---|---|---|
| baseline(プローブ無) | 360.7 | 55.8ms | 実処理あり |
| kernel uprobe(§2 より引用) | 45 | 530ms | — |
| bpftime **ON**(process_vm_readv, 安全) | 38.6 | 668.8ms | 動く・遅い(既知 ~36-39/669 と一致) |
| bpftime **OFF**(生 memcpy, 速い) | **✕** | **✕** | **worker が SIGSEGV → 全 502・サービス停止** |

- 発火確認(正当性ゲート): ON は percall カウンタが 15s で ~2.7M 増(真に per-call 発火)。
  OFF はカウンタが ~39,145 で凍結、php-fpm ログに `child … exited on signal 11 (SIGSEGV)`
  が連発、`/cpu` も `/fast` も **502**(oha の success はHTTP応答があれば1と数えるが codes は
  `{"502": 17922}`)= 実リクエストは0件。
- **なぜ**: マイクロベンチの OFF は**意図的に有効なポインタ鎖**を読んでいたので memcpy が
  フォルトしなかっただけ。実 Zend フレームには**不正/陳腐化したポインタ**が混じり、ガード無し
  memcpy がそこを踏んで worker を即死させる。
- ビルド正当性: OFF イメージは cmake ログで `-DENABLE_PROBE_READ_CHECK=OFF` + `bpf_helper.cpp`
  再コンパイルを確認(キャッシュ再利用でない)。

→ **`process_vm_readv` syscall は「切れる無駄」ではなく、ホストを生かしている当のもの**。
bpftime の read コストは実装の粗ではなく**安全↔速度の下限**。§4(注入ハング)と合わせ、
「ランタイム注入 = 本番リスク」を**ライブクラッシュで実証**した形。
(P99 の共有 map 競合の残差は、OFF が実トラフィックを一切さばけなかったため単離できず。
ON の 668ms は per-fire の syscall コストで完全に説明がつく。)

> 注意: この実験で `phptrace-php-bench:latest` / `phptrace-php-dtrace:latest` は OFF ビルドに
> なっている。既定(ON)に戻すには `docker compose --profile bench build php-bench php-dtrace`。

## 6. 方式B(per-request dynamic attach)を実装して測った — RPS は救える、P99 は救えない(2026-08-21)

方式A(soft-sampling: フックは付けたまま毎回発火、非サンプルは work だけ skip)は /cpu で回復
しなかった(37 rps)= **fire を毎回払う**から。**方式B = 非サンプル request ではフックごと外す**を
**忠実に実装**した: dtrace ビルド(`dtrace_execute_ex` が per-call)に **frida-gadget** を注入、
`php_request_startup` で 1/N の時だけ `Interceptor.attach(dtrace_execute_ex)`、`php_request_shutdown`
で `detach`。非サンプル request は execute フックが**物理的に不在**=native 速度。

| 条件 | N | RPS | P99 | p50 | fires/req | attach/s |
|---|---|---|---|---|---|---|
| baseline(gadget無) | – | 346.5 | 128.8ms | 39.0 | 0 | 0 |
| never-attach(境界hookのみ) | ∞ | 341.8 | 120.3ms | 40.2 | 0 | 0 |
| N=1(毎回=full per-call) | 1 | 88.1 | 546.0ms | 152.4 | 73,258 | 88.1 |
| N=10 | 10 | 261.5 | 165.3ms | 52.2 | 7,088 | 26.2 |
| N=100 | 100 | 330.0 | 137.4ms | 40.5 | 688 | 3.2 |
| N=1000 | 1000 | 338.6 | 106.4ms | 44.4 | 55 | 0.3 |

- **RPS は N とともに単調回復**(88→262→330→339 = N=1000 で baseline の 98%)。非サンプル request が
  フック不在で native 速度だから。**動かぬ証拠 = `fires/req ≈ 73k/N`**(73258/7088/688/55)。方式A(37)
  との決定的な差。
- **P99 は救えない(サンプル率 >1% の間)**: N=10(10%)で P99=165ms がサンプル request の中央値に
  張り付く。N=100(1%)で 137ms と落ち始め、N=1000(0.1%)で 106ms=baseline 並み。理屈: サンプルは
  request 単位の Bernoulli フィルタで、1/N の request が full 課税 → P99(上位1%)がそれを見なくなるのは
  1/N < 1% になってから。→ **throughput は守れるが tail SLO を守るには <1% サンプル必須**。
- **付け外しのパッチコストは無視可**(never-attach 341.8 vs baseline 346.5 = ~1.4%)。効くのは attach
  中の per-call fire だけ = N で制御できる。

**実装上の正直な限界(=まだ研究段階)**:
- 基盤は **`php -S`(fork-free)** で php-fpm ではない。**frida-gadget は php-fpm の fork-without-exec を
  生き延びられず**、継承フックの初回発火で worker が SIGSEGV。RPS baseline は fpm とほぼ一致(346 vs
  ~350)なので RPS の話は代表性あり、ただし絶対 P99 は php -S が高め(129ms vs fpm 56ms)。全条件で
  共有基盤なので**相対の張り付き/回復は有効**。
- N=1 full=88 rps は kernel(45)/bpftime(36)より速い。frida は読みを**プロセス内のガード付き読み**で
  行い `process_vm_readv` syscall を打たないため(= §4/§5 で議論した「③ SIGSEGV ハンドラ方式」を frida
  が実装している格好)。
- **fork の壁**: frida-gadget は fork で死に、bpftime は fork 生存するが per-request toggle API が無い。
  **どちらも fpm 上の方式B をそのままは実現しない**。fork 生存する注入器 + 実行時 attach/detach が要る。
- 再現: `bench/Dockerfile.fridaB` + `bench/fridaB/`(agent.js / entry-cli.sh / nginx-fridaB-cli.conf)。
  `frida-gadget.so`(28MB, linux-arm64)は gitignore(frida releases から取得)。

## まとめ

- **サンプリングは常に平坦(~0%)・安全(対象無傷)**。アプリの形も負荷も問わない。
- per-call は **予測不能**(0%〜1000%)で、しかも一番効いてほしい高負荷時に一番重い。
- ランタイム注入(bpftime)は **環境依存の不確実性**を持つ — arm64/Docker で
  実際にハングした(x86 実機では全構成で再現せず)。「必ず壊れる」ではないが、
  **プロセス外サンプリングにはこの class の問題が原理的に無い**のが本番での安心材料。
- 全関数の per-request トレースが欲しいなら、**DB/IO律速のエンドポイントに限って**
  per-call を選択的に併用するのが現実的(CPU律速だけ避ける)。
