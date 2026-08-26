# phptrace — eBPF PHP プロファイラ + per-call/per-request トレースの実測調査

常時サンプリング型の eBPF PHP プロファイラを自作し、そのうえで **「真の APM
(=1リクエストの全関数トレース)を本番で成立させるコスト」** を
kernel uprobe / ユーザ空間eBPF(bpftime)/ per-request 動的サンプリング の
3方式で実測した記録。UI は [LeanTEA](https://github.com/Verilean/lean-tea)
(Lean 4)製の Web + TUI、ストレージは SQLite 1ファイル。

## TL;DR(結論)

- **サンプリング(99Hz・プロセス外)= 安全・常時・言語非依存**。「システムのどこが重いか」
  は見えるが、**1リクエストの全関数コールツリー(=APM の本丸)は撮れない**(点でしか見ない)。
- **その per-call トレースは高負荷で死ぬ**: 全関数 uprobe は 2024 本番で P99 を倍にした。
  重さ = **呼出密 × CPU余裕**(一番負荷が高い=一番 APM が欲しい時に一番重い)。
- **bpftime は空プローブなら kernel の 5〜9倍速**だが、実トレーサでは逆転する。犯人は
  `bpf_probe_read_user` = **`process_vm_readv` syscall(kernel の ~20倍)**。フラグを切る
  (`READ_CHECK=OFF` = 生 memcpy)と μbench は速いが、**実負荷では php-fpm を SIGSEGV**
  (安全↔速度の下限)。
- **per-request 動的サンプリング(方式B)**: リクエスト境界でフックを attach/detach し、
  非サンプル request は native 速度。**RPS は baseline へ回復・P99 は <1% サンプルで守れる**。
  eBPF は自分でフックを張れないため、実装は frida-gum(bpftime の下回り)を直接使う。

数値・再現の一次資料: [`bench/RESULTS.md`](bench/RESULTS.md)(実負荷 RPS/P99)、
[`bench-uprobe/RESULTS.md`](bench-uprobe/RESULTS.md)(発火単価の分解)。

---

## 構成(docker compose)

```
┌─ php (php-fpm 8.3 + demo app) ←─ nginx :8081 ←─ loadgen
├─ apache74 (mod_php 7.4) :8082 ←─ loadgen74     [profile: legacy]
├─ mysql
├─ tracer (privileged, pid:host)
│    perf_event 99Hz → executor_globals→current_execute_data を BPF 内 unwind
│    uprobe php_request_startup/shutdown → リクエストスパン (URI/method/duration)
│    uprobe mysqlnd conn_data::query → SQL スパン
│    → /data/{samples,requests,db_queries}.ndjson
├─ ui (lean-tea) :8080   ndjson → SQLite ingest + Web UI
└─ tui (apm_top)         perf top 風の監視TUI [profile: tui]
```

```sh
docker compose up -d --build          # 本体 (8.3 スタック + tracer + ui)
open http://localhost:8080            # UI: Overview / Flamegraph / Requests / Queries / Diff
# 負荷をかけて眺める(demo app は /cpu /db /api /framework /slow /mixed /fast)
for i in $(seq 200); do curl -s localhost:8081/cpu >/dev/null; done

docker compose --profile legacy up -d       # Apache+mod_php 7.4 スタックも追加
docker compose --profile tui run --rm tui    # top 風 TUI
```

ローカル(Mac)で UI だけ動かす:

```sh
cd ui && lake build
DB_PATH=../data/apm.sqlite DATA_DIR=../data PORT=8080 ./.lake/build/bin/apm_serve
```

---

# 第1章 — 作ったもの(常時サンプリング型プロファイラ)

kernel の perf_event で **99Hz サンプリング**。プロセスの外から PID を追い、CPU 上の
Zend スタックを読む = **対象は無傷・常時 on・オーバーヘッド ~0%**(357→352 rps)。
関数ポインタはカーネル内では解決せず、ユーザ空間で遅延シンボル化(キャッシュ)。

## UI(全ページ共通で Grafana 風の時間レンジピッカー)

プリセット(5m/15m/30m/1h/2h/6h)、`◀ ▶` シフト、`⤢` ズームアウト、`now` スナップ、
`from`/`to` 絶対指定(`now-30m` / エポック秒)、`⟳` 自動更新。Overview のタイムラインは
**マウスドラッグで範囲選択**。レンジは URL に乗るので deep-link・共有可能。

- **Overview** — エンドポイント別に **合計時間(件数×平均)ランキング** + %time・P50/P95/P99・
  リクエスト時系列・レイテンシヒストグラム(Datadog Resources 相当)
- **Flamegraph** — 時間レンジ × エンドポイント × 最小 duration で絞ってから畳む集約 flamegraph
  (クリックでズーム)。`call tree` タブで self/total% 付きツリーにも切替(ゼロ JS、native `<details>`)
- **Requests** — 直近一覧 → 単一リクエストの **waterfall**(スパン + on-CPU ティック +
  mysqlnd クエリ + **各クエリの呼び出し元 PHP スタック**)。呼び出し元は近傍サンプル推測ではなく
  **mysqlnd uprobe 発火時に BPF 内で Zend スタックを walk して確定**(DB 待ちは off-CPU)
- **Queries** — mysqlnd クエリを**リテラル正規化**して集約し合計時間でランキング(Top Queries 相当)
- **Diff** — 2つのサンプル集合 A/B を独立に絞り、**関数別シェア差分でデグレを自動 attribution**
  + 差分 flamegraph。「デプロイ前後」でも「速い vs 遅いリクエスト(differential profiling)」でも
  同じ UI。トレース×プロファイル×時間が**同一テーブル**なので 1 クエリで書ける

## TUI(apm_top)— perf top の改良版

同じ SQLite を読む `top` 風ライブ監視。関数 self-time top + op別レイテンシを毎秒リフレッシュ。

```sh
docker compose --profile tui run --rm tui                                   # PHP スタック
DB_PATH=data-native/apm.sqlite VIEW=both ./ui/.lake/build/bin/apm_top       # memcached 等
```
`f` FUNCTIONS / `o` OPS / `b` both / `q` 終了。env: `VIEW`・`WINDOW_SEC`(既定60)・`DB_PATH`。

## 設計メモ

- **オフセット自動生成**: `tracer/gen_offsets.c` を対象 PHP イメージ内でコンパイルして
  zend 構造体オフセットのヘッダを生成。PHP 版差分はここに集約(8.3 / 7.4 対応)
- **strip された static 関数に uprobe**: mysqlnd の query 実体はシンボルが無いが、
  エクスポートされたメソッドテーブル `mysqlnd_mysqlnd_conn_data_methods` を実行中プロセスの
  メモリから読み、関数ポインタ→ファイルオフセットに換算して attach
- **SQLite を時系列 DB 的に運用**: WAL + ts インデックス + 毎分ロールアップ +
  retention(`RETENTION_HOURS`、既定 2h)。フラットなイベント行なので ClickHouse へ差替可能
- **BPF は BTF/CO-RE 非依存**なので BTF の無いノードでも動く

## 一般性 — 言語非依存(profile: native)

PHP 固有なのは「Zend VM スタックの walk」だけ。そこを `bpf_get_stack`(フレームポインタ
unwind)+ ELF symtab に差し替えれば、**下流(ingest / flamegraph / call tree / total-time)を
一切変えず**に任意のネイティブアプリに適用できる。

```sh
docker compose --profile native up -d --build
open http://localhost:8091/flame     # memcached の flamegraph
```

- `native-tracer/` — `bpf_get_stack(BPF_F_USER_STACK)` + `/proc/pid/maps` + ELF symtab で
  シンボル解決。`TARGET_COMM` でターゲット指定(既定 memcached)。C++ は `__cxa_demangle`
- `memcached/` — `-fno-omit-frame-pointer` でソースビルド。`drive_machine → transmit →
  sendmsg` のような内部スタックが名前付きで出る
- **bounded モード**(常駐用に負荷・時間非依存で一定リソース): レート硬上限
  (`MAX_SAMPLES_PER_SEC`)+ stack→count 即時集約(実測 約18倍圧縮)+ SQLite サイズ上限
  (`MAX_DB_MB`)。境界 uprobe(`PROBE_FUNC`)で op別レイテンシも取れる

## Kubernetes(k8s/)

eBPF プロファイラの定番 **DaemonSet**。1ノード1エージェントが `hostPID` でそのノードの
php-fpm を自動発見してトレース(被トレースアプリは無改変・非特権)。`k8s/deploy.sh` で
kind に一発デプロイ実証済み。詳細と kind 固有の PID 名前空間対応は `k8s/README.md`。

---

# 第2章 — でもサンプリングは APM ではない

サンプリングは「傾向」は見えるが「**1リクエストの全関数コールツリー**」は撮れない
(発火の合間のフレームは解放済み)。真の APM = per-request トレースには、全関数に張る
**per-call** が要る。そしてその per-call が地雷だった(第3章)。

**execute_ex と per-call の前提**: PHP 8 の VM は `zend_execute_ex == execute_ex` の間は
ユーザランド呼び出しをインライン実行するため、`execute_ex` uprobe はリクエストあたり
約1回しか発火しない。per-call で発火させるには `--enable-dtrace` ビルド + `USE_ZEND_DTRACE=1`
起動が必要(`dtrace_execute_ex` に切替わり毎コール発火)。公式 docker は dtrace 無効なので、
bench は dtrace 有効の再ビルド(`bench/Dockerfile.dtrace`)で per-call を計測する。
2024 本番(ディストリ版 PHP = dtrace 有効)で per-call が観測できたのはこのため。

---

# 第3章 — per-call を安くできるか(実測)

3つの bench がそれぞれ別の角度を測る。**各ディレクトリの `RESULTS.md` が一次資料**。

## bench-uprobe/ — 発火単価の分解(kernel vs bpftime、per-fire)

「1発火あたり何ns か」を同一マシンで実測。空プローブから段階的に重くして、
**どの処理が効くか**を分解する(タイトなCループの target に uprobe を張って delta を測定)。

```sh
cd bench-uprobe
docker build -t phptrace-uprobe-bench:decomp .                    # JIT=ON(llvm+ubpf両方)
docker run --rm --privileged phptrace-uprobe-bench:decomp         # 分解マトリクスを出力
# プローブを絞る / ubpf 専用 / read syscall を切る:
docker run --rm --privileged -e PROBES="probe probe_read probe_full" phptrace-uprobe-bench:decomp
docker build --build-arg PROBE_READ_CHECK=OFF -t phptrace-uprobe-bench:nocheck .   # 生 memcpy 版
```

プローブ変種(`probe*.bpf.c`): `probe`(空=trampoline のみ)/ `probe_map`(map×8)/
`probe_read`(`bpf_probe_read_user`×6=フレーム辿り)/ `probe_full`(実トレーサ相当)/
`probe_gated`(サンプル判定して早期 return)/ `probe_heavy`(768 ALU=VM実行)。

**結果(arm64, per-fire)**:

| プローブ | kernel | bpftime |
|---|---|---|
| 空 | 744ns | **78ns**(9倍速) |
| +read×6 | 799ns | **1202ns**(1.5倍遅=逆転) |

→ **逆転の犯人は `bpf_probe_read_user` 一択**。bpftime の実体は `process_vm_readv` **syscall**
(~187ns)で kernel の `copy_from_user`(~9ns)の**約20倍**。kernel は int3 で一度カーネル入場
すれば read は激安、bpftime は read 毎に syscall で入り直す。詳細・クロスアーキ表・strace 実証は
[`bench-uprobe/RESULTS.md`](bench-uprobe/RESULTS.md)。

## bench/ — 実負荷での RPS/P99 比較

per-call uprobe(`execute_ex@dtrace`)が実アプリのスループット/レイテンシに与える影響を、
oha 負荷で baseline / kernel uprobe / bpftime / サンプリング と比較する。

```sh
docker compose --profile bench up -d --build     # dtrace / bpftime 用のスタックを起動
bash bench/run.sh                                # 全条件を計測し JSON を data/ に出力
# 主要 env:
ENDPOINTS="/cpu /framework" bash bench/run.sh    # 対象エンドポイント
READ_CHECK=OFF bash bench/run.sh                 # bpftime を生 memcpy でビルドして計測
```

**結果(/cpu, 並行16)**:

| 条件 | RPS | P99 |
|---|---|---|
| baseline | 357 | 56ms |
| per-call kernel uprobe | 45 | 530ms |
| per-call bpftime(READ_CHECK=ON) | 36 | 669ms |
| per-call bpftime(READ_CHECK=OFF) | **✕ SIGSEGV → 全502** | — |
| 99Hz サンプリング | 352 | 57ms(~0%) |

→ per-call はエンドポイント依存で 0%〜1/8 に激変(呼出密×CPU余裕)。`READ_CHECK=OFF` は
μbench では 8倍速だが、実 Zend フレームの不正ポインタを生 memcpy が踏んで **worker が SIGSEGV**
= **syscall はホストを生かしている当のもの**(安全↔速度の下限)。詳細は
[`bench/RESULTS.md`](bench/RESULTS.md)。
(注: bpftime 注入のハングは arm64/Docker 固有。x86 実機は CLI/php-fpm・並行・llvm/ubpf の
全構成で完走 = 過度には貶めない。)

## bench/fridaB/ — per-request 動的サンプリング(方式B)

「非サンプル request では per-call フックごと外す」を忠実に実装。**eBPF は自分でフックを
張れない**ため、frida-gum(bpftime の下回りと同じ)を直接使い、`php_request_startup` で
1/N なら `Interceptor.attach(dtrace_execute_ex)`、`php_request_shutdown` で `detach`。

```sh
# frida-gadget(linux-arm64)を frida releases から取得(gitignore 済み、~28MB)
curl -sL https://github.com/frida/frida/releases/download/<ver>/frida-gadget-<ver>-linux-arm64.so.xz \
  | xz -d > bench/fridaB/frida-gadget.so
docker build -f bench/Dockerfile.fridaB -t phptrace-fridab bench
# agent.js の __SAMPLE_N__ を N に差し替えて起動 → nginx 経由で oha /cpu を計測(条件別に N を振る)
```

**結果(/cpu, サンプル率 N を振る)**:

| サンプル率 | RPS | P99 | fires/req |
|---|---|---|---|
| baseline | 346 | 129ms | 0 |
| N=1(毎回=full) | 88 | 546ms | 73,258 |
| N=10(10%) | 262 | 165ms | 7,088 |
| N=1000(0.1%) | 339 | 106ms | 55 |

→ **RPS は N とともに baseline へ回復**(`fires/req ≈ 73k/N` = 非サンプルは発火ゼロ=フック不在)。
だが **P99 はサンプル率が 1% を切るまで**サンプル request の遅延に張り付く。付け外しコストは
無視可(~1.4%)。**throughput は守れる / tail SLO は <1% サンプルで守れる**。
限界: 実装は fork-free な `php -S`(frida-gadget は php-fpm の fork で死ぬ)。fork 生存する
注入器 + 実行時 toggle API は future work。詳細は [`bench/RESULTS.md`](bench/RESULTS.md) §6。

---

## flamegraph が重くならない工夫(非正規化)

distinct stack は数百種に収束するので素の `GROUP BY stack` は軽い。重かったのは
**エンドポイント/duration で絞った flamegraph**(`samples` × 数十万行 `requests` の範囲 JOIN)。
対策として **ingest 時に各サンプルへ所属リクエストの `uri`/`req_dur_us` を書き込む非正規化**
(`Apm.Ingest.stitch`)を導入。フィルタ版もインデックススキャンになり件数非依存で数十 ms。

## 制限 / TODO

- ndjson はローテーションしない(デモ用途。長期運用は logrotate 相当が必要)
- タイマーサンプリングは on-CPU のみ。DB/curl 待ちは境界 uprobe のスパンで補完
- flamegraph は親の 0.2% 未満のフレームを間引く
- 方式B(per-request 動的サンプリング)は fork 生存注入器 + 実行時 toggle API が未実装
