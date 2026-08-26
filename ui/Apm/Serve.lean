import Apm.Db
import Apm.Ingest
import Apm.Views

/-! # apm_serve — the web UI.

Screens, all server-rendered from SQLite with Grafana-style `from`/`to`
time ranges (`now-30m`, epoch seconds; presets / shift / zoom-out /
auto-refresh in the top bar):
  `/`          endpoint stats (P50/P95/P99, req timeline, latency histogram)
  `/flame`     aggregated flamegraph, filterable by range / endpoint /
               min request duration
  `/requests`  recent requests; `/request` = one request's waterfall
               (request span + mysqlnd queries + on-CPU sample ticks),
               flamegraph, and query table
-/

namespace Apm

open LeanTea LeanTea.Net.Http LeanTea.Net.Server
open Apm.Views

private def qparam (req : Request) (key : String) : Option String :=
  LeanTea.Rpc.lookupParam req.query key

private def qnat (req : Request) (key : String) (dflt : Nat) : Nat :=
  ((qparam req key).bind (·.toNat?)).getD dflt

/-! ## Time range resolution -/

/-- Parse "now", "now-30m" / "now-2h" / "now-90s" / "now-1d", or epoch
    seconds. -/
private def parseTimeExpr (nowSec : Int) (s : String) : Option Int :=
  if s == "now" then some nowSec
  else if s.startsWith "now-" then
    let rest := (s.drop 4).toString
    let (numPart, mult) :=
      if rest.endsWith "s" then ((rest.dropEnd 1).toString, 1)
      else if rest.endsWith "m" then ((rest.dropEnd 1).toString, 60)
      else if rest.endsWith "h" then ((rest.dropEnd 1).toString, 3600)
      else if rest.endsWith "d" then ((rest.dropEnd 1).toString, 86400)
      else (rest, 1)
    numPart.toNat?.map fun n => nowSec - (n : Int) * mult
  else
    s.toNat?.map fun n => (n : Int)

private def resolveRange (st : Store) (req : Request) : IO TimeRange := do
  let now ← st.nowNs
  let nowSec := now / 1000000000
  let fromRaw := ((qparam req "from").filter (· ≠ "")).getD "now-30m"
  let toRaw := ((qparam req "to").filter (· ≠ "")).getD "now"
  let fromSec := (parseTimeExpr nowSec fromRaw).getD (nowSec - 1800)
  let toSec := (parseTimeExpr nowSec toRaw).getD nowSec
  let (fromSec, toSec) :=
    if fromSec + 10 <= toSec then (fromSec, toSec) else (toSec - 1800, toSec)
  let label ←
    if toRaw == "now" && fromRaw.startsWith "now-" then
      pure s!"last {(fromRaw.drop 4).toString}"
    else do
      let rows ← st.query
        "SELECT datetime(?,'unixepoch','localtime'), datetime(?,'unixepoch','localtime')"
        #[toString fromSec, toString toSec]
      let a := (rows[0]?.bind (·[0]?)).getD (toString fromSec)
      let b := (rows[0]?.bind (·[1]?)).getD (toString toSec)
      pure s!"{a} → {b}"
  return { fromRaw, toRaw,
           fromNs := fromSec * 1000000000, toNs := toSec * 1000000000,
           label, refreshSec := min (qnat req "refresh" 0) 3600 }

/-- `n` evenly-spaced local-time tick labels across the range. Uses a
    finer format for short spans (HH:MM:SS) and adds the date for spans
    over a day. -/
private def rangeTicks (st : Store) (r : TimeRange) (n : Nat := 7) : IO (List String) := do
  let fromSec := r.fromNs / 1000000000
  let spanSec := r.spanNs / 1000000000
  let fmt :=
    if spanSec >= 86400 then "%m/%d %H:%M"
    else if spanSec >= 600 then "%H:%M"
    else "%H:%M:%S"
  let secs := (List.range n).map fun i =>
    fromSec + spanSec * Int.ofNat i / Int.ofNat (max 1 (n - 1))
  let values := String.intercalate "," (secs.map (fun _ => "(?)"))
  let params := (secs.map toString).toArray
  let rows ← st.query
    s!"SELECT strftime('{fmt}', column1, 'unixepoch', 'localtime') FROM (VALUES {values})"
    params
  return rows.toList.map fun row => (row[0]?).getD ""

/-- `&uri=...&min_ms=...` suffix preserving current filters. -/
private def filterSuffix (uri : Option String) (minMs : Nat) : String :=
  (match uri with | some u => s!"&uri={urlEncode u}" | none => "")
  ++ (if minMs > 0 then s!"&min_ms={minMs}" else "")

/-! ## Overview -/

structure EpStat where
  uri : String
  durs : Array Int

private def collectStats (rows : Array (Array String)) : List EpStat := Id.run do
  let mut acc : List EpStat := []
  for r in rows do
    let uri := r[0]!
    let dur := r[1]!.toInt?.getD 0
    match acc.find? (·.uri == uri) with
    | some _ => acc := acc.map fun e =>
        if e.uri == uri then { e with durs := e.durs.push dur } else e
    | none => acc := acc ++ [{ uri, durs := #[dur] }]
  return acc

private def latencyHistogram (durs : Array Int) : List (String × Nat) :=
  -- log2-ish buckets from 0.5ms up to >2s (upper bounds in us)
  let bounds : Array (Int × String) :=
    #[(500, "<0.5ms"), (1000, "1ms"), (2000, "2ms"), (4000, "4ms"), (8000, "8ms"),
      (16000, "16ms"), (32000, "32ms"), (64000, "64ms"), (125000, "125ms"),
      (250000, "250ms"), (500000, "500ms"), (1000000, "1s"), (2000000, "2s")]
  let counted := bounds.zipIdx.map fun ((hi, label), i) =>
    let lo : Int := if i == 0 then 0 else (bounds[i-1]!).1
    (label, durs.foldl (fun a d => if d >= lo && d < hi then a + 1 else a) 0)
  let over := durs.foldl (fun a d => if d >= 2000000 then a + 1 else a) 0
  counted.toList ++ [(">2s", over)]

/-- Bucket request end timestamps across the range for the timeline. -/
private def timelineBuckets (r : TimeRange) (ends : Array Int) : List (String × Nat) :=
  let buckets := 60
  let span := max 1 r.spanNs
  let counts := Id.run do
    let mut c : Array Nat := .replicate buckets 0
    for e in ends do
      let i := ((e - r.fromNs) * buckets / span).toNat
      let i := min i (buckets - 1)
      c := c.set! i (c[i]! + 1)
    return c
  (List.range buckets).map fun i =>
    let agoSec := (r.spanNs * Int.ofNat (buckets - i) / Int.ofNat buckets) / 1000000000
    (s!"-{agoSec}s", counts[i]!)

private def overview (st : Store) (req : Request) : IO Response := do
  let r ← resolveRange st req
  let rq := r.qs
  let sort := (qparam req "sort").getD "cnt"
  let rows ← st.query
    "SELECT uri, dur_us, end_ns FROM requests WHERE end_ns BETWEEN ? AND ?"
    #[toString r.fromNs, toString r.toNs]
  let stats := collectStats rows
  let stats := stats.map fun e => { e with durs := e.durs.qsort (· < ·) }
  let totalOf : EpStat → Int := fun e => e.durs.foldl (· + ·) 0
  -- default sort is by total time spent (Datadog "Resources" ranking):
  -- count × avg, so a fast-but-frequent endpoint outranks a rare slow one.
  let sort := if sort == "cnt" then "total" else sort
  let key : EpStat → Int := fun e =>
    match sort with
    | "p50" => - percentile e.durs 50
    | "p99" => - percentile e.durs 99
    | "max" => - (e.durs.back?.getD 0)
    | "req" => - (e.durs.size : Int)
    | _ => - totalOf e   -- "total"
  let stats := (stats.toArray.qsort (fun a b => key a < key b)).toList
  let grandTotal := stats.foldl (fun a e => a + totalOf e) 0

  let ends := rows.map fun row => row[2]!.toInt?.getD 0
  let ticks ← rangeTicks st r
  let spanSec := (r.spanNs / 1000000000).toNat
  let allDurs := (stats.foldl (fun a e => a ++ e.durs.toList) []).toArray
  let sortHdr (k label : String) : Html :=
    elem "th" [] [a_ [("href", s!"/?{rq}&sort={k}")]
      [text (if sort == k then s!"▾{label}" else label)]]
  let table := elem "table" [("class","data")] <|
    elem "tr" [] [
      elem "th" [("class","l")] [text "endpoint"],
      sortHdr "total" "total time", elem "th" [] [text "%time"],
      sortHdr "req" "req", elem "th" [] [text "rps"],
      sortHdr "p50" "p50", sortHdr "p50" "p95", sortHdr "p99" "p99",
      sortHdr "max" "max", elem "th" [] []
    ] :: stats.map fun e =>
      let tot := totalOf e
      elem "tr" [] [
        elem "td" [("class","l")] [
          a_ [("href", s!"/requests?{rq}&uri={urlEncode e.uri}")] [text e.uri]],
        elem "td" [] [text (fmtUs tot)],
        elem "td" [("style","color:#9aa3b2")] [text (pctStr tot.toNat (max 1 grandTotal.toNat))],
        elem "td" [] [text (toString e.durs.size)],
        elem "td" [] [text (toString (e.durs.size / max spanSec 1))],
        elem "td" [] [text (fmtUs (percentile e.durs 50))],
        elem "td" [] [text (fmtUs (percentile e.durs 95))],
        elem "td" [] [text (fmtUs (percentile e.durs 99))],
        elem "td" [] [text (fmtUs (e.durs.back?.getD 0))],
        elem "td" [] [
          a_ [("href", s!"/flame?{rq}&uri={urlEncode e.uri}")] [text "flame"]]
      ]

  let body : List Html := [
    h1 [] [text "Endpoints"],
    rangePicker "/" "" [] r,
    div_ [("class","grid")] [
      div_ [("class","chart")] [
        h2 [] [text s!"requests over range (n={ends.size})"],
        timeRangeChart (timelineBuckets r ends) (r.fromNs / 1000000000)
          (r.toNs / 1000000000) ticks "/"
          (if r.refreshSec > 0 then s!"&refresh={r.refreshSec}" else ""),
        span_ [("class","tsel-hint")] [text "↔ ドラッグで範囲を選択"]],
      div_ [("class","chart")] [
        h2 [] [text s!"latency histogram (n={allDurs.size})"],
        barChart (latencyHistogram allDurs) "qbar"]
    ],
    table
  ]
  return Response.html 200 (shell "phptrace — endpoints" "overview" rq r.refreshSec body)

/-! ## Flamegraph -/

-- Filters read the denormalized uri/req_dur_us columns on samples
-- (stitched at ingest), so this is an indexed GROUP BY with no join —
-- cost is bounded by distinct stacks, independent of request volume.
private def foldedRows (st : Store) (r : TimeRange) (uri : Option String)
    (minUs : Int) : IO (Array (Array String)) :=
  -- SUM(cnt): counts pre-aggregated (native bounded mode) and per-sample
  -- (cnt=1, PHP) rows uniformly.
  match uri with
  | some u =>
    st.query
      "SELECT stack, SUM(cnt) FROM samples
       WHERE uri = ? AND req_dur_us >= ? AND ts_ns BETWEEN ? AND ?
       GROUP BY stack"
      #[u, toString minUs, toString r.fromNs, toString r.toNs]
  | none =>
    if minUs > 0 then
      st.query
        "SELECT stack, SUM(cnt) FROM samples
         WHERE req_dur_us >= ? AND ts_ns BETWEEN ? AND ?
         GROUP BY stack"
        #[toString minUs, toString r.fromNs, toString r.toNs]
    else
      st.query
        "SELECT stack, SUM(cnt) FROM samples WHERE ts_ns BETWEEN ? AND ? GROUP BY stack"
        #[toString r.fromNs, toString r.toNs]

/-- Descend the forest along a ;-separated focus path. -/
private def descend (forest : List FTree) (path : List String) : List FTree :=
  match path with
  | [] => forest
  | name :: rest =>
    match forest.find? (·.name == name) with
    | some t => if rest.isEmpty then [t] else descend t.children rest
    | none => []

private def flamePage (st : Store) (req : Request) : IO Response := do
  let r ← resolveRange st req
  let rq := r.qs
  let uri := (qparam req "uri").filter (· ≠ "")
  let minMs := qnat req "min_ms" 0
  let focus := ((qparam req "focus").getD "")
  let rows ← foldedRows st r uri ((minMs : Int) * 1000)
  let folded := rows.toList.map fun row =>
    ((row[0]!.splitOn ";").filter (· ≠ ""), row[1]!.toNat?.getD 0)
  let forest := buildForest folded
  let focusParts := (focus.splitOn ";").filter (· ≠ "")
  let shown := if focusParts.isEmpty then forest else descend forest focusParts

  let fsuffix := filterSuffix uri minMs
  let zoomBase := s!"/flame?{rq}{fsuffix}"
  let uris ← st.query
    "SELECT DISTINCT uri FROM requests WHERE end_ns BETWEEN ? AND ? ORDER BY uri"
    #[toString r.fromNs, toString r.toNs]
  let uriOptions := elem "select" [("name","uri")] <|
    elem "option" [("value","")] [text "(all endpoints)"] ::
    uris.toList.map fun row =>
      let u := row[0]!
      elem "option"
        ([("value", u)] ++ if uri == some u then [("selected","selected")] else [])
        [text u]
  let form := form_ [("class","filter"), ("method","get"), ("action","/flame")] [
    input_ [("type","hidden"),("name","from"),("value", r.fromRaw)],
    input_ [("type","hidden"),("name","to"),("value", r.toRaw)],
    uriOptions,
    span_ [("class","muted")] [text "min duration (ms):"],
    input_ [("type","number"),("name","min_ms"),("value", toString minMs),("min","0"),("style","width:6em")],
    button_ [("type","submit")] [text "filter"]
  ]

  let view := (qparam req "view").getD "flame"
  let tab (v label : String) : Html :=
    a_ [("href", s!"{zoomBase}&view={v}{if focus.isEmpty then "" else s!"&focus={urlEncode focus}"}"),
        ("class", if view == v then "active" else "")] [text label]
  let viz := if view == "tree" then callTree shown else flamegraph zoomBase focus shown
  let body : List Html := [
    h1 [] [text "Flamegraph (on-CPU, 99Hz)"],
    rangePicker "/flame" fsuffix
      ((match uri with | some u => [("uri", u)] | none => []) ++
       (if minMs > 0 then [("min_ms", toString minMs)] else [])) r,
    form,
    div_ [("class","viewtabs")] [tab "flame" "flamegraph", tab "tree" "call tree"],
    crumbs zoomBase focus,
    viz
  ]
  return Response.html 200 (shell "phptrace — flamegraph" "flame" rq r.refreshSec body)

/-! ## Requests -/

private def requestsPage (st : Store) (req : Request) : IO Response := do
  let r ← resolveRange st req
  let rq := r.qs
  let now ← st.nowNs
  let uri := (qparam req "uri").filter (· ≠ "")
  let sort := (qparam req "sort").getD "time"
  let order := if sort == "dur" then "dur_us DESC" else "end_ns DESC"
  let baseSql := "SELECT pid,start_ns,end_ns,dur_us,method,uri FROM requests WHERE end_ns BETWEEN ? AND ?"
  let rows ←
    match uri with
    | some u =>
      st.query (baseSql ++ s!" AND uri = ? ORDER BY {order} LIMIT 200")
        #[toString r.fromNs, toString r.toNs, u]
    | none =>
      st.query (baseSql ++ s!" ORDER BY {order} LIMIT 200")
        #[toString r.fromNs, toString r.toNs]

  let fsuffix := filterSuffix uri 0
  let durs := (rows.map fun row => row[3]!.toInt?.getD 0).qsort (· < ·)
  let table := elem "table" [("class","data")] <|
    elem "tr" [] [
      elem "th" [("class","l")] [
        a_ [("href", s!"/requests?{rq}{fsuffix}&sort=time")] [text "time"]],
      elem "th" [("class","l")] [text "method"],
      elem "th" [("class","l")] [text "uri"],
      elem "th" [] [
        a_ [("href", s!"/requests?{rq}{fsuffix}&sort=dur")] [text "duration"]],
      elem "th" [] [text "pid"], elem "th" [] []
    ] :: rows.toList.map fun row =>
      let ago := (now - row[2]!.toInt?.getD 0) / 1000000000
      elem "tr" [] [
        elem "td" [("class","l muted")] [text s!"{ago}s ago"],
        elem "td" [("class","l")] [text row[4]!],
        elem "td" [("class","l")] [text row[5]!],
        elem "td" [] [text (fmtUs (row[3]!.toInt?.getD 0))],
        elem "td" [] [text row[0]!],
        elem "td" [] [
          a_ [("href", s!"/request?pid={row[0]!}&s={row[1]!}&e={row[2]!}&{rq}")]
            [text "detail"]]
      ]
  let body : List Html := [
    h1 [] [text (match uri with
      | some u => s!"Requests — {u}" | none => "Requests")],
    rangePicker "/requests" fsuffix
      (match uri with | some u => [("uri", u)] | none => []) r,
    div_ [("class","chart")] [
      h2 [] [text s!"latency histogram (n={durs.size})"],
      barChart (latencyHistogram durs) "qbar"],
    table
  ]
  return Response.html 200 (shell "phptrace — requests" "requests" rq r.refreshSec body)

/-! ## Top MySQL queries (Datadog-style, ranked by total time) -/

private def queriesPage (st : Store) (req : Request) : IO Response := do
  let r ← resolveRange st req
  let rq := r.qs
  let sort := (qparam req "sort").getD "total"
  let orderExpr := match sort with
    | "calls" => "cnt"
    | "avg" => "SUM(dur_us)/COUNT(*)"
    | "max" => "MAX(dur_us)"
    | _ => "SUM(dur_us)"   -- total
  -- normalized queries grouped; ranked by aggregate time spent
  let rows ← st.query
    (s!"SELECT qnorm, COUNT(*) cnt, SUM(dur_us) tot, SUM(dur_us)/COUNT(*) avg, MAX(dur_us) mx
        FROM db_queries WHERE ts_ns BETWEEN ? AND ? AND qnorm IS NOT NULL
        GROUP BY qnorm ORDER BY {orderExpr} DESC LIMIT 100")
    #[toString r.fromNs, toString r.toNs]
  let grand := rows.foldl (fun a row => a + (row[2]!.toInt?.getD 0)) 0

  let sortHdr (k label : String) : Html :=
    elem "th" [] [a_ [("href", s!"/queries?{rq}&sort={k}")]
      [text (if sort == k then s!"▾{label}" else label)]]
  let table := elem "table" [("class","data")] <|
    elem "tr" [] [
      sortHdr "total" "total time", elem "th" [] [text "%time"],
      sortHdr "calls" "calls", sortHdr "avg" "avg", sortHdr "max" "max",
      elem "th" [("class","l")] [text "query pattern"]
    ] :: rows.toList.map fun row =>
      let tot := row[2]!.toInt?.getD 0
      elem "tr" [] [
        elem "td" [] [text (fmtUs tot)],
        elem "td" [("style","color:#9aa3b2")] [text (pctStr tot.toNat (max 1 grand.toNat))],
        elem "td" [] [text row[1]!],
        elem "td" [] [text (fmtUs (row[3]!.toInt?.getD 0))],
        elem "td" [] [text (fmtUs (row[4]!.toInt?.getD 0))],
        elem "td" [("class","l"), ("style","font-size:0.85em")] [text row[0]!]
      ]
  let body : List Html := [
    h1 [] [text "Top MySQL queries"],
    p [("class","muted")] [text "リテラルを正規化してパターン単位で集約、合計時間でランキング(件数×平均 — 速いが多いクエリが上位に来る)"],
    rangePicker "/queries" "" [] r,
    table
  ]
  return Response.html 200 (shell "phptrace — queries" "queries" rq r.refreshSec body)

/-! ## Single request: waterfall + flamegraph + queries -/

private def truncate (n : Nat) (s : String) : String :=
  if s.length > n then (s.take (n - 1)).toString ++ "…" else s

/-- The last few PHP frames of a folded stack, e.g.
    `UserRepository::findProfile → PDO::execute`. Builtins/`{main}` are
    dropped so the tail is a real call site. -/
private def stackTail (stk : String) : String :=
  let frames := (stk.splitOn ";").filter (· ≠ "")
  let php := frames.filter fun f =>
    (f.splitOn "::").length == 2 && !(f.startsWith "{")
  let kept := if php.isEmpty then frames else php
  if kept.isEmpty then "(呼び出し元不明)"
  else String.intercalate " → " ((kept.reverse.take 3).reverse)

private def requestPage (st : Store) (req : Request) : IO Response := do
  let r ← resolveRange st req
  let rq := r.qs
  let pid := (qparam req "pid").getD "0"
  let s := (qparam req "s").getD "0"
  let e := (qparam req "e").getD "0"
  let sI := s.toInt?.getD 0
  let eI := e.toInt?.getD 0

  let metaRows ← st.query
    "SELECT method, uri, dur_us FROM requests WHERE pid=? AND start_ns=? AND end_ns=?"
    #[pid, s, e]
  let (method, uri, durUs) :=
    match metaRows[0]? with
    | some row => (row[0]!, row[1]!, row[2]!.toInt?.getD 0)
    | none => ("?", "?", 0)

  let sampleRows ← st.query
    "SELECT ts_ns, stack FROM samples WHERE pid=? AND ts_ns BETWEEN ? AND ? ORDER BY ts_ns"
    #[pid, s, e]
  let queryRows ← st.query
    "SELECT ts_ns, dur_us, query, COALESCE(stack,'') FROM db_queries WHERE pid=? AND ts_ns BETWEEN ? AND ? ORDER BY ts_ns"
    #[pid, s, e]

  -- waterfall rows: request span, on-CPU ticks, then for each query a
  -- caller row (its captured PHP call site) with the query span nested.
  let tickNs : Int := 1000000000 / 99
  let cpuBars := sampleRows.toList.map fun row =>
    let ts := row[0]!.toInt?.getD 0
    let leaf := ((row[1]!.splitOn ";").getLast?).getD "?"
    { startNs := ts, durNs := tickNs, title := s!"on-CPU: {leaf}" : WfBar }
  let sqlRows := (queryRows.toList.take 40).foldr (init := []) fun row acc =>
    let ts := row[0]!.toInt?.getD 0
    let dq := row[1]!.toInt?.getD 0
    let q := row[2]!
    let site := stackTail row[3]!
    -- caller row (muted, spans the query window) + the query bar under it
    ({ label := s!"↳ {site}", kind := "cpu",
       bars := [{ startNs := ts, durNs := dq * 1000, title := site }] : WfRow })
    :: ({ label := truncate 46 q, kind := "sql",
          bars := [{ startNs := ts, durNs := dq * 1000,
                     title := s!"{q} — {fmtUs dq}" }] : WfRow })
    :: acc
  let wfRows : List WfRow :=
    { label := s!"{method} {uri}", kind := "req",
      bars := [{ startNs := sI, durNs := eI - sI, title := s!"request — {fmtUs durUs}" }] }
    :: { label := s!"on-CPU samples ({sampleRows.size})", kind := "cpu", bars := cpuBars }
    :: sqlRows

  let folded := Id.run do
    let mut acc : List (List String × Nat) := []
    for row in sampleRows do
      let stk := (row[1]!.splitOn ";").filter (· ≠ "")
      match acc.find? (·.1 == stk) with
      | some _ => acc := acc.map fun p => if p.1 == stk then (p.1, p.2 + 1) else p
      | none => acc := acc ++ [(stk, 1)]
    return acc
  let forest := buildForest folded

  let queriesTotalUs := queryRows.foldl (fun a row => a + row[1]!.toInt?.getD 0) 0
  let qtable := elem "table" [("class","data")] <|
    elem "tr" [] [
      elem "th" [] [text "offset"], elem "th" [] [text "duration"],
      elem "th" [("class","l")] [text "called from"],
      elem "th" [("class","l")] [text "query"]
    ] :: queryRows.toList.map fun row =>
      let ts := row[0]!.toInt?.getD 0
      let site := stackTail row[3]!
      elem "tr" [] [
        elem "td" [] [text (fmtUs ((ts - sI) / 1000))],
        elem "td" [] [text (fmtUs (row[1]!.toInt?.getD 0))],
        elem "td" [("class","l"), ("style","font-size:0.82em;color:#d9a153")] [text site],
        elem "td" [("class","l"), ("style","font-size:0.85em")] [text row[2]!]
      ]

  let zoomBase := s!"/request?pid={pid}&s={s}&e={e}&{rq}"
  let focus := (qparam req "focus").getD ""
  let fp := (focus.splitOn ";").filter (· ≠ "")
  let shown := if fp.isEmpty then forest else descend forest fp
  let view := (qparam req "view").getD "flame"
  let tab (v label : String) : Html :=
    a_ [("href", s!"{zoomBase}&view={v}{if focus.isEmpty then "" else s!"&focus={urlEncode focus}"}"),
        ("class", if view == v then "active" else "")] [text label]
  let viz := if view == "tree" then callTree shown else flamegraph zoomBase focus shown
  let body : List Html := [
    h1 [] [text s!"{method} {uri}"],
    p [] [
      span_ [("class","pill")] [text (fmtUs durUs)],
      text " ",
      span_ [("class","pill")] [text s!"sql {fmtUs queriesTotalUs} ({queryRows.size})"],
      text " ", span_ [("class","muted")] [text s!"pid {pid}"],
      text "  ", a_ [("href", s!"/requests?{rq}")] [text "← requests"]],
    h2 [] [text "waterfall"],
    waterfall sI eI wfRows (fun us => fmtUs us),
    h2 [] [text "on-CPU call graph of this request"],
    div_ [("class","viewtabs")] [tab "flame" "flamegraph", tab "tree" "call tree"],
    viz,
    h2 [] [text s!"mysqlnd queries ({queryRows.size})"],
    qtable
  ]
  return Response.html 200 (shell s!"phptrace — {uri}" "requests" rq r.refreshSec body)

/-! ## Diff — regression attribution + diff flamegraph

Two sample sets A (baseline) and B (comparison), each filtered independently
by time / endpoint / duration. Because trace (uri, duration), profile (stack)
and time live in one table, "what changed A→B, by function" is a GROUP BY —
the query commercial APMs can't write because trace and profile are split
products. Works as "before/after deploy" (time diff) or "slow vs fast
requests" (duration diff — differential profiling). -/

/-- Fold one side into folded (frames, count) rows. -/
private def foldSide (st : Store) (fromNs toNs : Int) (uri : Option String)
    (minUs maxUs : Int) : IO (Array (Array String)) :=
  let hi := if maxUs <= 0 then (9223372036854775807 : Int) else maxUs
  match uri with
  | some u =>
    st.query
      "SELECT stack, SUM(cnt) FROM samples
       WHERE ts_ns BETWEEN ? AND ? AND uri = ? AND req_dur_us >= ? AND req_dur_us <= ?
       GROUP BY stack"
      #[toString fromNs, toString toNs, u, toString minUs, toString hi]
  | none =>
    st.query
      "SELECT stack, SUM(cnt) FROM samples
       WHERE ts_ns BETWEEN ? AND ? AND req_dur_us >= ? AND req_dur_us <= ?
       GROUP BY stack"
      #[toString fromNs, toString toNs, toString minUs, toString hi]

/-- self-time by leaf function, as (fn, count). -/
private def selfByFn (rows : Array (Array String)) : List (String × Nat) × Nat := Id.run do
  let mut acc : List (String × Nat) := []
  let mut total := 0
  for r in rows do
    let n := (r[1]!.toNat?).getD 0
    total := total + n
    let leaf := (((r[0]!.splitOn ";").filter (· ≠ "")).getLast?).getD "?"
    match acc.find? (·.1 == leaf) with
    | some _ => acc := acc.map fun e => if e.1 == leaf then (e.1, e.2 + n) else e
    | none => acc := acc ++ [(leaf, n)]
  return (acc, total)

private def diffPage (st : Store) (req : Request) : IO Response := do
  let now ← st.nowNs
  let nowSec := now / 1000000000
  let g (k dflt : String) : String := ((qparam req k).filter (· ≠ "")).getD dflt
  let resolve (s : String) (dflt : Int) : Int := (parseTimeExpr nowSec s).getD dflt
  -- side A (baseline) and B (comparison)
  let aFrom := g "af" "now-2h"; let aTo := g "at" "now-1h"
  let bFrom := g "bf" "now-1h"; let bTo := g "bt" "now"
  let aUri := (qparam req "au").filter (· ≠ ""); let bUri := (qparam req "bu").filter (· ≠ "")
  let aMin := (qnat req "amin" 0); let aMax := (qnat req "amax" 0)
  let bMin := (qnat req "bmin" 0); let bMax := (qnat req "bmax" 0)
  let aFromNs := resolve aFrom (nowSec - 7200) * 1000000000
  let aToNs := resolve aTo (nowSec - 3600) * 1000000000
  let bFromNs := resolve bFrom (nowSec - 3600) * 1000000000
  let bToNs := resolve bTo nowSec * 1000000000

  let aRows ← foldSide st aFromNs aToNs aUri (aMin * 1000) (aMax * 1000)
  let bRows ← foldSide st bFromNs bToNs bUri (bMin * 1000) (bMax * 1000)
  let foldedA := aRows.toList.map fun r => ((r[0]!.splitOn ";").filter (· ≠ ""), r[1]!.toNat?.getD 0)
  let foldedB := bRows.toList.map fun r => ((r[0]!.splitOn ";").filter (· ≠ ""), r[1]!.toNat?.getD 0)
  let forestB := buildForest foldedB
  let aTotals := pathTotals (buildForest foldedA)
  let (fnA, totA) := selfByFn aRows
  let (fnB, totB) := selfByFn bRows

  -- regression table: per function, share‰ in A vs B, delta, ranked by delta
  let names := (fnA.map (·.1) ++ fnB.map (·.1)).eraseDups
  let shareOf (lst : List (String × Nat)) (tot : Nat) (nm : String) : Int :=
    let c := (lst.find? (·.1 == nm)).map (·.2) |>.getD 0
    if tot == 0 then 0 else (c * 1000 / tot : Nat)
  let deltas := names.map fun nm =>
    let sa := shareOf fnA totA nm; let sb := shareOf fnB totB nm
    (nm, sa, sb, sb - sa)
  let ranked := (deltas.toArray.qsort (fun a b => a.2.2.2 > b.2.2.2)).toList

  let cell (v : String) : Html := elem "td" [] [text v]
  let deltaRow (nm : String) (sa sb d : Int) : Html :=
    let sign := if d > 0 then "+" else ""
    let col := if d > 1 then "#e06c75" else if d < -1 then "#61afef" else "#9aa3b2"
    elem "tr" [] [
      cell s!"{sa}‰", cell s!"{sb}‰",
      elem "td" [("style", s!"color:{col};font-weight:600")] [text s!"{sign}{d}‰"],
      elem "td" [("class","l")] [text nm]
    ]
  let hdrRow := elem "tr" [] [elem "th" [] [text "A share"], elem "th" [] [text "B share"],
      elem "th" [] [text "Δ (B−A)"], elem "th" [("class","l")] [text "function (self)"]]
  let dataRows := ((ranked.filter (fun r => r.2.2.2 != 0)).take 20).map
    (fun (nm, sa, sb, d) => deltaRow nm sa sb d)
  let table := elem "table" [("class","data")] (hdrRow :: dataRows)

  -- form: two independent sides + presets
  let inp (n v ph : String) := input_ [("name",n),("value",v),("placeholder",ph),("style","width:9em")]
  let side (tag : String) (f t : String) (u : Option String) (mn mx : Nat) : Html :=
    div_ [("class","chart"),("style","flex:1")] [
      h2 [] [text (if tag == "a" then "A (baseline)" else "B (comparison)")],
      div_ [("class","filter")] [
        span_ [("class","muted")] [text "from"], inp s!"{tag}f" f "now-1h",
        span_ [("class","muted")] [text "to"], inp s!"{tag}t" t "now"],
      div_ [("class","filter")] [
        span_ [("class","muted")] [text "endpoint"], inp s!"{tag}u" (u.getD "") "(all)",
        span_ [("class","muted")] [text "dur≥ms"], inp s!"{tag}min" (if mn>0 then toString mn else "") "0",
        span_ [("class","muted")] [text "dur≤ms"], inp s!"{tag}max" (if mx>0 then toString mx else "") "∞"]
    ]
  let form := form_ [("method","get"),("action","/diff")] [
    div_ [("style","display:flex;gap:1em")] [
      side "a" aFrom aTo aUri aMin aMax,
      side "b" bFrom bTo bUri bMin bMax ],
    div_ [("class","filter")] [
      button_ [("type","submit")] [text "diff"],
      span_ [("class","muted")] [text "  presets: "],
      a_ [("class","preset"),("href","/diff?af=now-2h&at=now-1h&bf=now-1h&bt=now")] [text "デプロイ前後(1h vs 1h)"],
      a_ [("class","preset"),("href","/diff?af=now-30m&at=now&amax=5&bf=now-30m&bt=now&bmin=50")] [text "速い(<5ms) vs 遅い(>50ms)"] ]
  ]

  let body : List Html := [
    h1 [] [text "Diff — regression attribution"],
    p [("class","muted")] [text "A と B を独立に絞って関数別のシェア差分を出す。デプロイ前後(時間差分)でも、速い/遅いリクエスト(duration差分=differential profiling)でも。トレース×プロファイル×時間が同一テーブルだから書ける GROUP BY。"],
    form,
    h2 [] [text s!"top regressions by self-time share (A {totA} → B {totB} samples)"],
    table,
    h2 [] [text "diff flamegraph (赤=B で増えた / 青=減った)"],
    diffFlame forestB aTotals totA totB
  ]
  return Response.html 200 (shell "phptrace — diff" "diff" "from=now-30m&to=now" 0 body)

/-! ## main -/

def handler (st : Store) : Handler := fun req => do
  try
    match req.path with
    | "/" => overview st req
    | "/flame" => flamePage st req
    | "/requests" => requestsPage st req
    | "/request" => requestPage st req
    | "/queries" => queriesPage st req
    | "/diff" => diffPage st req
    | "/favicon.ico" => return { status := 204 }
    | _ => return Response.notFound
  catch ex =>
    return Response.serverError s!"error: {ex}"

end Apm

def main (_ : List String) : IO Unit := do
  let dbPath := (← IO.getEnv "DB_PATH").getD "/data/apm.sqlite"
  let dataDir := (← IO.getEnv "DATA_DIR").getD "/data"
  let port := (((← IO.getEnv "PORT").bind (·.toNat?)).getD 8080).toUInt16
  let retention := ((← IO.getEnv "RETENTION_HOURS").bind (·.toNat?)).getD 2
  let st ← Apm.Store.open dbPath
  let _ ← IO.asTask (Apm.Ingest.loop st dataDir retention)
  IO.eprintln s!"apm_serve: http://0.0.0.0:{port}/ (db={dbPath}, data={dataDir})"
  LeanTea.Net.Server.serveConcurrent port "0.0.0.0" (Apm.handler st)
