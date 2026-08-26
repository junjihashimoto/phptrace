import Apm.Db
import Lean.Data.Json

/-! # Apm.Ingest — tail the tracer's ndjson files into SQLite.

Runs as a background `IO.asTask` loop next to the HTTP server:
  * every second: read newly appended bytes of samples/requests/
    db_queries ndjson, insert rows in one transaction per file
  * every minute: refresh the per-minute endpoint rollup and delete
    raw events older than the retention window

Byte offsets are persisted in `ingest_state`, so restarts skip what
was already ingested (the files themselves are append-only). -/

namespace Apm.Ingest

open Lean (Json)
open Apm

private def jStr (j : Json) (k : String) : Option String :=
  (j.getObjVal? k).toOption.bind (·.getStr?.toOption)

/-- Datadog-style SQL normalization: collapse literals to `?` so queries
    group by shape. Strips '…'/"…" string literals and numeric literals,
    collapses whitespace, and folds `IN (?, ?, …)` to `IN (?)`. Backtick
    identifiers are kept. -/
def normalizeQuery (q : String) : String := Id.run do
  let cs := q.toList.toArray
  let n := cs.size
  let mut out : String := ""
  let mut i := 0
  let mut prev : Char := ' '
  while i < n do
    let c := cs[i]!
    if c == '\'' || c == '"' then
      let quote := c
      i := i + 1
      while i < n && cs[i]! != quote do
        if cs[i]! == '\\' && i + 1 < n then i := i + 2 else i := i + 1
      i := i + 1
      out := out.push '?'; prev := '?'
    else if c.isDigit && !(prev.isAlphanum || prev == '_') then
      while i < n && (cs[i]!.isDigit || cs[i]! == '.') do i := i + 1
      out := out.push '?'; prev := '?'
    else if c == ' ' || c == '\n' || c == '\t' || c == '\r' then
      if prev != ' ' then out := out.push ' '
      prev := ' '; i := i + 1
    else
      out := out.push c; prev := c; i := i + 1
  -- fold IN (?, ?, ?) → IN (?)
  let mut s := out
  for _ in [0:6] do
    s := s.replace "?, ?" "?"
  return s.trimAscii.toString

private def jInt (j : Json) (k : String) : Option Int :=
  (j.getObjVal? k).toOption.bind (·.getInt?.toOption)

/-- One tailed file: how to turn a parsed line into an INSERT. -/
structure FileSpec where
  fname : String
  sql : String
  toParams : Json → Option (Array String)

def specs : List FileSpec := [
  { fname := "samples.ndjson"
    -- optional "n" = pre-aggregated sample count (bounded native mode);
    -- absent on the per-sample PHP path, defaulting to 1.
    sql := "INSERT INTO samples(ts_ns,pid,stack,cnt) VALUES(?,?,?,?)"
    toParams := fun j => do
      let ts ← jInt j "ts"; let pid ← jInt j "pid"; let st ← jStr j "stack"
      let n := (jInt j "n").getD 1
      pure #[toString ts, toString pid, st, toString n] },
  { fname := "requests.ndjson"
    sql := "INSERT INTO requests(pid,start_ns,end_ns,dur_us,method,uri) VALUES(?,?,?,?,?,?)"
    toParams := fun j => do
      let pid ← jInt j "pid"; let s ← jInt j "start_ns"; let e ← jInt j "end_ns"
      let d ← jInt j "dur_us"; let m ← jStr j "method"; let u ← jStr j "uri"
      pure #[toString pid, toString s, toString e, toString d, m, u] },
  { fname := "db_queries.ndjson"
    sql := "INSERT INTO db_queries(pid,ts_ns,dur_us,query,stack,qnorm) VALUES(?,?,?,?,?,?)"
    toParams := fun j => do
      let pid ← jInt j "pid"; let ts ← jInt j "ts"; let d ← jInt j "dur_us"
      let q ← jStr j "query"
      let stk := (jStr j "stack").getD ""
      pure #[toString pid, toString ts, toString d, q, stk, normalizeQuery q] }
]

structure FileState where
  spec : FileSpec
  handle : Option IO.FS.Handle := none
  buf : ByteArray := .empty
  offset : Nat := 0   -- bytes consumed from the file (persisted)

/-- Split buffered bytes into complete lines + remainder. -/
private def splitLines (b : ByteArray) : List ByteArray × ByteArray := Id.run do
  let mut lines : List ByteArray := []
  let mut start := 0
  for i in [0:b.size] do
    if b[i]! == 10 then
      lines := b.extract start i :: lines
      start := i + 1
  return (lines.reverse, b.extract start b.size)

private def readAvailable (h : IO.FS.Handle) : IO ByteArray := do
  let mut acc := ByteArray.empty
  repeat
    let chunk ← h.read 65536
    if chunk.isEmpty then
      break
    acc := acc ++ chunk
  return acc

/-- Open the file (if it exists) and skip already-ingested bytes. -/
private def openAt (path : String) (offset : Nat) : IO (Option IO.FS.Handle) := do
  try
    let h ← IO.FS.Handle.mk path IO.FS.Mode.read
    let mut left := offset
    while left > 0 do
      let chunk ← h.read (min left 1048576).toUSize
      if chunk.isEmpty then
        break -- file shrank? start from wherever we are
      left := left - chunk.size
    return some h
  catch _ =>
    return none

def tick (store : Store) (dir : String) (st : FileState) : IO FileState := do
  let mut st := st
  -- Rotation detection: if the file shrank below our offset, the writer
  -- truncated it (native bounded mode caps the ndjson). Reopen from 0.
  let path := s!"{dir}/{st.spec.fname}"
  let curSize ← (do
    try return (← (System.FilePath.mk path).metadata).byteSize.toNat
    catch _ => return st.offset)
  if curSize < st.offset then
    st := { st with offset := 0, handle := none, buf := .empty }
  if st.handle.isNone then
    st := { st with handle := ← openAt path st.offset }
  match st.handle with
  | none => return st
  | some h =>
    let fresh ← readAvailable h
    if fresh.isEmpty then
      return st
    let (lines, rest) := splitLines (st.buf ++ fresh)
    let consumed := (st.buf ++ fresh).size - rest.size
    if lines.isEmpty then
      return { st with buf := rest, offset := st.offset + consumed }
    store.exec "BEGIN"
    let mut n := 0
    for lb in lines do
      if let some s := String.fromUTF8? lb then
        if let .ok j := Json.parse s then
          if let some params := st.spec.toParams j then
            store.exec st.spec.sql params
            n := n + 1
    let newOffset := st.offset + consumed
    store.exec "INSERT OR REPLACE INTO ingest_state(file,offset) VALUES(?,?)"
      #[st.spec.fname, toString newOffset]
    store.exec "COMMIT"
    return { st with buf := rest, offset := newOffset }

/-- Rebuild the rollup for the last few minutes from raw requests. -/
def rollup (store : Store) : IO Unit := do
  let now ← store.nowNs
  let curMin := now / 60000000000
  for m in [0:5] do
    let minute := curMin - m
    let lo := minute * 60000000000
    let hi := lo + 60000000000
    let rows ← store.query
      "SELECT uri, dur_us FROM requests WHERE end_ns >= ? AND end_ns < ?"
      #[toString lo, toString hi]
    -- group durations by uri
    let mut byUri : List (String × Array Int) := []
    for r in rows do
      let uri := r[0]!
      let dur := r[1]!.toInt?.getD 0
      match byUri.find? (·.1 == uri) with
      | some (_, ds) => byUri := (uri, ds.push dur) :: byUri.filter (·.1 != uri)
      | none => byUri := (uri, #[dur]) :: byUri
    for (uri, durs) in byUri do
      let sorted := durs.qsort (· < ·)
      store.exec
        "INSERT OR REPLACE INTO endpoint_stats_1m(minute,uri,cnt,p50_us,p95_us,p99_us) VALUES(?,?,?,?,?,?)"
        #[toString minute, uri, toString sorted.size,
          toString (percentile sorted 50), toString (percentile sorted 95),
          toString (percentile sorted 99)]

/-- Denormalize: copy each untagged sample's owning request uri/dur onto
    the sample row. Runs every tick over the recent untagged window, so
    the filtered flamegraph never has to join against `requests`. Bounds
    the rescan to the last few minutes (a request completes within ms;
    samples with no matching request stay NULL and age out via retention). -/
def stitch (store : Store) : IO Unit := do
  let now ← store.nowNs
  let cutoff := now - 300000000000  -- 5 min
  store.exec
    "UPDATE samples SET
       uri = (SELECT rq.uri FROM requests rq
              WHERE rq.pid = samples.pid
                AND samples.ts_ns BETWEEN rq.start_ns AND rq.end_ns
              ORDER BY rq.start_ns DESC LIMIT 1),
       req_dur_us = (SELECT rq.dur_us FROM requests rq
              WHERE rq.pid = samples.pid
                AND samples.ts_ns BETWEEN rq.start_ns AND rq.end_ns
              ORDER BY rq.start_ns DESC LIMIT 1)
     WHERE uri IS NULL AND ts_ns > ?
       AND EXISTS (SELECT 1 FROM requests rq
                   WHERE rq.pid = samples.pid
                     AND samples.ts_ns BETWEEN rq.start_ns AND rq.end_ns)"
    #[toString cutoff]

def retention (store : Store) (hours : Nat) : IO Unit := do
  let now ← store.nowNs
  let cutoff := now - (hours : Int) * 3600000000000
  store.exec "DELETE FROM samples WHERE ts_ns < ?" #[toString cutoff]
  store.exec "DELETE FROM requests WHERE end_ns < ?" #[toString cutoff]
  store.exec "DELETE FROM db_queries WHERE ts_ns < ?" #[toString cutoff]

private def loadOffset (store : Store) (fname : String) : IO Nat := do
  let rows ← store.query "SELECT offset FROM ingest_state WHERE file = ?" #[fname]
  return ((rows[0]?.bind (·[0]?)).bind (·.toNat?)).getD 0

partial def loop (store : Store) (dir : String) (retentionHours : Nat) : IO Unit := do
  let mut states ← specs.mapM fun spec => do
    let off ← loadOffset store spec.fname
    pure { spec, offset := off : FileState }
  let mut lastMinuteJob : Int := 0
  while true do
    states ← states.mapM fun st => do
      try tick store dir st
      catch e =>
        IO.eprintln s!"ingest {st.spec.fname}: {e}"
        pure st
    try stitch store catch e => IO.eprintln s!"stitch: {e}"
    let now ← store.nowNs
    if now - lastMinuteJob > 60000000000 then
      lastMinuteJob := now
      try
        rollup store
        retention store retentionHours
      catch e => IO.eprintln s!"rollup/retention: {e}"
    IO.sleep 1000

end Apm.Ingest
