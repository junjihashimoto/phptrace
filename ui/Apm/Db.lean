import LeanTea

/-! # Apm.Db — SQLite store for the PHP APM.

Flat event rows (deliberately ClickHouse-shaped so the backend can be
swapped later) plus a per-minute rollup and ingest bookkeeping. Raw
events are kept for `RETENTION_HOURS` (default 2h); the rollup keeps
long-term endpoint stats beyond that. -/

namespace Apm

open LeanTea

structure Store where
  db : Sqlite.Db

def ddl : String := "
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
-- samples carry a denormalized copy of their owning request's uri/dur
-- (stitched in at ingest) so the filtered flamegraph needs no join.
-- `cnt` lets one row stand for N identical samples: the native tracer's
-- bounded mode pre-aggregates (stack -> count) so the store stays constant
-- regardless of load. The per-sample PHP path just writes cnt=1.
CREATE TABLE IF NOT EXISTS samples(
  ts_ns INTEGER NOT NULL, pid INTEGER NOT NULL, stack TEXT NOT NULL,
  uri TEXT, req_dur_us INTEGER, cnt INTEGER NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts_ns);
CREATE TABLE IF NOT EXISTS requests(
  pid INTEGER NOT NULL, start_ns INTEGER NOT NULL, end_ns INTEGER NOT NULL,
  dur_us INTEGER NOT NULL, method TEXT NOT NULL, uri TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_requests_end ON requests(end_ns);
CREATE INDEX IF NOT EXISTS idx_requests_uri ON requests(uri, end_ns);
CREATE TABLE IF NOT EXISTS db_queries(
  pid INTEGER NOT NULL, ts_ns INTEGER NOT NULL, dur_us INTEGER NOT NULL,
  query TEXT NOT NULL, stack TEXT, qnorm TEXT);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON db_queries(ts_ns);
CREATE TABLE IF NOT EXISTS ingest_state(file TEXT PRIMARY KEY, offset INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS endpoint_stats_1m(
  minute INTEGER NOT NULL, uri TEXT NOT NULL, cnt INTEGER NOT NULL,
  p50_us INTEGER NOT NULL, p95_us INTEGER NOT NULL, p99_us INTEGER NOT NULL,
  PRIMARY KEY(minute, uri));
"

/-- Idempotent migrations for DBs created before a column existed.
    SQLite has no `ADD COLUMN IF NOT EXISTS`, so we just try and swallow
    the "duplicate column" error. -/
def migrations : List String := [
  "ALTER TABLE samples ADD COLUMN uri TEXT",
  "ALTER TABLE samples ADD COLUMN req_dur_us INTEGER",
  "CREATE INDEX IF NOT EXISTS idx_samples_uri ON samples(uri, ts_ns)",
  "ALTER TABLE db_queries ADD COLUMN stack TEXT",
  "ALTER TABLE db_queries ADD COLUMN qnorm TEXT",
  "CREATE INDEX IF NOT EXISTS idx_queries_norm ON db_queries(qnorm, ts_ns)",
  "ALTER TABLE samples ADD COLUMN cnt INTEGER NOT NULL DEFAULT 1"
]

def Store.open (path : String) : IO Store := do
  let db ← Sqlite.open' path
  Sqlite.exec db ddl
  for m in migrations do
    try Sqlite.exec db m catch _ => pure ()
  -- Hard ceiling on the DB file size (MAX_DB_MB, 0 = unlimited): writes past
  -- it fail with SQLITE_FULL rather than filling the disk; retention frees
  -- space. page_size is 4096 by default, so pages = MB * 256.
  match (← IO.getEnv "MAX_DB_MB").bind (·.toNat?) with
  | some mb =>
    if mb > 0 then
      try Sqlite.exec db s!"PRAGMA max_page_count={mb * 256}" catch _ => pure ()
  | none => pure ()
  return { db }

def Store.query (s : Store) (sql : String) (params : Array String := #[]) :
    IO (Array (Array String)) :=
  Sqlite.query s.db sql params

def Store.exec (s : Store) (sql : String) (params : Array String := #[]) : IO Unit := do
  let _ ← Sqlite.execp s.db sql params

/-- Current wall-clock time in ns since epoch (via sqlite, avoiding
    platform time APIs). Sub-second precision is not needed here. -/
def Store.nowNs (s : Store) : IO Int := do
  let rows ← s.query "SELECT CAST(strftime('%s','now') AS INTEGER)"
  let sec := (rows[0]?.bind (·[0]?)).bind (·.toInt?) |>.getD 0
  return sec * 1000000000

/-- p-th percentile (0-100) of a sorted array. -/
def percentile (sorted : Array Int) (p : Nat) : Int :=
  if sorted.isEmpty then 0
  else
    let idx := (sorted.size - 1) * p / 100
    sorted[idx]!

def fmtUs (us : Int) : String :=
  if us >= 1000000 then
    let ms10 := us / 100000  -- tenths of a second
    s!"{ms10 / 10}.{ms10 % 10}s"
  else if us >= 1000 then
    let t := us / 100        -- tenths of a ms
    s!"{t / 10}.{t % 10}ms"
  else
    s!"{us}us"

end Apm
