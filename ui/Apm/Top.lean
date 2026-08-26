import Apm.Db
import LeanTea.Tui

/-! # apm_top — a `top`-like live monitor, built on the LeanTea.Tui runtime.

Unlike the old hand-rolled ANSI loop, this uses `LeanTea.Tui.App`: raw mode,
alt-screen, clean Ctrl-C teardown, and the new `tickMs`/`onTick` support so
the display refreshes on a timer (re-querying SQLite each tick).

Two live views over the trailing window:
  * **functions** — top functions by on-CPU self-time (the `perf top` view)
  * **ops** — per-op / per-endpoint latency, ranked by total time

Keys: `f` functions · `o` ops · `b` both · `q`/Ctrl-C quit. -/

namespace Apm.Top

open Apm LeanTea.Tui

/-! ## State -/

structure Fn where
  name : String
  self : Nat

structure Op where
  uri : String
  cnt : Nat
  tot : Int
  avg : Int
  mx : Int

structure St where
  store   : Store
  view    : String        -- funcs | ops | both
  winSec  : Nat
  samples : Nat := 0
  fnTotal : Nat := 0
  fns     : List Fn := []
  ops     : List Op := []

inductive Msg where
  | setView (v : String)
  | quit

/-! ## Refresh (IO, called each tick) -/

private def leafOf (stack : String) : String :=
  (((stack.splitOn ";").filter (· ≠ "")).getLast?).getD "?"

def refresh (st : St) : IO St := do
  let now ← st.store.nowNs
  let cutoff := now - (st.winSec : Int) * 1000000000
  -- on-CPU self-time by leaf frame
  let frows ← st.store.query
    "SELECT stack, SUM(cnt) FROM samples WHERE ts_ns >= ? GROUP BY stack"
    #[toString cutoff]
  let mut byLeaf : List (String × Nat) := []
  let mut total := 0
  for r in frows do
    let n := (r[1]!.toNat?).getD 0
    total := total + n
    let leaf := leafOf r[0]!
    match byLeaf.find? (·.1 == leaf) with
    | some _ => byLeaf := byLeaf.map fun e => if e.1 == leaf then (e.1, e.2 + n) else e
    | none => byLeaf := byLeaf ++ [(leaf, n)]
  let fns := ((byLeaf.toArray.qsort (fun a b => a.2 > b.2)).toList.take 18).map
    (fun (nm, n) => { name := nm, self := n : Fn })
  -- per-op latency, aggregated in SQL
  let orows ← st.store.query
    "SELECT uri, COUNT(*), SUM(dur_us), SUM(dur_us)/COUNT(*), MAX(dur_us)
     FROM requests WHERE end_ns >= ? GROUP BY uri ORDER BY SUM(dur_us) DESC LIMIT 12"
    #[toString cutoff]
  let ops := orows.toList.map fun r =>
    { uri := r[0]!, cnt := (r[1]!.toNat?).getD 0, tot := r[2]!.toInt?.getD 0,
      avg := r[3]!.toInt?.getD 0, mx := r[4]!.toInt?.getD 0 : Op }
  return { st with samples := total, fnTotal := total, fns := fns, ops := ops }

/-! ## View helpers -/

private def pad (w : Nat) (s : String) : String :=
  if s.length >= w then s else "".pushn ' ' (w - s.length) ++ s
private def padR (w : Nat) (s : String) : String :=
  if s.length >= w then (s.take w).toString else s ++ "".pushn ' ' (w - s.length)
private def bar (v maxV width : Nat) : String :=
  let n := if maxV == 0 then 0 else v * width / maxV
  "".pushn '█' n ++ "".pushn '·' (width - n)
private def pctS (part whole : Nat) : String :=
  let x := if whole == 0 then 0 else part * 1000 / whole
  s!"{x / 10}.{x % 10}%"

private def dim : Style := { dim := true }
private def hdr : Style := { fg := .cyan, bold := true }

private def funcsWidget (st : St) : List (Widget Msg) :=
  let maxV := st.fns.foldl (fun a f => max a f.self) 1
  text "FUNCTIONS  (on-CPU self-time)" hdr
  :: text (pad 8 "SELF%" ++ pad 9 "SAMPLES" ++ "  " ++ padR 20 "" ++ "FUNCTION") dim
  :: st.fns.map fun f =>
      text (pad 8 (pctS f.self st.fnTotal) ++ pad 9 (toString f.self) ++ "  "
            ++ bar f.self maxV 18 ++ " " ++ f.name) { fg := .green }

private def opsWidget (st : St) : List (Widget Msg) :=
  let maxTot := st.ops.foldl (fun a o => max a o.tot.toNat) 1
  text "OPS / ENDPOINTS  (latency, by total time)" hdr
  :: text (padR 16 "OP" ++ pad 8 "REQ" ++ pad 7 "RPS" ++ pad 10 "AVG"
           ++ pad 10 "MAX" ++ pad 11 "TOTAL" ++ "  LOAD") dim
  :: st.ops.map fun o =>
      text (padR 16 o.uri ++ pad 8 (toString o.cnt)
            ++ pad 7 (toString (o.cnt / max st.winSec 1))
            ++ pad 10 (fmtUs o.avg) ++ pad 10 (fmtUs o.mx) ++ pad 11 (fmtUs o.tot)
            ++ "  " ++ bar o.tot.toNat maxTot 20) { fg := .magenta }

def view (st : St) : Widget Msg :=
  let header := text
    (s!"phptrace top — trailing {st.winSec}s   samples: {st.samples}   view: {st.view}   "
      ++ "(f/o/b switch · q quit)")
    { fg := .yellow, bold := true }
  let body : List (Widget Msg) :=
    (if st.view != "ops" then funcsWidget st ++ [text "" {}] else [])
    ++ (if st.view != "funcs" then opsWidget st else [])
  let tree := vbox (header :: text "" {} :: body)
  -- root gets focus so its onKey receives view-switch / quit keys
  { tree with
    focusId := "root",
    onKey := fun k => match k with
      | .char 'f' => some (.setView "funcs")
      | .char 'o' => some (.setView "ops")
      | .char 'e' => some (.setView "ops")
      | .char 'b' => some (.setView "both")
      | .char 'q' => some .quit
      | _ => none }

def update : Msg → St → St
  | .setView v, st => { st with view := v }
  | .quit, st => { st with view := "__quit__" }

end Apm.Top

def main (_ : List String) : IO Unit := do
  let dbPath := (← IO.getEnv "DB_PATH").getD "/data/apm.sqlite"
  let view := (← IO.getEnv "VIEW").getD "both"
  let winSec := ((← IO.getEnv "WINDOW_SEC").bind (·.toNat?)).getD 60
  let store ← Apm.Store.open dbPath
  -- first query up front so the opening frame isn't empty
  let st0 ← Apm.Top.refresh { store, view, winSec }
  let app : LeanTea.Tui.App Apm.Top.St Apm.Top.Msg := {
    init := st0
    view := Apm.Top.view
    update := Apm.Top.update
    quitWhen := fun st => st.view == "__quit__"
    onTick := Apm.Top.refresh
    tickMs := some 1000
    initialFocus := "root"
  }
  LeanTea.Tui.App.runWith app { focusOrder := ["root"], width := 100, height := 34 }
