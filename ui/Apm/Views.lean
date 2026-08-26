import LeanTea

/-! # Apm.Views — pure HTML views (server-rendered, zero client JS).

Every interaction is a plain link or GET form, so pages are
deep-linkable and the server stays stateless. Time ranges are
Grafana-style `from`/`to` params (`now-30m`, `now`, or epoch seconds);
the flamegraph is nested flex divs; a request's waterfall is
absolutely-positioned bars on a shared time axis. -/

namespace Apm.Views

open LeanTea

/-- Minimal percent-encoder for query-string values. -/
def urlEncode (s : String) : String :=
  s.foldl (init := "") fun acc c =>
    if c.isAlphanum || c == '-' || c == '_' || c == '.' || c == '/' then
      acc.push c
    else
      let n := c.toNat
      if n < 128 then
        acc ++ s!"%{hexByte n}"
      else -- utf-8 encode
        (String.singleton c).toUTF8.foldl (fun a b => a ++ s!"%{hexByte b.toNat}") acc
where
  hexByte (n : Nat) : String :=
    let d := "0123456789ABCDEF".toList
    String.mk [d[n / 16 % 16]!, d[n % 16]!]

/-! ## Time range -/

/-- A resolved Grafana-style time range. `fromRaw`/`toRaw` are the URL
    forms (kept relative like "now-30m" so navigation stays "live");
    `fromNs`/`toNs` are resolved epoch ns; `label` is preformatted. -/
structure TimeRange where
  fromRaw : String
  toRaw : String
  fromNs : Int
  toNs : Int
  label : String
  refreshSec : Nat := 0

def TimeRange.spanNs (r : TimeRange) : Int := r.toNs - r.fromNs

/-- Query string carrying range + refresh (no leading `?`/`&`). -/
def TimeRange.qs (r : TimeRange) : String :=
  s!"from={urlEncode r.fromRaw}&to={urlEncode r.toRaw}"
  ++ (if r.refreshSec > 0 then s!"&refresh={r.refreshSec}" else "")

def css : String := "
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { background:#14161a; color:#d8dee9; font:14px/1.5 -apple-system,'Segoe UI',sans-serif;
       margin:0; padding:0 0 4em 0; }
a { color:#7aa2f7; text-decoration:none; } a:hover { text-decoration:underline; }
nav { background:#1b1e24; padding:0.6em 1.2em; display:flex; gap:1.5em; align-items:baseline;
      border-bottom:1px solid #2a2e36; position:sticky; top:0; z-index:5; }
nav .brand { font-weight:700; color:#e5c07b; }
nav a.active { color:#e5c07b; }
main { padding:1.2em; max-width:1200px; margin:0 auto; }
h1 { font-size:1.2em; } h2 { font-size:1em; color:#9aa3b2; }
table.data { border-collapse:collapse; width:100%; margin:0.8em 0; }
table.data th, table.data td { text-align:right; padding:0.35em 0.7em;
  border-bottom:1px solid #262a32; font-variant-numeric:tabular-nums; }
table.data th { color:#9aa3b2; font-weight:600; }
table.data th a { color:#9aa3b2; }
table.data td.l, table.data th.l { text-align:left; }
table.data tr:hover td { background:#1b1e24; }
.muted { color:#6b7280; }
.pill { background:#262a32; border-radius:9px; padding:0.05em 0.6em; font-size:0.85em; }
form.filter { display:flex; gap:0.8em; align-items:center; margin:0.8em 0; flex-wrap:wrap; }
form.filter input, form.filter select { background:#1b1e24; color:#d8dee9;
  border:1px solid #2a2e36; border-radius:4px; padding:0.25em 0.5em; }
form.filter button { background:#31405f; color:#d8dee9; border:0; border-radius:4px;
  padding:0.3em 0.9em; cursor:pointer; }
/* time range picker */
.tr-bar { display:flex; gap:0.5em; align-items:center; flex-wrap:wrap; margin:0.8em 0;
  background:#1b1e24; border:1px solid #2a2e36; border-radius:6px; padding:0.45em 0.7em; }
.tr-bar .lbl { color:#e5c07b; font-weight:600; margin-right:0.4em; }
.tr-bar a.preset { padding:0.1em 0.55em; border-radius:4px; background:#262a32; color:#9aa3b2; }
.tr-bar a.preset.active { background:#31405f; color:#e6edf7; }
.tr-bar a.navbtn { padding:0.1em 0.5em; border-radius:4px; background:#262a32; }
.tr-bar form { display:flex; gap:0.4em; align-items:center; margin:0; }
.tr-bar input { background:#14161a; color:#d8dee9; border:1px solid #2a2e36;
  border-radius:4px; padding:0.15em 0.4em; width:9em; font-size:0.9em; }
.tr-bar button { background:#31405f; color:#d8dee9; border:0; border-radius:4px;
  padding:0.2em 0.7em; cursor:pointer; }
/* flamegraph */
.fg { margin-top:0.8em; font-size:11px; }
.fg-node { overflow:hidden; min-width:1px; }
.fg-label { display:block; height:19px; line-height:19px; padding:0 4px; margin:1px 1px 0 0;
  border-radius:2px; color:#10131a; white-space:nowrap; overflow:hidden;
  text-overflow:ellipsis; cursor:pointer; }
.fg-label:hover { filter:brightness(1.25); text-decoration:none; }
.fg-children { display:flex; }
.crumbs { margin:0.4em 0; }
.crumbs a { margin-right:0.3em; }
/* charts */
.chart { background:#1b1e24; border:1px solid #2a2e36; border-radius:6px;
  padding:0.6em; margin:0.6em 0; }
.chart svg { display:block; width:100%; }
.bar { fill:#5b7fbd; } .bar:hover { fill:#7aa2f7; }
.qbar { fill:#b06ab3; }
.grid { grid-template-columns:1fr 1fr; display:grid; gap:1em; }
@media (max-width:900px){ .grid { grid-template-columns:1fr; } }
/* drag-to-select time range (Grafana-style) */
.tsel { position:relative; cursor:crosshair; touch-action:none; user-select:none; }
.tsel-box { position:absolute; top:0; bottom:0; background:rgba(122,162,247,0.22);
  border-left:1px solid #7aa2f7; border-right:1px solid #7aa2f7; display:none;
  pointer-events:none; }
.tsel-hint { color:#6b7280; font-size:0.8em; }
.taxis { position:relative; height:15px; margin-top:3px; }
.taxis span { position:absolute; transform:translateX(-50%); color:#6b7280;
  font-size:10px; white-space:nowrap; font-variant-numeric:tabular-nums; }
.taxis span:first-child { transform:none; }
.taxis span:last-child { transform:translateX(-100%); }
.taxis .tick { border-left:1px solid #2a2e36; padding-left:3px; }
/* call tree (Datadog-style progressive drill-down, native <details>) */
.tree { font-size:12px; margin-top:0.6em; }
.tree details { margin:0; }
.tree summary { cursor:pointer; display:flex; align-items:center; gap:10px;
  padding:2px 4px; list-style:none; border-radius:3px; }
.tree summary:hover { background:#1b1e24; }
.tree summary::-webkit-details-marker { display:none; }
.tree .mk { color:#6b7280; width:0.9em; display:inline-block; text-align:center; }
.tree .leaf .mk { color:#333842; }
.tree-children { margin-left:8px; border-left:1px solid #262a32; padding-left:8px; }
.tree-bar { flex:0 0 130px; height:11px; background:#14161a; border-radius:2px;
  position:relative; overflow:hidden; }
.tree-bar i { position:absolute; left:0; top:0; bottom:0; display:block; border-radius:2px; }
.tree-tot { flex:0 0 54px; text-align:right; color:#c8d0dc; font-variant-numeric:tabular-nums; }
.tree-self { flex:0 0 96px; text-align:right; color:#6b7280;
  font-variant-numeric:tabular-nums; font-size:0.92em; }
.tree-name { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; white-space:nowrap; }
.viewtabs { margin:0.6em 0; } .viewtabs a { margin-right:0.8em; padding:0.15em 0.6em;
  border-radius:4px; background:#262a32; color:#9aa3b2; }
.viewtabs a.active { background:#31405f; color:#e6edf7; }
/* waterfall */
.wf { background:#1b1e24; border:1px solid #2a2e36; border-radius:6px;
  padding:0.6em 0.8em; margin:0.6em 0; font-size:12px; }
.wf-row { display:flex; align-items:center; height:22px; }
.wf-label { flex:0 0 260px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
  padding-right:0.8em; color:#9aa3b2; }
.wf-track { flex:1; position:relative; height:14px; background:#14161a;
  border-radius:3px; overflow:hidden; }
.wf-bar { position:absolute; top:0; height:14px; border-radius:2px; min-width:2px; }
.wf-bar.req { background:#5b7fbd; }
.wf-bar.sql { background:#b06ab3; }
.wf-bar.cpu { background:#d9a153; }
.wf-axis { display:flex; }
.wf-axis .wf-label { color:#6b7280; }
.wf-axis .wf-track { background:none; overflow:visible; height:16px; }
.wf-axis span { position:absolute; transform:translateX(-50%); color:#6b7280;
  font-size:10px; }
"

/-- The only client JS: wires drag-to-zoom on any `.tsel` chart. A
    drag maps pixel fractions of the chart width onto the [from,to]
    epoch-second span carried in data-attributes, then navigates. -/
def dragScript : String :=
  "(function(){function wire(el){var f=+el.dataset.from,t=+el.dataset.to," ++
  "base=el.dataset.base,extra=el.dataset.extra||'';var box=el.querySelector('.tsel-box');" ++
  "var sx=null;function frac(e){var r=el.getBoundingClientRect();" ++
  "return Math.min(1,Math.max(0,(e.clientX-r.left)/r.width));}" ++
  "el.addEventListener('pointerdown',function(e){sx=frac(e);box.style.display='block';" ++
  "box.style.left=(sx*100)+'%';box.style.width='0';el.setPointerCapture(e.pointerId);});" ++
  "el.addEventListener('pointermove',function(e){if(sx==null)return;var c=frac(e);" ++
  "var l=Math.min(sx,c),w=Math.abs(c-sx);box.style.left=(l*100)+'%';box.style.width=(w*100)+'%';});" ++
  "function done(e){if(sx==null)return;var c=frac(e);var a=Math.min(sx,c),b=Math.max(sx,c);" ++
  "sx=null;box.style.display='none';if(b-a<0.012)return;" ++
  "var nf=Math.round(f+a*(t-f)),nt=Math.round(f+b*(t-f));" ++
  "location.href=base+'?from='+nf+'&to='+nt+extra;}" ++
  "el.addEventListener('pointerup',done);el.addEventListener('pointercancel',function(){sx=null;box.style.display='none';});}" ++
  "document.querySelectorAll('.tsel').forEach(wire);})();"

def shell (title : String) (active : String) (rangeQS : String)
    (refreshSec : Nat) (body : List Html) : String :=
  let nav := elem "nav" [] [
    span_ [("class","brand")] [text "phptrace"],
    a_ [("href", s!"/?{rangeQS}"), ("class", if active == "overview" then "active" else "")] [text "Overview"],
    a_ [("href", s!"/flame?{rangeQS}"), ("class", if active == "flame" then "active" else "")] [text "Flamegraph"],
    a_ [("href", s!"/requests?{rangeQS}"), ("class", if active == "requests" then "active" else "")] [text "Requests"],
    a_ [("href", s!"/queries?{rangeQS}"), ("class", if active == "queries" then "active" else "")] [text "Queries"],
    a_ [("href", "/diff"), ("class", if active == "diff" then "active" else "")] [text "Diff"],
    span_ [("class","muted")] [text "eBPF PHP APM"]
  ]
  let headEls := [
      elem "meta" [("charset","utf-8")] [],
      elem "meta" [("name","viewport"),("content","width=device-width, initial-scale=1")] [],
      elem "title" [] [text title],
      style_ css
    ] ++ (if refreshSec > 0 then
      [elem "meta" [("http-equiv","refresh"),("content", toString refreshSec)] []] else [])
  let doc := elem "html" [("lang","ja")] [
    elem "head" [] headEls,
    elem "body" [] (nav :: elem "main" [] body :: [elem "script" [] [Html.raw dragScript]])
  ]
  "<!doctype html>" ++ Html.render doc

/-! ## Grafana-style time range picker -/

/-- `base` = page path; `extra` = extra query params to preserve
    (leading `&`, e.g. "&uri=/db&min_ms=100"); `hidden` = the same as
    form fields for the absolute-range form. -/
def rangePicker (base : String) (extra : String) (hidden : List (String × String))
    (r : TimeRange) : Html :=
  let presets := [("5m","now-5m"), ("15m","now-15m"), ("30m","now-30m"),
                  ("1h","now-1h"), ("2h","now-2h"), ("6h","now-6h")]
  let mk (raw : String) (label : String) : Html :=
    let cls := if r.fromRaw == raw && r.toRaw == "now" then "preset active" else "preset"
    a_ [("class", cls), ("href", s!"{base}?from={raw}&to=now{extra}"),
        ("title", s!"last {label}")] [text label]
  -- shift / zoom on resolved absolute bounds (epoch seconds)
  let span := r.spanNs / 1000000000
  let fs := r.fromNs / 1000000000
  let ts := r.toNs / 1000000000
  let half := max 1 (span / 2)
  let back := s!"{base}?from={fs - half}&to={ts - half}{extra}"
  let fwd := s!"{base}?from={fs + half}&to={ts + half}{extra}"
  let out := s!"{base}?from={fs - half}&to={ts + half}{extra}"
  let live := s!"{base}?from=now-{span}&to=now{extra}"
  let refreshLink :=
    if r.refreshSec > 0 then
      a_ [("class","navbtn"), ("href", s!"{base}?from={r.fromRaw}&to={r.toRaw}{extra}"),
          ("title","auto-refresh off")] [text s!"⟳{r.refreshSec}s"]
    else
      a_ [("class","navbtn"),
          ("href", s!"{base}?from={r.fromRaw}&to={r.toRaw}&refresh=10{extra}"),
          ("title","auto-refresh every 10s")] [text "⟳off"]
  let form := form_ [("method","get"), ("action", base)] <|
    (hidden.map fun (k, v) => input_ [("type","hidden"),("name",k),("value",v)]) ++
    [input_ [("name","from"),("value", r.fromRaw),("title","now-30m / now-2h / epoch sec")],
     span_ [("class","muted")] [text "→"],
     input_ [("name","to"),("value", r.toRaw),("title","now / epoch sec")],
     button_ [("type","submit")] [text "apply"]]
  div_ [("class","tr-bar")] <|
    [span_ [("class","lbl")] [text r.label],
     a_ [("class","navbtn"), ("href", back), ("title","shift back")] [text "◀"],
     a_ [("class","navbtn"), ("href", out), ("title","zoom out")] [text "⤢"],
     a_ [("class","navbtn"), ("href", fwd), ("title","shift forward")] [text "▶"],
     a_ [("class","navbtn"), ("href", live), ("title","snap to now")] [text "now"]]
    ++ presets.map (fun (l, raw) => mk raw l)
    ++ [refreshLink, form]

/-! ## Flamegraph -/

inductive FTree where
  | node (name : String) (total : Nat) (children : List FTree)

def FTree.total : FTree → Nat | .node _ t _ => t
def FTree.name : FTree → String | .node n _ _ => n
def FTree.children : FTree → List FTree | .node _ _ c => c

/-- Build a forest from folded rows: (frames root-first, count). -/
partial def buildForest (rows : List (List String × Nat)) : List FTree := Id.run do
  let mut acc : List (String × Nat × List (List String × Nat)) := []
  for (stk, cnt) in rows do
    match stk with
    | [] => pure ()
    | name :: rest =>
      let tail := if rest.isEmpty then [] else [(rest, cnt)]
      match acc.find? (·.1 == name) with
      | some _ =>
        acc := acc.map fun e =>
          if e.1 == name then (name, e.2.1 + cnt, tail ++ e.2.2) else e
      | none => acc := acc ++ [(name, cnt, tail)]
  return acc.map fun (name, cnt, tails) => .node name cnt (buildForest tails)

def hueOf (s : String) : Nat :=
  (s.foldl (fun h c => (h * 31 + c.toNat) % 1000003) 7) % 360

/-- Per-mille width as a CSS percentage. -/
def pctOf (part whole : Nat) : String :=
  let pm := if whole == 0 then 0 else part * 10000 / whole
  s!"{pm / 100}.{pm % 100 / 10}{pm % 10}%"

/-- One flamegraph node: label + children row. `zoomBase` gets
    `&focus=<path>` appended; `path` is ;-joined names to this node. -/
partial def renderNode (zoomBase : String) (path : String) (parentTotal : Nat)
    (t : FTree) : Html :=
  let pct := pctOf t.total parentTotal
  let hue := hueOf t.name
  let href := s!"{zoomBase}&focus={urlEncode path}"
  let kids := (t.children.filter (fun c => c.total * 1000 / (max t.total 1) >= 2))
    |>.map fun c => renderNode zoomBase (path ++ ";" ++ c.name) t.total c
  div_ [("class","fg-node"), ("style", s!"width:{pct}")] [
    a_ [("class","fg-label"),
        ("style", s!"background:hsl({hue},55%,62%)"),
        ("href", href),
        ("title", s!"{t.name} — {t.total} samples")] [text t.name],
    div_ [("class","fg-children")] kids
  ]

/-- Full flamegraph block with an "all" root. -/
def flamegraph (zoomBase : String) (focusPath : String) (forest : List FTree) : Html :=
  let total := forest.foldl (fun a t => a + t.total) 0
  if total == 0 then
    p [("class","muted")] [text "no samples in this window/filter"]
  else
    let rootName := if focusPath.isEmpty then "all" else focusPath
    let kids := forest.map fun c =>
      renderNode zoomBase
        (if focusPath.isEmpty then c.name else focusPath ++ ";" ++ c.name) total c
    div_ [("class","fg")] [
      div_ [("class","fg-node"), ("style","width:100%")] [
        a_ [("class","fg-label"), ("style","background:#8b93a5"),
            ("href", zoomBase),
            ("title", s!"{rootName} — {total} samples")] [text s!"{rootName} ({total} samples)"],
        div_ [("class","fg-children")] kids
      ]
    ]

/-! ## Diff flamegraph (regression evaluation)

Compare two sample sets A (baseline) and B (comparison). Widths follow B's
tree; each frame is colored by how its *share* changed A→B (share = frame
samples / that set's total, so different sample counts are comparable):
red = grew in B (regression suspect), blue = shrank, gray = unchanged. -/

/-- Every node's full path (root→node, ;-joined) → its subtree total. -/
partial def pathTotals (forest : List FTree) (pre : String := "")
    : List (String × Nat) :=
  forest.foldl (init := []) fun acc t =>
    let p := if pre.isEmpty then t.name else pre ++ ";" ++ t.name
    acc ++ [(p, t.total)] ++ pathTotals t.children p

/-- Color for a share delta given in per-mille (‰) of total. -/
def diffColor (deltaPm : Int) : String :=
  let mag := Int.toNat (min 120 (if deltaPm < 0 then -deltaPm else deltaPm))
  let sat := 25 + mag * 55 / 120        -- 25%..80%
  if deltaPm > 1 then s!"hsl(2,{sat}%,58%)"        -- red: grew
  else if deltaPm < -1 then s!"hsl(210,{sat}%,58%)" -- blue: shrank
  else "hsl(0,0%,42%)"                              -- gray: ~unchanged

partial def renderDiffNode (aTotals : List (String × Nat)) (grandA grandB : Nat)
    (path : String) (parentTotal : Nat) (t : FTree) : Html :=
  let pct := pctOf t.total parentTotal
  let aT := (aTotals.find? (·.1 == path)).map (·.2) |>.getD 0
  -- share in per-mille of each side's grand total
  let shB : Int := if grandB == 0 then 0 else (t.total * 1000 / grandB : Nat)
  let shA : Int := if grandA == 0 then 0 else (aT * 1000 / grandA : Nat)
  let delta := shB - shA
  let sign := if delta > 0 then "+" else ""
  let kids := (t.children.filter (fun c => c.total * 1000 / (max t.total 1) >= 2))
    |>.map fun c => renderDiffNode aTotals grandA grandB (path ++ ";" ++ c.name) t.total c
  div_ [("class","fg-node"), ("style", s!"width:{pct}")] [
    a_ [("class","fg-label"), ("style", s!"background:{diffColor delta}"),
        ("title", s!"{t.name} — B {shB}‰ vs A {shA}‰ (Δ{sign}{delta}‰)")]
      [text t.name],
    div_ [("class","fg-children")] kids
  ]

/-- Diff flamegraph: B's tree, frames colored by A→B share change. -/
def diffFlame (forestB : List FTree) (aTotals : List (String × Nat))
    (grandA grandB : Nat) : Html :=
  if grandB == 0 then p [("class","muted")] [text "no samples in set B"]
  else
    let kids := forestB.map fun c => renderDiffNode aTotals grandA grandB c.name grandB c
    div_ [("class","fg")] [
      div_ [("class","fg-node"), ("style","width:100%")] [
        span_ [("class","fg-label"), ("style","background:#8b93a5;cursor:default")]
          [text s!"diff — A {grandA} vs B {grandB} samples (赤=増 / 青=減)"],
        div_ [("class","fg-children")] kids
      ]
    ]

/-! ## Call tree (Datadog-style progressive drill-down) -/

def pctStr (part whole : Nat) : String :=
  let x := if whole == 0 then 0 else part * 1000 / whole
  s!"{x / 10}.{x % 10}%"

/-- One call-tree node. `<details>` gives native click-to-expand with no
    JS; each level reveals the function's callees. Pre-opened down to
    `openDepth` so the hot path is visible, deeper levels expand on click.
    Shows total% (of the whole), a proportional bar, and self samples. -/
partial def renderTreeNode (grandTotal : Nat) (depth openDepth : Nat) (t : FTree) : Html :=
  let childSum := t.children.foldl (fun a c => a + c.total) 0
  let selfCount := t.total - min childSum t.total
  let hue := hueOf t.name
  let row : List Html := [
    span_ [("class","mk")] [text (if t.children.isEmpty then "·" else "▸")],
    div_ [("class","tree-bar")] [
      elem "i" [("style", s!"width:{pctOf t.total grandTotal};background:hsl({hue},55%,58%)")] []],
    span_ [("class","tree-tot")] [text (pctStr t.total grandTotal)],
    span_ [("class","tree-self")] [text s!"self {selfCount}"],
    span_ [("class","tree-name")] [text t.name]
  ]
  if t.children.isEmpty then
    div_ [("class","leaf")] [div_ [("class","summary"),("style","display:flex;align-items:center;gap:10px;padding:2px 4px")] row]
  else
    let kids := (t.children.toArray.qsort (fun a b => a.total > b.total)).toList
    elem "details" (if depth < openDepth then [("open","")] else []) [
      elem "summary" [] row,
      div_ [("class","tree-children")]
        (kids.map (renderTreeNode grandTotal (depth + 1) openDepth))
    ]

/-- Full call-tree view of a forest, roots sorted hottest-first. -/
def callTree (forest : List FTree) (openDepth : Nat := 2) : Html :=
  let total := forest.foldl (fun a t => a + t.total) 0
  if total == 0 then p [("class","muted")] [text "no samples"]
  else
    let roots := (forest.toArray.qsort (fun a b => a.total > b.total)).toList
    div_ [("class","tree")] (roots.map (renderTreeNode total 0 openDepth))

/-- Breadcrumbs for the current focus path. -/
def crumbs (zoomBase : String) (focusPath : String) : Html :=
  if focusPath.isEmpty then div_ [] []
  else Id.run do
    let parts := (focusPath.splitOn ";").filter (· ≠ "")
    let mut acc : List Html := [a_ [("href", zoomBase)] [text "all"]]
    let mut path := ""
    for pt in parts do
      path := if path.isEmpty then pt else path ++ ";" ++ pt
      acc := acc ++ [span_ [("class","muted")] [text " › "],
                     a_ [("href", s!"{zoomBase}&focus={urlEncode path}")] [text pt]]
    return div_ [("class","crumbs")] acc

/-! ## Charts (inline SVG) -/

/-- Vertical bar chart. `bars` = (label, value); fixed height 120. -/
def barChart (bars : List (String × Nat)) (cssClass : String := "bar") : Html :=
  let maxV := max 1 (bars.foldl (fun a b => max a b.2) 0)
  let n := max 1 bars.length
  let w := 1000
  let bw := w / n
  let rects := bars.zipIdx.map fun ((label, v), i) =>
    let h := v * 110 / maxV
    elem "rect" [
      ("x", toString (i * bw + 1)), ("y", toString (118 - h)),
      ("width", toString (max (bw - 2) 1)), ("height", toString (max h 1)),
      ("class", cssClass)] [elem "title" [] [text s!"{label}: {v}"]]
  elem "svg" [("viewBox", s!"0 0 {w} 120"), ("preserveAspectRatio","none"),
              ("height","120")] rects

/-- Evenly-spaced x-axis labels beneath a full-width time chart.
    `ticks` are left→right; positioned at their fractional offset. -/
def timeAxis (ticks : List String) : Html :=
  let n := ticks.length
  div_ [("class","taxis")] <|
    ticks.zipIdx.map fun (lbl, i) =>
      let pm := if n <= 1 then 0 else i * 1000 / (n - 1)
      span_ [("class","tick"), ("style", s!"left:{pm / 10}.{pm % 10}%")] [text lbl]

/-- A bar chart the user can drag across to pick a sub-range, with a
    time axis underneath. `fromSec`/`toSec` are the epoch-second bounds
    the x-axis spans; `ticks` are preformatted left→right labels;
    `extra` (leading `&`) preserves params like refresh. -/
def timeRangeChart (bars : List (String × Nat)) (fromSec toSec : Int)
    (ticks : List String) (base extra : String) (cssClass : String := "bar") : Html :=
  div_ [] [
    div_ [("class","tsel"), ("data-from", toString fromSec), ("data-to", toString toSec),
          ("data-base", base), ("data-extra", extra)] [
      barChart bars cssClass,
      div_ [("class","tsel-box")] []
    ],
    timeAxis ticks
  ]

/-! ## Waterfall (single request) -/

structure WfBar where
  startNs : Int
  durNs : Int
  title : String

structure WfRow where
  label : String
  kind : String            -- "req" | "sql" | "cpu"
  bars : List WfBar

/-- Position within [t0, t0+span] as per-mille CSS offsets. -/
private def wfStyle (t0 span : Int) (b : WfBar) : String :=
  let leftPm := (max 0 ((b.startNs - t0) * 1000 / max span 1)).toNat
  let widPm := (max 2 (b.durNs * 1000 / max span 1)).toNat
  s!"left:{leftPm / 10}.{leftPm % 10}%;width:{widPm / 10}.{widPm % 10}%"

/-- Waterfall over the request's own time axis. -/
def waterfall (t0 t1 : Int) (rows : List WfRow) (fmt : Int → String) : Html :=
  let span := max 1 (t1 - t0)
  let axis := div_ [("class","wf-row wf-axis")] [
    div_ [("class","wf-label")] [],
    div_ [("class","wf-track")] <|
      [0, 250, 500, 750, 1000].map fun pm =>
        span_ [("style", s!"left:{pm / 10}%")] [text (fmt (span * pm / 1000 / 1000))]
  ]
  let body := rows.map fun row =>
    div_ [("class","wf-row")] [
      div_ [("class","wf-label"), ("title", row.label)] [text row.label],
      div_ [("class","wf-track")] <|
        row.bars.map fun b =>
          div_ [("class", s!"wf-bar {row.kind}"),
                ("style", wfStyle t0 span b),
                ("title", b.title)] []
    ]
  div_ [("class","wf")] (axis :: body)

end Apm.Views
