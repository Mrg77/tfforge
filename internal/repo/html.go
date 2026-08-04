package repo

import (
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/Mrg77/tfforge/internal/tools"
)

// HTML renders the audit as a single self-contained HTML page — a SHAREABLE
// deliverable, not a terminal dump. No external assets (CSP-safe, works offline,
// email-attachable): all CSS is inline, fonts are system stacks, no network, no
// JavaScript. The page is a cockpit an engineer (or an interviewer) reads at a
// glance: a health verdict, per-category TABS (CSS-only radio + sibling combinator
// — accessible, keyboard-navigable), and a per-directory rollup. Light and dark
// themes both, following the OS preference. It scales: each panel is capped so a
// 500- or 5000-finding repo still renders a fast, bounded page (the full list is
// always available via --json).
//
// enrich, when non-nil, maps a finding's identity (file + message) to an
// AI-written explanation; it's how the optional `--explain` layer grafts onto
// the deterministic report without the HTML knowing anything about the model.
func (r *Report) HTML(enrich map[string]Enrichment, cost *ExplainCost) string {
	data := r.htmlModel(enrich, cost)
	var b strings.Builder
	if err := htmlTmpl.Execute(&b, data); err != nil {
		// Templating a fixed template over validated data shouldn't fail; if it
		// somehow does, fall back to the text report wrapped in <pre> so the user
		// still gets something usable.
		return "<!doctype html><meta charset=utf-8><pre>" +
			template.HTMLEscapeString(r.Text(len(r.Findings), false)) + "</pre>"
	}
	return b.String()
}

// Enrichment is one finding's AI-written fix: a short prose explanation plus an
// optional before/after HCL diff. The --explain CLI layer fills these in; the
// HTML renders Prose as a "Fix ·" line and Before/After as a diff.
type Enrichment struct {
	Prose  string
	Before string // current problematic HCL (reconstructed), "" if none
	After  string // corrected HCL, copy-pasteable
}

// ExplainCost is the FinOps summary of the --explain API call, shown in the HTML
// footer so the AI layer's spend is visible. Zero value = no AI call was made.
type ExplainCost struct {
	Model  string
	InTok  int
	OutTok int
	USD    float64
}

// EnrichKey identifies a finding for the AI-explanation map (used by the CLI's
// --explain layer to key its results). File+Message is
// stable and unique enough for a report (two identical messages in one file are
// the same class of issue).
func EnrichKey(f tools.Finding) string { return f.File + "\x00" + f.Message }

// --- view model ------------------------------------------------------------

// htmlCat is a category panel: its own tab + a (possibly truncated) finding list.
type htmlCat struct {
	ID        string        // "security", "version", "bp", "structure", "variables"
	Title     string        // "Security", ...
	N         int           // total findings in this category
	Shown     []htmlFinding // capped slice actually rendered
	Truncated bool
}

type htmlFinding struct {
	Rank     int
	Severity string
	SevClass string // css class: crit|high|med|low|info
	Category string
	File     string
	Message  string
	Explain  string // AI enrichment prose, "" if none
	Before   string // AI-reconstructed current HCL, "" if none
	After    string // AI-written fixed HCL, "" if none
}

type htmlDir struct {
	Dir      string
	N        int
	Pct      int // width % of the widest dir's bar
	MaxClass string
}

type htmlModel struct {
	Root        string
	DirsScanned int
	TFFiles     int
	Providers   []string

	Total        int
	Security     int
	Version      int
	BestPractice int
	Structure    int
	Variables    int

	Hot         bool // any CRITICAL/HIGH at all → "All" pill turns red
	SecurityHot bool // any CRITICAL/HIGH in security

	MaxSeverity  string
	MaxClass     string
	Verdict      string // one-line human verdict
	VerdictClass string // healthy|attention|urgent
	Enriched     bool
	Cost         *ExplainCost // set when --explain ran; nil otherwise

	AllShown     []htmlFinding // capped "All" list
	AllShownN    int
	AllTruncated bool
	Cats         []htmlCat // only non-empty categories, in priority order

	Dirs []htmlDir
}

func sevClass(s string) string {
	switch s {
	case "CRITICAL":
		return "crit"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "med"
	case "LOW":
		return "low"
	default:
		return "info"
	}
}

// maxPerPanel caps how many findings each panel renders, so a huge repo produces
// a fast, readable page instead of a megabyte of DOM. The full data is always
// available via --json — truncation is honest and visible (a ".more" banner),
// never silent, and always the WORST N (findings are pre-sorted worst-first).
const maxPerPanel = 50

func (r *Report) htmlModel(enrich map[string]Enrichment, cost *ExplainCost) htmlModel {
	cat := r.CategoryCounts()
	m := htmlModel{
		Cost:         cost,
		Root:         r.Root,
		DirsScanned:  r.DirsScanned,
		TFFiles:      r.TFFiles,
		Providers:    r.Providers,
		Total:        len(r.Findings),
		Security:     cat[tools.CatSecurity],
		Version:      cat[tools.CatVersion],
		BestPractice: cat[tools.CatBestPractice],
		Structure:    cat[tools.CatStructure],
		Variables:    cat[tools.CatVariables],
		MaxSeverity:  r.MaxSeverity().String(),
		Enriched:     len(enrich) > 0,
	}
	m.MaxClass = sevClass(m.MaxSeverity)
	m.Hot = r.MaxSeverity() >= tools.SevHigh

	// Verdict: honest one-liner keyed off the worst severity present.
	switch {
	case m.Total == 0:
		m.Verdict, m.VerdictClass = "No findings — this repo looks healthy.", "healthy"
	case r.MaxSeverity() >= tools.SevHigh:
		m.Verdict, m.VerdictClass = "Urgent issues found — fix the security items at the top before anything else.", "urgent"
	case r.MaxSeverity() >= tools.SevMedium:
		m.Verdict, m.VerdictClass = "Needs attention — deprecations and gaps to clean up, nothing on fire.", "attention"
	default:
		m.Verdict, m.VerdictClass = "Mostly healthy — only low-severity polish left.", "healthy"
	}

	// Build the flat "All" list (already worst-first) + per-category buckets.
	// r.Findings is pre-sorted, so buckets inherit that order.
	buckets := map[tools.Category][]htmlFinding{}
	for i, f := range r.Findings {
		hf := htmlFinding{
			Rank:     i + 1,
			Severity: f.Severity,
			SevClass: sevClass(f.Severity),
			Category: string(f.Category),
			File:     f.File,
			Message:  f.Message,
		}
		if enrich != nil {
			if e, ok := enrich[EnrichKey(f)]; ok {
				hf.Explain = e.Prose
				hf.Before = e.Before
				hf.After = e.After
			}
		}
		if f.Sev() >= tools.SevHigh && f.Category == tools.CatSecurity {
			m.SecurityHot = true
		}
		if len(m.AllShown) < maxPerPanel {
			m.AllShown = append(m.AllShown, hf)
		}
		buckets[f.Category] = append(buckets[f.Category], hf)
	}
	m.AllShownN = len(m.AllShown)
	m.AllTruncated = m.Total > m.AllShownN

	// Category panels, only if non-empty, in fixed priority order.
	order := []struct {
		cat   tools.Category
		id    string
		title string
	}{
		{tools.CatSecurity, "security", "Security"},
		{tools.CatVersion, "version", "Version"},
		{tools.CatBestPractice, "bp", "Best-practice"},
		{tools.CatStructure, "structure", "Structure"},
		{tools.CatVariables, "variables", "Variables"},
	}
	for _, o := range order {
		all := buckets[o.cat]
		if len(all) == 0 {
			continue
		}
		shown := all
		trunc := false
		if len(shown) > maxPerPanel {
			shown = shown[:maxPerPanel]
			trunc = true
		}
		m.Cats = append(m.Cats, htmlCat{
			ID: o.id, Title: o.title, N: len(all),
			Shown: shown, Truncated: trunc,
		})
	}

	// Per-directory rollup, worst-count first, with a bar scaled to the max.
	type acc struct {
		n   int
		max tools.Severity
	}
	byDir := map[string]*acc{}
	dorder := []string{}
	for _, d := range r.byDir {
		if len(d.Findings) == 0 {
			continue
		}
		a := &acc{}
		for _, f := range d.Findings {
			a.n++
			if f.Sev() > a.max {
				a.max = f.Sev()
			}
		}
		byDir[d.Dir] = a
		dorder = append(dorder, d.Dir)
	}
	maxN := 1
	for _, a := range byDir {
		if a.n > maxN {
			maxN = a.n
		}
	}
	sort.Slice(dorder, func(i, j int) bool {
		if byDir[dorder[i]].n != byDir[dorder[j]].n {
			return byDir[dorder[i]].n > byDir[dorder[j]].n
		}
		return dorder[i] < dorder[j]
	})
	for _, d := range dorder {
		a := byDir[d]
		m.Dirs = append(m.Dirs, htmlDir{Dir: d, N: a.n, Pct: a.n * 100 / maxN, MaxClass: sevClass(a.max.String())})
	}
	return m
}

// --- template --------------------------------------------------------------

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"pct": func(i int) template.CSS { return template.CSS(fmt.Sprintf("%d%%", i)) },
}).Parse(htmlSource))

const htmlSource = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Terraform health — {{.Root}}</title>
<style>
  :root{
    --bg:#f4f6f9; --panel:#ffffff; --ink:#12161c; --muted:#5a6675; --line:#e2e7ee;
    --accent:#2f6db0; --shadow:0 1px 3px rgba(18,22,28,.08),0 8px 24px rgba(18,22,28,.05);
    --crit:#c0392b; --high:#d15b2b; --med:#c68a12; --low:#4f7bbf; --info:#8a94a3;
    --crit-bg:#fbecea; --high-bg:#fbf0e8; --med-bg:#faf3e0; --low-bg:#eef3fb; --info-bg:#f0f2f5;
    --ok:#3f8f5f; --ok-bg:#e8f2ec; --chip:#eef1f5;
  }
  @media (prefers-color-scheme:dark){
    :root{
      --bg:#0e1217; --panel:#161c24; --ink:#e8edf3; --muted:#93a0b0; --line:#242d38;
      --accent:#5b9bd8; --shadow:0 1px 3px rgba(0,0,0,.4),0 10px 30px rgba(0,0,0,.35);
      --crit:#e5675a; --high:#e8895c; --med:#d9ab4a; --low:#7aa6e0; --info:#8793a3;
      --crit-bg:#2a1917; --high-bg:#291d15; --med-bg:#282013; --low-bg:#151f2c; --info-bg:#1a2029;
      --ok:#63b382; --ok-bg:#16241c; --chip:#1c232d;
    }
  }
  :root[data-theme="light"]{
    --bg:#f4f6f9; --panel:#ffffff; --ink:#12161c; --muted:#5a6675; --line:#e2e7ee;
    --accent:#2f6db0; --shadow:0 1px 3px rgba(18,22,28,.08),0 8px 24px rgba(18,22,28,.05);
    --crit:#c0392b; --high:#d15b2b; --med:#c68a12; --low:#4f7bbf; --info:#8a94a3;
    --crit-bg:#fbecea; --high-bg:#fbf0e8; --med-bg:#faf3e0; --low-bg:#eef3fb; --info-bg:#f0f2f5;
    --ok:#3f8f5f; --ok-bg:#e8f2ec; --chip:#eef1f5;
  }
  :root[data-theme="dark"]{
    --bg:#0e1217; --panel:#161c24; --ink:#e8edf3; --muted:#93a0b0; --line:#242d38;
    --accent:#5b9bd8; --shadow:0 1px 3px rgba(0,0,0,.4),0 10px 30px rgba(0,0,0,.35);
    --crit:#e5675a; --high:#e8895c; --med:#d9ab4a; --low:#7aa6e0; --info:#8793a3;
    --crit-bg:#2a1917; --high-bg:#291d15; --med-bg:#282013; --low-bg:#151f2c; --info-bg:#1a2029;
    --ok:#63b382; --ok-bg:#16241c; --chip:#1c232d;
  }
  *{box-sizing:border-box}
  body{
    margin:0; background:var(--bg); color:var(--ink);
    font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    -webkit-font-smoothing:antialiased;
  }
  .wrap{max-width:960px; margin:0 auto; padding:40px 24px 72px}
  code,.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
  .num{font-variant-numeric:tabular-nums}

  header.top{margin-bottom:22px}
  .eyebrow{font-size:12px; letter-spacing:.12em; text-transform:uppercase; color:var(--muted); font-weight:600}
  h1{font-size:20px; margin:6px 0 2px; font-weight:650; word-break:break-all; line-height:1.3}
  .sub{color:var(--muted); font-size:13.5px}
  .providers{margin-top:10px; display:flex; gap:6px; flex-wrap:wrap; align-items:center}
  .providers .plabel{font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; font-weight:600}
  .chip{font-size:12px; padding:3px 9px; border-radius:999px; background:var(--chip);
        border:1px solid var(--line); color:var(--ink); font-weight:550}

  .verdict{
    display:flex; align-items:center; gap:14px; margin:20px 0 24px;
    padding:16px 18px; border-radius:12px; background:var(--panel);
    box-shadow:var(--shadow); border-left:4px solid var(--accent);
  }
  .verdict.healthy{border-left-color:var(--ok)}
  .verdict.attention{border-left-color:var(--med)}
  .verdict.urgent{border-left-color:var(--crit)}
  .verdict .dot{width:10px;height:10px;border-radius:50%;flex:none;background:var(--accent)}
  .verdict.healthy .dot{background:var(--ok)}
  .verdict.attention .dot{background:var(--med)}
  .verdict.urgent .dot{background:var(--crit)}
  .verdict p{margin:0;font-weight:550}

  .cards{display:grid; grid-template-columns:repeat(6,1fr); gap:10px; margin-bottom:30px}
  @media(max-width:760px){.cards{grid-template-columns:repeat(3,1fr)}}
  @media(max-width:460px){.cards{grid-template-columns:repeat(2,1fr)}}
  .card{background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:14px 14px 12px}
  .card .k{font-size:11px; letter-spacing:.04em; text-transform:uppercase; color:var(--muted); font-weight:600}
  .card .v{font-size:26px; font-weight:680; margin-top:5px; line-height:1}
  .card.total .v{color:var(--ink)}
  .card.sec .v{color:var(--crit)} .card.ver .v{color:var(--med)}
  .card.bp .v{color:var(--muted)} .card.st .v{color:var(--low)} .card.va .v{color:var(--info)}

  /* ---- tabs (CSS-only, radio + sibling combinator) ---- */
  .tabwrap{position:relative}
  .tabwrap input.tabr{position:absolute; opacity:0; pointer-events:none; width:0; height:0}
  .tabbar{display:flex; gap:6px; flex-wrap:wrap; margin-bottom:18px;
          border-bottom:1px solid var(--line)}
  .tabbar label{
    display:inline-flex; align-items:center; gap:7px; cursor:pointer;
    font-size:13.5px; font-weight:600; color:var(--muted);
    padding:9px 13px; border:1px solid transparent; border-bottom:none;
    border-radius:9px 9px 0 0; position:relative; top:1px; user-select:none;
  }
  .tabbar label:hover{color:var(--ink)}
  .tabbar .pill{font-size:11px; font-weight:700; padding:1px 7px; border-radius:999px;
                background:var(--chip); color:var(--muted); min-width:1.4em; text-align:center}
  .tabbar .pill.hot{background:var(--crit-bg); color:var(--crit)}

  .panel{display:none}
  #tab-all:checked       ~ .panels #panel-all,
  #tab-security:checked  ~ .panels #panel-security,
  #tab-version:checked   ~ .panels #panel-version,
  #tab-bp:checked        ~ .panels #panel-bp,
  #tab-structure:checked ~ .panels #panel-structure,
  #tab-variables:checked ~ .panels #panel-variables{display:block}
  #tab-all:checked       ~ .tabbar label[for=tab-all],
  #tab-security:checked  ~ .tabbar label[for=tab-security],
  #tab-version:checked   ~ .tabbar label[for=tab-version],
  #tab-bp:checked        ~ .tabbar label[for=tab-bp],
  #tab-structure:checked ~ .tabbar label[for=tab-structure],
  #tab-variables:checked ~ .tabbar label[for=tab-variables]{
    color:var(--ink); background:var(--panel);
    border-color:var(--line); border-bottom-color:var(--panel);
  }
  .tabr:focus-visible ~ .tabbar label[for]{outline:2px solid var(--accent); outline-offset:-2px; border-radius:9px}

  h2{font-size:13px; letter-spacing:.08em; text-transform:uppercase; color:var(--muted);
     margin:26px 0 14px; font-weight:650}
  h2:first-child{margin-top:0}

  ol.findings{list-style:none; margin:0 0 8px; padding:0; display:flex; flex-direction:column; gap:10px}
  li.f{
    background:var(--panel); border:1px solid var(--line); border-radius:11px;
    padding:14px 16px; box-shadow:var(--shadow); position:relative; overflow:hidden;
  }
  li.f::before{content:""; position:absolute; left:0; top:0; bottom:0; width:4px; background:var(--info)}
  li.f.crit::before{background:var(--crit)} li.f.high::before{background:var(--high)}
  li.f.med::before{background:var(--med)} li.f.low::before{background:var(--low)}
  .f .row1{display:flex; align-items:center; gap:10px; flex-wrap:wrap}
  .rank{color:var(--muted); font-weight:650; font-size:13px; min-width:1.6em}
  .badge{font-size:11px; font-weight:700; letter-spacing:.03em; padding:3px 8px; border-radius:999px; text-transform:uppercase}
  .badge.crit{color:var(--crit);background:var(--crit-bg)} .badge.high{color:var(--high);background:var(--high-bg)}
  .badge.med{color:var(--med);background:var(--med-bg)} .badge.low{color:var(--low);background:var(--low-bg)}
  .badge.info{color:var(--info);background:var(--info-bg)}
  .cat{font-size:12px; color:var(--muted)}
  .path{font-size:12.5px; color:var(--accent); margin-left:auto; word-break:break-all}
  .f .msg{margin:9px 0 0; color:var(--ink)}
  .f .explain{margin:10px 0 0; padding:10px 12px; border-radius:8px; background:var(--info-bg);
              font-size:13.5px; color:var(--ink)}
  .f .explain b{color:var(--accent)}
  /* before/after diff: two stacked columns, tinted red (removed) / green (added) */
  .diff{display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:10px}
  @media(max-width:640px){.diff{grid-template-columns:1fr}}
  .d-col{border-radius:7px; overflow:hidden; border:1px solid var(--line); background:var(--bg)}
  .d-lbl{display:block; font-size:10.5px; font-weight:700; letter-spacing:.08em; text-transform:uppercase;
         padding:5px 10px; color:var(--muted)}
  .d-before .d-lbl{color:var(--crit); background:var(--crit-bg)}
  .d-after .d-lbl{color:var(--ok); background:var(--ok-bg)}
  .d-lbl em{font-style:normal; font-weight:500; opacity:.75; text-transform:none; letter-spacing:0}
  .diffnote{margin:7px 0 0; font-size:11.5px; color:var(--muted); font-style:italic}
  .d-col pre{
    margin:0; padding:10px 12px; overflow-x:auto; white-space:pre;
    font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; font-size:12.5px;
    line-height:1.5; color:var(--ink);
  }
  footer .cost{padding:3px 9px; border-radius:999px; background:var(--chip);
               border:1px solid var(--line); color:var(--muted); font-size:11.5px}

  .more{margin:14px 0 4px; font-size:13px; color:var(--muted); text-align:center;
        padding:10px; border:1px dashed var(--line); border-radius:9px}
  .more b{color:var(--ink)}

  .dirs{display:flex; flex-direction:column; gap:9px; margin-bottom:6px}
  .dir{display:grid; grid-template-columns:1fr auto; gap:6px 14px; align-items:center}
  .dir .lbl{font-size:13px}
  .dir .track{grid-column:1/2; background:var(--line); border-radius:6px; height:8px; overflow:hidden}
  .dir .bar{height:8px; border-radius:6px; background:var(--info)}
  .dir.crit .bar{background:var(--crit)} .dir.high .bar{background:var(--high)}
  .dir.med .bar{background:var(--med)} .dir.low .bar{background:var(--low)}
  .dir .cnt{grid-column:2/3; grid-row:1/3; color:var(--muted); font-weight:650; font-size:14px}

  .context{background:var(--panel); border:1px solid var(--line); border-radius:12px;
           padding:18px 18px 14px; margin-top:26px; box-shadow:var(--shadow)}

  footer{margin-top:40px; padding-top:18px; border-top:1px solid var(--line);
          color:var(--muted); font-size:12.5px; display:flex; gap:8px; flex-wrap:wrap; align-items:center}
  footer .tf{font-weight:700; color:var(--ink); letter-spacing:.02em}
  .clean{background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:30px;
          text-align:center; color:var(--ok); font-weight:600; box-shadow:var(--shadow)}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <div class="eyebrow">Terraform repo health report</div>
    <h1>{{.Root}}</h1>
    <div class="sub num">Scanned {{.DirsScanned}} director{{if eq .DirsScanned 1}}y{{else}}ies{{end}} · {{.TFFiles}} .tf file{{if eq .TFFiles 1}}{{else}}s{{end}}{{if .Enriched}} · AI-explained{{end}}</div>
    {{if .Providers}}
    <div class="providers">
      <span class="plabel">Providers</span>
      {{range .Providers}}<span class="chip">{{.}}</span>{{end}}
    </div>
    {{end}}
  </header>

  <div class="verdict {{.VerdictClass}}"><span class="dot"></span><p>{{.Verdict}}</p></div>

  <div class="cards">
    <div class="card total"><div class="k">Total</div><div class="v num">{{.Total}}</div></div>
    <div class="card sec"><div class="k">Security</div><div class="v num">{{.Security}}</div></div>
    <div class="card ver"><div class="k">Version</div><div class="v num">{{.Version}}</div></div>
    <div class="card bp"><div class="k">Best-practice</div><div class="v num">{{.BestPractice}}</div></div>
    <div class="card st"><div class="k">Structure</div><div class="v num">{{.Structure}}</div></div>
    <div class="card va"><div class="k">Variables</div><div class="v num">{{.Variables}}</div></div>
  </div>

  {{if .Total}}
  <div class="tabwrap">
    <input class="tabr" type="radio" name="tab" id="tab-all" checked>
    {{if .Security}}<input class="tabr" type="radio" name="tab" id="tab-security">{{end}}
    {{if .Version}}<input class="tabr" type="radio" name="tab" id="tab-version">{{end}}
    {{if .BestPractice}}<input class="tabr" type="radio" name="tab" id="tab-bp">{{end}}
    {{if .Structure}}<input class="tabr" type="radio" name="tab" id="tab-structure">{{end}}
    {{if .Variables}}<input class="tabr" type="radio" name="tab" id="tab-variables">{{end}}

    <div class="tabbar" role="tablist">
      <label for="tab-all">All <span class="pill{{if .Hot}} hot{{end}}">{{.Total}}</span></label>
      {{if .Security}}<label for="tab-security">Security <span class="pill{{if .SecurityHot}} hot{{end}}">{{.Security}}</span></label>{{end}}
      {{if .Version}}<label for="tab-version">Version <span class="pill">{{.Version}}</span></label>{{end}}
      {{if .BestPractice}}<label for="tab-bp">Best-practice <span class="pill">{{.BestPractice}}</span></label>{{end}}
      {{if .Structure}}<label for="tab-structure">Structure <span class="pill">{{.Structure}}</span></label>{{end}}
      {{if .Variables}}<label for="tab-variables">Variables <span class="pill">{{.Variables}}</span></label>{{end}}
    </div>

    <div class="panels">
      <section class="panel" id="panel-all">
        <h2>Fix these first</h2>
        <ol class="findings">
          {{range .AllShown}}{{template "finding" .}}{{end}}
        </ol>
        {{if .AllTruncated}}<div class="more">Showing the top <b>{{.AllShownN}}</b> of <b>{{.Total}}</b> findings. Open a category tab above, or run <code>tfforge audit --json</code> for the full list.</div>{{end}}

        <div class="context">
          <h2>Where the debt concentrates</h2>
          <div class="dirs">
            {{range .Dirs}}
            <div class="dir {{.MaxClass}}">
              <span class="lbl mono">{{.Dir}}</span>
              <span class="cnt num">{{.N}}</span>
              <div class="track"><div class="bar" style="width:{{pct .Pct}}"></div></div>
            </div>
            {{end}}
          </div>
        </div>
      </section>
      {{range .Cats}}
      <section class="panel" id="panel-{{.ID}}">
        <h2>{{.Title}} — {{.N}} finding{{if eq .N 1}}{{else}}s{{end}}</h2>
        <ol class="findings">
          {{range .Shown}}{{template "finding" .}}{{end}}
        </ol>
        {{if .Truncated}}<div class="more">Showing the top <b>{{len .Shown}}</b> of <b>{{.N}}</b> in this category. Run <code>tfforge audit --json</code> for the full list.</div>{{end}}
      </section>
      {{end}}
    </div>
  </div>
  {{else}}
  <div class="clean">✓ No findings — this repo looks healthy.</div>
  {{end}}

  <footer>
    <span class="tf">tfforge</span>
    {{if .Enriched}}<span>· deterministic audit · fixes AI-explained on request</span>{{else}}<span>· deterministic audit, no LLM tokens</span>{{end}}
    {{if .Cost}}<span class="cost">AI explain · {{.Cost.Model}} · {{.Cost.InTok}} in / {{.Cost.OutTok}} out tokens · ~${{printf "%.4f" .Cost.USD}}</span>{{end}}
  </footer>
</div>
</body>
</html>
{{define "finding"}}
<li class="f {{.SevClass}}">
  <div class="row1">
    <span class="rank num">{{.Rank}}</span>
    <span class="badge {{.SevClass}}">{{.Severity}}</span>
    <span class="cat">{{.Category}}</span>
    <span class="path mono">{{.File}}</span>
  </div>
  <p class="msg">{{.Message}}</p>
  {{if .Explain}}<div class="explain"><b>Fix &middot;</b> {{.Explain}}
    {{if or .Before .After}}<div class="diff">
      {{if .Before}}<div class="d-col d-before"><span class="d-lbl">before <em>· illustrative</em></span><pre>{{.Before}}</pre></div>{{end}}
      {{if .After}}<div class="d-col d-after"><span class="d-lbl">after</span><pre>{{.After}}</pre></div>{{end}}
    </div>{{if .Before}}<p class="diffnote">The “before” is an AI-reconstructed example — tfforge doesn’t read your file contents. Adapt the “after” to your actual code.</p>{{end}}{{end}}
  </div>{{end}}
</li>
{{end}}
`
