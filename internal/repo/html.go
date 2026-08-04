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
// email-attachable): all CSS is inline, fonts are system stacks, no network. The
// page is a cockpit an engineer (or an interviewer) reads at a glance: a health
// verdict up top, the prioritized "fix these first" list, then a per-directory
// rollup. Light and dark themes both, following the OS preference.
//
// enrich, when non-nil, maps a finding's identity (file + message) to an
// AI-written explanation; it's how the optional `--explain` layer grafts onto
// the deterministic report without the HTML knowing anything about the model.
func (r *Report) HTML(enrich map[string]string) string {
	data := r.htmlModel(enrich)
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

// EnrichKey identifies a finding for the AI-explanation map (used by the CLI's
// --explain layer to key its results). File+Message is
// stable and unique enough for a report (two identical messages in one file are
// the same class of issue).
func EnrichKey(f tools.Finding) string { return f.File + "\x00" + f.Message }

// --- view model ------------------------------------------------------------

type htmlFinding struct {
	Rank     int
	Severity string
	SevClass string // css class: crit|high|med|low|info
	Category string
	File     string
	Message  string
	Explain  string // AI enrichment, "" if none
}

type htmlDir struct {
	Dir      string
	N        int
	Pct      int // width % of the widest dir's bar
	MaxClass string
}

type htmlModel struct {
	Root         string
	DirsScanned  int
	TFFiles      int
	Total        int
	Security     int
	Version      int
	BestPractice int
	MaxSeverity  string
	MaxClass     string
	Verdict      string // one-line human verdict
	VerdictClass string // healthy|attention|urgent
	Findings     []htmlFinding
	Dirs         []htmlDir
	Enriched     bool
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

func (r *Report) htmlModel(enrich map[string]string) htmlModel {
	cat := r.CategoryCounts()
	m := htmlModel{
		Root:         r.Root,
		DirsScanned:  r.DirsScanned,
		TFFiles:      r.TFFiles,
		Total:        len(r.Findings),
		Security:     cat[tools.CatSecurity],
		Version:      cat[tools.CatVersion],
		BestPractice: cat[tools.CatBestPractice],
		MaxSeverity:  r.MaxSeverity().String(),
		Enriched:     len(enrich) > 0,
	}
	m.MaxClass = sevClass(m.MaxSeverity)

	// Verdict: honest one-liner keyed off the worst severity present.
	switch {
	case m.Total == 0:
		m.Verdict = "No findings — this repo looks healthy."
		m.VerdictClass = "healthy"
	case r.MaxSeverity() >= tools.SevHigh:
		m.Verdict = "Urgent issues found — fix the security items at the top before anything else."
		m.VerdictClass = "urgent"
	case r.MaxSeverity() >= tools.SevMedium:
		m.Verdict = "Needs attention — deprecations and gaps to clean up, nothing on fire."
		m.VerdictClass = "attention"
	default:
		m.Verdict = "Mostly healthy — only low-severity polish left."
		m.VerdictClass = "healthy"
	}

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
			hf.Explain = enrich[EnrichKey(f)]
		}
		m.Findings = append(m.Findings, hf)
	}

	// Per-directory rollup, worst-count first, with a bar scaled to the max.
	type acc struct {
		n   int
		max tools.Severity
	}
	byDir := map[string]*acc{}
	order := []string{}
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
		order = append(order, d.Dir)
	}
	maxN := 1
	for _, a := range byDir {
		if a.n > maxN {
			maxN = a.n
		}
	}
	sort.Slice(order, func(i, j int) bool {
		if byDir[order[i]].n != byDir[order[j]].n {
			return byDir[order[i]].n > byDir[order[j]].n
		}
		return order[i] < order[j]
	})
	for _, d := range order {
		a := byDir[d]
		m.Dirs = append(m.Dirs, htmlDir{
			Dir:      d,
			N:        a.n,
			Pct:      a.n * 100 / maxN,
			MaxClass: sevClass(a.max.String()),
		})
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
    --ok:#3f8f5f;
  }
  @media (prefers-color-scheme:dark){
    :root{
      --bg:#0e1217; --panel:#161c24; --ink:#e8edf3; --muted:#93a0b0; --line:#242d38;
      --accent:#5b9bd8; --shadow:0 1px 3px rgba(0,0,0,.4),0 10px 30px rgba(0,0,0,.35);
      --crit:#e5675a; --high:#e8895c; --med:#d9ab4a; --low:#7aa6e0; --info:#8793a3;
      --crit-bg:#2a1917; --high-bg:#291d15; --med-bg:#282013; --low-bg:#151f2c; --info-bg:#1a2029;
      --ok:#63b382;
    }
  }
  :root[data-theme="light"]{
    --bg:#f4f6f9; --panel:#ffffff; --ink:#12161c; --muted:#5a6675; --line:#e2e7ee;
    --accent:#2f6db0;
    --crit:#c0392b; --high:#d15b2b; --med:#c68a12; --low:#4f7bbf; --info:#8a94a3;
    --crit-bg:#fbecea; --high-bg:#fbf0e8; --med-bg:#faf3e0; --low-bg:#eef3fb; --info-bg:#f0f2f5;
    --ok:#3f8f5f;
  }
  :root[data-theme="dark"]{
    --bg:#0e1217; --panel:#161c24; --ink:#e8edf3; --muted:#93a0b0; --line:#242d38;
    --accent:#5b9bd8;
    --crit:#e5675a; --high:#e8895c; --med:#d9ab4a; --low:#7aa6e0; --info:#8793a3;
    --crit-bg:#2a1917; --high-bg:#291d15; --med-bg:#282013; --low-bg:#151f2c; --info-bg:#1a2029;
    --ok:#63b382;
  }
  *{box-sizing:border-box}
  body{
    margin:0; background:var(--bg); color:var(--ink);
    font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
    -webkit-font-smoothing:antialiased;
  }
  .wrap{max-width:940px; margin:0 auto; padding:40px 24px 72px}
  code,.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace}
  .num{font-variant-numeric:tabular-nums}

  header.top{margin-bottom:28px}
  .eyebrow{font-size:12px; letter-spacing:.12em; text-transform:uppercase; color:var(--muted); font-weight:600}
  h1{font-size:20px; margin:6px 0 2px; font-weight:650; word-break:break-all; line-height:1.3}
  .sub{color:var(--muted); font-size:13.5px}

  .verdict{
    display:flex; align-items:center; gap:14px; margin:22px 0 26px;
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

  .cards{display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:34px}
  @media(max-width:620px){.cards{grid-template-columns:repeat(2,1fr)}}
  .card{background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px 16px 14px}
  .card .k{font-size:12px; letter-spacing:.04em; text-transform:uppercase; color:var(--muted); font-weight:600}
  .card .v{font-size:30px; font-weight:680; margin-top:6px; line-height:1}
  .card.sec .v{color:var(--crit)} .card.ver .v{color:var(--med)} .card.bp .v{color:var(--muted)}

  h2{font-size:13px; letter-spacing:.08em; text-transform:uppercase; color:var(--muted);
     margin:0 0 14px; font-weight:650}

  ol.findings{list-style:none; margin:0 0 40px; padding:0; display:flex; flex-direction:column; gap:10px}
  li.f{
    background:var(--panel); border:1px solid var(--line); border-radius:11px;
    padding:14px 16px 14px 16px; box-shadow:var(--shadow); position:relative; overflow:hidden;
  }
  li.f::before{content:""; position:absolute; left:0; top:0; bottom:0; width:4px; background:var(--info)}
  li.f.crit::before{background:var(--crit)} li.f.high::before{background:var(--high)}
  li.f.med::before{background:var(--med)} li.f.low::before{background:var(--low)}
  .f .row1{display:flex; align-items:center; gap:10px; flex-wrap:wrap}
  .rank{color:var(--muted); font-weight:650; font-size:13px; min-width:1.6em}
  .badge{font-size:11px; font-weight:700; letter-spacing:.03em; padding:3px 8px; border-radius:999px;
         text-transform:uppercase}
  .badge.crit{color:var(--crit);background:var(--crit-bg)} .badge.high{color:var(--high);background:var(--high-bg)}
  .badge.med{color:var(--med);background:var(--med-bg)} .badge.low{color:var(--low);background:var(--low-bg)}
  .badge.info{color:var(--info);background:var(--info-bg)}
  .cat{font-size:12px; color:var(--muted)}
  .path{font-size:12.5px; color:var(--accent); margin-left:auto; word-break:break-all}
  .f .msg{margin:9px 0 0; color:var(--ink)}
  .f .explain{margin:10px 0 0; padding:10px 12px; border-radius:8px; background:var(--info-bg);
              font-size:13.5px; color:var(--ink)}
  .f .explain b{color:var(--accent)}

  .dirs{display:flex; flex-direction:column; gap:9px; margin-bottom:20px}
  .dir{display:grid; grid-template-columns:1fr auto; gap:10px 14px; align-items:center}
  .dir .lbl{font-size:13px}
  .dir .bar{grid-column:1/2; height:8px; border-radius:6px; background:var(--info); opacity:.9}
  .dir.crit .bar{background:var(--crit)} .dir.high .bar{background:var(--high)}
  .dir.med .bar{background:var(--med)} .dir.low .bar{background:var(--low)}
  .dir .cnt{grid-column:2/3; grid-row:1/3; color:var(--muted); font-weight:650; font-size:14px}
  .dir .track{grid-column:1/2; background:var(--line); border-radius:6px; height:8px; overflow:hidden}

  footer{margin-top:44px; padding-top:18px; border-top:1px solid var(--line);
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
  </header>

  <div class="verdict {{.VerdictClass}}"><span class="dot"></span><p>{{.Verdict}}</p></div>

  <div class="cards">
    <div class="card"><div class="k">Total</div><div class="v num">{{.Total}}</div></div>
    <div class="card sec"><div class="k">Security</div><div class="v num">{{.Security}}</div></div>
    <div class="card ver"><div class="k">Version</div><div class="v num">{{.Version}}</div></div>
    <div class="card bp"><div class="k">Best-practice</div><div class="v num">{{.BestPractice}}</div></div>
  </div>

  {{if .Findings}}
  <h2>Fix these first</h2>
  <ol class="findings">
    {{range .Findings}}
    <li class="f {{.SevClass}}">
      <div class="row1">
        <span class="rank num">{{.Rank}}</span>
        <span class="badge {{.SevClass}}">{{.Severity}}</span>
        <span class="cat">{{.Category}}</span>
        <span class="path mono">{{.File}}</span>
      </div>
      <p class="msg">{{.Message}}</p>
      {{if .Explain}}<div class="explain"><b>Fix &middot;</b> {{.Explain}}</div>{{end}}
    </li>
    {{end}}
  </ol>

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
  {{else}}
  <div class="clean">✓ No findings — this repo looks healthy.</div>
  {{end}}

  <footer>
    <span class="tf">tfforge</span>
    <span>· deterministic audit, no LLM tokens{{if .Enriched}} (findings AI-explained on request){{end}}</span>
  </footer>
</div>
<script>
// Respect an explicit theme toggle if a host ever stamps data-theme; otherwise
// the OS preference (prefers-color-scheme) drives the palette. No-op standalone.
</script>
</body>
</html>
`
