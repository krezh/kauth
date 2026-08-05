package handlers

import (
	"fmt"
	"html/template"
	"time"
)

var dashboardTemplate = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"short": func(value string) string {
		if len(value) > 10 {
			return value[:10]
		}
		return value
	},
	"when": func(value time.Time) string {
		if value.IsZero() {
			return "Never"
		}
		return value.UTC().Format("2006-01-02 15:04:05Z")
	},
	"duration": func(value time.Duration) string {
		if value < time.Millisecond {
			return "<1ms"
		}
		return value.Round(time.Millisecond).String()
	},
	"bytes": func(value int64) string {
		if value < 1024 {
			return fmt.Sprintf("%d B", value)
		}
		if value < 1024*1024 {
			return fmt.Sprintf("%.1f KiB", float64(value)/1024)
		}
		return fmt.Sprintf("%.1f MiB", float64(value)/(1024*1024))
	},
	"statusClass": func(status int) string {
		if status >= 500 {
			return "error"
		}
		if status >= 400 {
			return "warn"
		}
		return "ok"
	},
	"phaseClass": func(phase string) string {
		switch phase {
		case "Active":
			return "ok"
		case "Pending":
			return "warn"
		case "Revoked", "Expired":
			return "error"
		default:
			return "muted"
		}
	},
}).Parse(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · kauth</title>
<style>
:root{color-scheme:dark;--font-mono:ui-monospace,"Cascadia Code","SF Mono",Menlo,monospace;--bg:#0c0c0d;--panel:#0e0e0e;--panel-2:#151515;--border:#242424;--fg:#f0efec;--muted:#7a7a7a;--accent:#e8863f;--ok:#6fae5a;--warn:#d9a441;--error:#d9544f}*{box-sizing:border-box}html,body{height:100%;margin:0;background:var(--bg);color:var(--fg);font-family:"Rubik",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;font-size:13px;line-height:1.45}a{color:inherit;text-decoration:none}button{font:inherit}.app{display:flex;flex-direction:column;height:100dvh;overflow:hidden}.topbar{display:flex;align-items:center;gap:.85rem;padding:.5rem .9rem;background:var(--panel);border-bottom:1px solid var(--border);box-shadow:0 4px 10px -4px rgba(0,0,0,.55);z-index:3}.brand{font-weight:800;text-transform:uppercase;letter-spacing:.16em;font-size:1.05rem;color:var(--accent)}.cluster-chip{padding-left:.85rem;border-left:1px solid var(--border);color:var(--muted);font-family:var(--font-mono);font-size:.78rem}.account{margin-left:auto;display:flex;align-items:center;gap:.7rem;padding-left:.85rem;border-left:1px solid var(--border)}.identity{color:var(--muted)}.role{color:var(--accent);font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em}.act{background:var(--panel-2);border:1px solid var(--border);border-radius:0;color:var(--fg);padding:.25rem .6rem;cursor:pointer;font-size:.82rem}.act:hover{border-color:var(--accent)}.body{flex:1;display:flex;min-height:0;overflow:hidden}.sidebar{width:230px;flex:0 0 auto;background:var(--panel);border-right:1px solid var(--border);padding:0 0 .5rem;overflow:auto}.sidebar-section{display:flex;align-items:center;gap:.55rem;padding:.85rem .75rem .4rem;color:var(--muted);font-size:.62rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase}.sidebar-section:after{content:"";height:1px;flex:1;background:var(--border)}.nav-item{display:flex;align-items:center;min-height:2.05rem;margin:0 .45rem .2rem;padding:.4rem .75rem;border:1px solid transparent;border-left-width:2px;background:color-mix(in srgb,var(--panel-2) 42%,transparent);color:var(--muted);font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em}.nav-item:hover{color:var(--fg);border-color:var(--border);background:var(--panel-2)}.nav-item.active{color:var(--accent);border-color:var(--border);border-left-color:var(--accent);background:color-mix(in srgb,var(--accent) 8%,var(--panel-2))}.nav-count{margin-left:auto;min-width:1.7rem;padding:.05rem .3rem;border:1px solid var(--border);background:var(--bg);color:var(--muted);font:400 .66rem/1.25 var(--font-mono);text-align:center}.side-kv{display:flex;justify-content:space-between;margin:0 .75rem;padding:.3rem 0;border-bottom:1px solid var(--border);font-size:.75rem}.side-kv span{color:var(--muted)}.side-kv b{font-family:var(--font-mono);font-weight:600}.main{flex:1;min-width:0;overflow:auto}.view-head{display:flex;align-items:center;gap:.8rem;padding:.65rem .9rem;position:sticky;top:0;background:var(--bg);border-bottom:1px solid transparent;z-index:2}.view-title{margin:0;font-size:1.05rem}.count{color:var(--muted);font-size:.8rem}.scope{margin-left:auto;color:var(--muted);font-size:.72rem}.stat-strip{display:flex;flex-wrap:wrap;gap:.5rem;margin:.2rem .9rem .65rem}.strip-seg{position:relative;display:flex;align-items:center;gap:.55rem;flex:1 1 9rem;max-width:12rem;height:2.8rem;padding:0 .8rem 3px;background:var(--panel);border:1px solid var(--border);box-shadow:0 4px 10px -7px rgba(0,0,0,.55)}.strip-lbl{font-size:.68rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}.strip-val{margin-left:auto;font:600 1.08rem var(--font-mono);font-variant-numeric:tabular-nums}.strip-share{position:absolute;left:0;bottom:0;height:3px;background:var(--accent)}.strip-seg.ok .strip-val,.status-ok{color:var(--ok)}.strip-seg.warn .strip-val,.status-warn{color:var(--warn)}.strip-seg.error .strip-val,.status-error{color:var(--error)}.table-wrap{margin:0 .9rem .9rem;background:var(--panel);border:1px solid var(--border);box-shadow:0 6px 14px -6px rgba(0,0,0,.5);overflow:auto}.data-table{width:100%;border-collapse:collapse;font-family:var(--font-mono);font-variant-numeric:tabular-nums}.data-table th{position:sticky;top:0;background:color-mix(in srgb,var(--panel) 82%,transparent);backdrop-filter:blur(10px);color:var(--muted);font-size:.68rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;text-align:left;padding:.5rem .75rem;border-bottom:1px solid var(--border)}.data-table td{height:2.35rem;padding:.35rem .75rem;border-bottom:1px solid var(--border);white-space:nowrap}.data-table tbody tr:hover td{background:color-mix(in srgb,var(--accent) 10%,transparent)}.data-table tbody tr:last-child td{border-bottom:0}.session-link{color:var(--accent);font-weight:600}.user-cell{font-family:"Rubik",ui-sans-serif,system-ui,sans-serif;font-weight:600}.pill{display:inline-block;padding:.14rem .5rem;border-radius:0;background:var(--panel-2);font-family:"Rubik",ui-sans-serif,system-ui,sans-serif;font-size:.75rem;font-weight:700}.pill.ok{background:var(--ok);color:var(--bg)}.pill.warn{background:var(--warn);color:var(--bg)}.pill.error{background:var(--error);color:#fff}.cell-muted{color:var(--muted)}.empty{padding:2rem;color:var(--muted)}.detail-stats{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));margin:0 .9rem .65rem;border:1px solid var(--border);background:color-mix(in srgb,var(--panel-2) 58%,transparent)}.detail-stat{padding:.65rem .75rem;border-right:1px solid var(--border)}.detail-stat:last-child{border-right:0}.detail-stat-label{color:color-mix(in srgb,var(--accent) 58%,var(--muted));font-size:.68rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}.detail-stat-value{margin-top:.18rem;font-family:var(--font-mono);font-size:.9rem;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}.section{margin:1rem .9rem .4rem;color:var(--muted);font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em}.request-method{color:var(--accent);font-weight:700}.path{max-width:48rem;overflow:hidden;text-overflow:ellipsis}.pager{display:flex;justify-content:flex-end;gap:.4rem;margin:0 .9rem .9rem}.pager a{background:var(--panel-2);border:1px solid var(--border);padding:.3rem .65rem;color:var(--muted)}.pager a:hover{color:var(--accent);border-color:var(--accent)}
@media(max-width:760px){html,body{font-size:16px}.sidebar{display:none}.topbar{gap:.5rem;padding:.5rem .7rem}.cluster-chip{display:none}.identity{max-width:42vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.view-head{padding:.6rem .7rem}.stat-strip{margin:.2rem .6rem .6rem;display:grid;grid-template-columns:1fr 1fr}.strip-seg{max-width:none;min-width:0}.table-wrap{margin:0 .6rem .6rem}.detail-stats{margin:0 .6rem .6rem;grid-template-columns:1fr 1fr}.detail-stat:nth-child(2){border-right:0}.detail-stat:nth-child(-n+2){border-bottom:1px solid var(--border)}.section{margin-left:.6rem}.data-table{font-size:.78rem}.data-table th,.data-table td{padding:.45rem .55rem}.path{max-width:16rem}.scope{display:none}}
</style>
</head>
<body>
<div class="app">
  <header class="topbar">
    <a class="brand" href="/">kauth</a>
    <span class="cluster-chip">{{.Cluster}}</span>
    <div class="account">
      <span class="identity">{{.Email}}</span>
      {{if .Admin}}<span class="role">admin</span>{{end}}
      <form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="act">Sign out</button></form>
    </div>
  </header>
  <div class="body">
    <aside class="sidebar">
      <div class="sidebar-section">Access</div>
      {{template "nav-summary" .}}
      <div class="sidebar-section">Scope</div>
      <div class="side-kv"><span>Cluster</span><b>{{.Cluster}}</b></div>
      <div class="side-kv"><span>Window</span><b>{{if .Detail}}30d{{else}}24h{{end}}</b></div>
    </aside>
    <main class="main">
      <div class="view-head">
        <h1 class="view-title">{{if .Detail}}Session / {{short .Detail.SessionID}}{{else}}{{if .Admin}}All sessions{{else}}Your sessions{{end}}{{end}}</h1>
        {{template "view-count" .}}
        <span class="scope">Kubernetes access telemetry</span>
      </div>
      {{template "stat-strip" .}}
      {{if .Detail}}
      {{template "detail-stats" .}}
      <div class="section">API request history</div>
      <div class="table-wrap">
        <table class="data-table"><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Latency</th><th>Bytes</th></tr></thead>{{template "events-tbody" .}}</table>
      </div>
      <div class="pager">{{if gt .Page 1}}<a href="?page={{.PreviousPage}}">Previous</a>{{end}}{{if .HasNext}}<a href="?page={{.NextPage}}">Next</a>{{end}}</div>
      {{else}}
      <div class="table-wrap">
        <table class="data-table"><thead><tr><th>Session</th><th>User</th><th>State</th><th>Created</th><th>Last used</th></tr></thead>{{template "sessions-tbody" .}}</table>
      </div>
      {{end}}
    </main>
  </div>
</div>
<script src="/static/dashboard-sse.js"></script>
</body>
</html>
{{define "nav-summary"}}<div id="nav-summary"><a class="nav-item active" href="/">Sessions <span class="nav-count">{{len .Sessions}}</span></a><div class="sidebar-section">Telemetry</div><div class="side-kv"><span>Requests</span><b>{{.Metrics.Requests}}</b></div><div class="side-kv"><span>4xx</span><b class="status-warn">{{.Metrics.ClientErrors}}</b></div><div class="side-kv"><span>5xx</span><b class="status-error">{{.Metrics.ServerErrors}}</b></div><div class="side-kv"><span>P95</span><b>{{duration .Metrics.P95}}</b></div></div>{{end}}
{{define "view-count"}}<span id="view-count" class="count">{{if .Detail}}{{.Detail.Email}}{{else}}{{len .Sessions}} total{{end}}</span>{{end}}
{{define "stat-strip"}}<div id="stat-strip" class="stat-strip"><div class="strip-seg ok"><span class="strip-lbl">Active</span><strong class="strip-val">{{.ActiveSessions}}</strong><i class="strip-share" style="width:100%"></i></div><div class="strip-seg"><span class="strip-lbl">Requests</span><strong class="strip-val">{{.Metrics.Requests}}</strong><i class="strip-share" style="width:72%"></i></div><div class="strip-seg warn"><span class="strip-lbl">4xx</span><strong class="strip-val">{{.Metrics.ClientErrors}}</strong><i class="strip-share" style="width:38%;background:var(--warn)"></i></div><div class="strip-seg error"><span class="strip-lbl">5xx</span><strong class="strip-val">{{.Metrics.ServerErrors}}</strong><i class="strip-share" style="width:12%;background:var(--error)"></i></div><div class="strip-seg"><span class="strip-lbl">P95</span><strong class="strip-val">{{duration .Metrics.P95}}</strong><i class="strip-share" style="width:44%"></i></div><div class="strip-seg"><span class="strip-lbl">Traffic</span><strong class="strip-val">{{bytes .Metrics.ResponseBytes}}</strong><i class="strip-share" style="width:58%"></i></div></div>{{end}}
{{define "detail-stats"}}<div id="detail-stats" class="detail-stats"><div class="detail-stat"><div class="detail-stat-label">Identity</div><div class="detail-stat-value">{{.Detail.Email}}</div></div><div class="detail-stat"><div class="detail-stat-label">State</div><div class="detail-stat-value"><span class="pill {{phaseClass .Detail.Phase}}">{{.Detail.Phase}}</span></div></div><div class="detail-stat"><div class="detail-stat-label">Created</div><div class="detail-stat-value">{{when .Detail.CreatedAt}}</div></div><div class="detail-stat"><div class="detail-stat-label">Last used</div><div class="detail-stat-value">{{when .Detail.LastUsed}}</div></div></div>{{end}}
{{define "events-tbody"}}<tbody id="events-tbody">{{if .Events}}{{range .Events}}<tr><td class="cell-muted">{{when .OccurredAt}}</td><td class="request-method">{{.Method}}</td><td class="path">{{.Path}}</td><td class="status-{{statusClass .StatusCode}}">{{.StatusCode}}</td><td>{{duration .Duration}}</td><td>{{bytes .ResponseBytes}}</td></tr>{{end}}{{else}}<tr><td colspan="6" class="empty">No API requests recorded for this session.</td></tr>{{end}}</tbody>{{end}}
{{define "sessions-tbody"}}<tbody id="sessions-tbody">{{if .Sessions}}{{range .Sessions}}<tr><td><a class="session-link" href="/sessions/{{urlquery .SessionID}}">{{short .SessionID}}</a></td><td class="user-cell">{{.Email}}</td><td><span class="pill {{phaseClass .Phase}}">{{.Phase}}</span></td><td class="cell-muted">{{when .CreatedAt}}</td><td class="cell-muted">{{when .LastUsed}}</td></tr>{{end}}{{else}}<tr><td colspan="5" class="empty">No sessions found.</td></tr>{{end}}</tbody>{{end}}`))
