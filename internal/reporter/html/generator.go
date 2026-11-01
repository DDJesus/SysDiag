package html

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/systemdiag/sysdiag/internal/models"
)

// Reporter exports self-contained single-file HTML reports.
type Reporter struct {
	tmpl *template.Template
}

type templateData struct {
	Report                     *models.DiagnosticReport
	CriticalCount              int
	WarningCount               int
	InfoCount                  int
	CoveragePercent            float64
	UptimeHours                float64
	TotalRAMGB                 float64
	AvailRAMGB                 float64
	CommitTotalGB              float64
	CommitLimitGB              float64
	HighConfidenceObservations []models.Finding
	DegradedProbesCount        int
}

// NewReporter instantiates an HTML report generator with embedded assets.
func NewReporter() (*Reporter, error) {
	funcs := template.FuncMap{
		"toGB": func(b uint64) string {
			return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
		},
		"toMB": func(b uint64) string {
			return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
		},
		"join": func(s []string, sep string) string {
			return strings.Join(s, sep)
		},
	}
	t, err := template.New("sysdiag_report").Funcs(funcs).Parse(reportTemplate)
	if err != nil {
		return nil, err
	}
	return &Reporter{tmpl: t}, nil
}

func (r *Reporter) Name() string {
	return "html"
}

func (r *Reporter) Generate(report *models.DiagnosticReport, w io.Writer) error {
	data := templateData{
		Report: report,
	}

	for _, f := range report.Findings {
		switch f.Severity {
		case models.SeverityCritical:
			data.CriticalCount++
		case models.SeverityWarning:
			data.WarningCount++
		case models.SeverityInfo:
			data.InfoCount++
		}
		if f.Confidence == models.ConfidenceHigh {
			data.HighConfidenceObservations = append(data.HighConfidenceObservations, f)
		}
	}

	if report.CollectionStatus.TotalProbes > 0 {
		data.CoveragePercent = (float64(report.CollectionStatus.Successful) / float64(report.CollectionStatus.TotalProbes)) * 100.0
	}

	data.DegradedProbesCount = report.CollectionStatus.RequiresAdmin +
		report.CollectionStatus.Failed +
		report.CollectionStatus.Timeout +
		report.CollectionStatus.Canceled +
		report.CollectionStatus.Skipped +
		report.CollectionStatus.Unsupported +
		report.CollectionStatus.Partial

	if report.Data.System != nil {
		data.UptimeHours = float64(report.Data.System.UptimeSeconds) / 3600.0
	}

	if report.Data.Memory != nil {
		data.TotalRAMGB = float64(report.Data.Memory.TotalBytes) / (1024 * 1024 * 1024)
		data.AvailRAMGB = float64(report.Data.Memory.AvailableBytes) / (1024 * 1024 * 1024)
		data.CommitTotalGB = float64(report.Data.Memory.CommitTotalBytes) / (1024 * 1024 * 1024)
		data.CommitLimitGB = float64(report.Data.Memory.CommitLimitBytes) / (1024 * 1024 * 1024)
	}

	return r.tmpl.Execute(w, data)
}

const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>sysdiag Diagnostic Report - {{.Report.Metadata.Hostname}}</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --bg-elevated: #334155;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --border-subtle: rgba(148, 163, 184, 0.15);
            --critical: #ef4444;
            --critical-bg: rgba(239, 68, 68, 0.12);
            --warning: #f59e0b;
            --warning-bg: rgba(245, 158, 11, 0.12);
            --info: #38bdf8;
            --info-bg: rgba(56, 189, 248, 0.12);
            --success: #10b981;
            --success-bg: rgba(16, 185, 129, 0.12);
            --accent: #6366f1;
            --accent-bg: rgba(99, 102, 241, 0.15);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
        body { background-color: var(--bg-primary); color: var(--text-primary); padding: 2rem; line-height: 1.5; }
        .container { max-width: 1200px; margin: 0 auto; }
        
        /* Banner & Header */
        .handover-banner {
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(16, 185, 129, 0.15) 100%);
            border: 1px solid rgba(99, 102, 241, 0.4);
            border-radius: 0.75rem;
            padding: 1.25rem 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1.5rem;
            flex-wrap: wrap;
        }
        .handover-title { font-size: 1.05rem; font-weight: 700; color: #a5b4fc; display: flex; align-items: center; gap: 0.5rem; }
        .handover-desc { font-size: 0.9rem; color: var(--text-primary); margin-top: 0.25rem; }
        .readonly-tag {
            background-color: rgba(16, 185, 129, 0.2);
            border: 1px solid var(--success);
            color: var(--success);
            padding: 0.35rem 0.75rem;
            border-radius: 0.5rem;
            font-size: 0.8rem;
            font-weight: 600;
            white-space: nowrap;
        }

        header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
        h1 { font-size: 1.75rem; font-weight: 700; letter-spacing: -0.02em; }
        .badge { display: inline-block; padding: 0.25rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .badge-critical { background-color: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }
        .badge-warning { background-color: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning); }
        .badge-info { background-color: var(--info-bg); color: var(--info); border: 1px solid var(--info); }
        .badge-success { background-color: var(--success-bg); color: var(--success); border: 1px solid var(--success); }

        /* Dashboard Grid */
        .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background-color: var(--bg-secondary); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.25rem; text-align: center; }
        .stat-card .val { font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }
        .stat-card .lbl { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

        .section-title { font-size: 1.25rem; font-weight: 600; margin: 2rem 0 1rem; display: flex; align-items: center; justify-content: space-between; }
        .card { background-color: var(--bg-secondary); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.25rem; margin-bottom: 1rem; }

        /* Highlights & Degraded Probes */
        .highlight-item { padding: 0.5rem 0; border-bottom: 1px solid var(--border-subtle); display: flex; align-items: baseline; gap: 0.75rem; font-size: 0.95rem; }
        .highlight-item:last-child { border-bottom: none; }

        /* Findings Filter & Cards */
        .filter-bar { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
        .filter-btn {
            background-color: var(--bg-elevated);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 0.35rem 0.85rem;
            border-radius: 0.375rem;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .filter-btn:hover { background-color: var(--accent); color: white; }
        .filter-btn.active { background-color: var(--accent); border-color: var(--accent); color: white; }

        .finding-card { border-left: 4px solid var(--accent); transition: all 0.2s ease; }
        .finding-card.CRITICAL { border-left-color: var(--critical); }
        .finding-card.WARNING { border-left-color: var(--warning); }
        .finding-card.INFO { border-left-color: var(--info); }
        .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.5rem; }
        .finding-title { font-size: 1.1rem; font-weight: 600; }
        .finding-body { font-size: 0.95rem; color: var(--text-muted); margin-bottom: 0.75rem; }
        .finding-body strong { color: var(--text-primary); }
        .finding-meta { display: flex; gap: 1rem; font-size: 0.85rem; margin-bottom: 0.5rem; flex-wrap: wrap; }
        .meta-item { display: flex; gap: 0.25rem; }
        .meta-label { color: var(--text-muted); }
        .evidence-drawer { margin-top: 0.75rem; border-top: 1px solid var(--border-subtle); padding-top: 0.75rem; }
        details summary { cursor: pointer; color: var(--accent); font-size: 0.85rem; font-weight: 600; outline: none; }
        details summary:hover { color: #a5b4fc; }
        .evidence-table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; font-size: 0.85rem; }
        .evidence-table th, .evidence-table td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border); }
        .evidence-table th { color: var(--text-muted); width: 35%; }

        /* Search input */
        .search-container { margin-bottom: 1.5rem; }
        .search-input {
            width: 100%;
            background-color: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            padding: 0.75rem 1rem;
            color: var(--text-primary);
            font-size: 0.95rem;
            outline: none;
            transition: border-color 0.15s ease;
        }
        .search-input:focus { border-color: var(--accent); }

        /* Subsystems Telemetry Grid */
        .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
        .metric-item { display: flex; justify-content: space-between; padding: 0.45rem 0; border-bottom: 1px solid var(--border-subtle); font-size: 0.9rem; }
        .metric-item:last-child { border-bottom: none; }
        .metric-item .name { color: var(--text-muted); }
        .metric-item .val { font-weight: 600; }

        /* Data Tables */
        .data-table-container { overflow-x: auto; margin-top: 0.5rem; }
        .data-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; text-align: left; }
        .data-table th, .data-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); }
        .data-table th { color: var(--text-muted); background-color: rgba(255, 255, 255, 0.02); font-weight: 600; }
        .data-table tr:hover td { background-color: rgba(255, 255, 255, 0.03); }

        /* Limitations */
        .limitation-item { background-color: rgba(245, 158, 11, 0.06); border: 1px solid var(--warning); border-radius: 0.375rem; padding: 0.75rem; margin-bottom: 0.5rem; font-size: 0.9rem; }
        footer { margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1rem; font-size: 0.8rem; color: var(--text-muted); text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Delivery Handover Banner (Mom Test) -->
        <div class="handover-banner">
            <div>
                <div class="handover-title">
                    <span>📄 Send This File to Support / Systems Engineering</span>
                </div>
                <div class="handover-desc">
                    This standalone HTML file contains complete empirical diagnostic telemetry and evidence-backed observations for <strong>{{.Report.Metadata.Hostname}}</strong>.
                </div>
            </div>
            <div class="readonly-tag">
                ✓ Safe &amp; Read-Only (0 Changes Made)
            </div>
        </div>

        <header>
            <div>
                <h1>sysdiag Diagnostic Report</h1>
                <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem;">
                    Host: <strong>{{.Report.Metadata.Hostname}}</strong> &bull; OS: <strong>{{.Report.Metadata.OSVersion}} ({{.Report.Metadata.Architecture}})</strong> &bull; Profile: <strong>{{.Report.Metadata.Profile}}</strong>
                </p>
            </div>
            <div>
                <span class="badge {{if .Report.Metadata.IsElevated}}badge-critical{{else}}badge-info{{end}}">
                    Privilege: {{.Report.Metadata.PrivilegeLevel}}
                </span>
            </div>
        </header>

        <!-- Executive Summary & Findings Dashboard -->
        <h2 class="section-title">Executive Summary &amp; Findings Dashboard</h2>
        <div class="dashboard-grid">
            <div class="stat-card">
                <div class="lbl">Critical Findings</div>
                <div class="val" style="color: var(--critical);">{{.CriticalCount}}</div>
            </div>
            <div class="stat-card">
                <div class="lbl">Warning Findings</div>
                <div class="val" style="color: var(--warning);">{{.WarningCount}}</div>
            </div>
            <div class="stat-card">
                <div class="lbl">Info Findings</div>
                <div class="val" style="color: var(--info);">{{.InfoCount}}</div>
            </div>
            <div class="stat-card">
                <div class="lbl">Collection Coverage</div>
                <div class="val" style="color: var(--success);">{{printf "%.0f" .CoveragePercent}}%</div>
            </div>
            <div class="stat-card">
                <div class="lbl">Probes Executed</div>
                <div class="val">{{.Report.CollectionStatus.Successful}} / {{.Report.CollectionStatus.TotalProbes}}</div>
            </div>
        </div>

        <!-- Highest-Confidence Observations -->
        {{if gt (len .HighConfidenceObservations) 0}}
        <div class="card" style="border-left: 4px solid var(--accent);">
            <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: #a5b4fc;">Highest-Confidence Diagnostic Observations</h3>
            {{range .HighConfidenceObservations}}
            <div class="highlight-item">
                <span class="badge badge-{{if eq .Severity "CRITICAL"}}critical{{else if eq .Severity "WARNING"}}warning{{else}}info{{end}}">{{.Severity}}</span>
                <span><strong>{{.Title}}:</strong> {{.Observation}}</span>
            </div>
            {{end}}
        </div>
        {{end}}

        <!-- Degraded / Unprivileged Probes Callout -->
        {{if gt .DegradedProbesCount 0}}
        <div class="card" style="border-left: 4px solid var(--warning);">
            <h3 style="font-size: 1rem; margin-bottom: 0.5rem; color: var(--warning);">Collection Coverage Notes</h3>
            <p style="font-size: 0.9rem; color: var(--text-muted);">
                {{if gt .Report.CollectionStatus.RequiresAdmin 0}}* {{.Report.CollectionStatus.RequiresAdmin}} probe(s) required elevated Administrator privileges to query full telemetry. {{end}}
                {{if gt .Report.CollectionStatus.Partial 0}}* {{.Report.CollectionStatus.Partial}} probe(s) returned partial results. {{end}}
                {{if gt .Report.CollectionStatus.Timeout 0}}* {{.Report.CollectionStatus.Timeout}} probe(s) timed out. {{end}}
                {{if gt .Report.CollectionStatus.Canceled 0}}* {{.Report.CollectionStatus.Canceled}} probe(s) canceled during collection. {{end}}
                {{if gt .Report.CollectionStatus.Skipped 0}}* {{.Report.CollectionStatus.Skipped}} probe(s) were not started after cancellation. {{end}}
                {{if gt .Report.CollectionStatus.Failed 0}}* {{.Report.CollectionStatus.Failed}} probe(s) encountered execution errors. {{end}}
            </p>
        </div>
        {{end}}

        <!-- Detected Findings & Interactive Filter -->
        <div class="section-title">
            <span>Traceable Findings &amp; Evidence ({{len .Report.Findings}})</span>
        </div>

        {{if eq (len .Report.Findings) 0}}
            <div class="card" style="border-left: 4px solid var(--success);">
                <div style="color: var(--success); font-weight: 600;">No Anomalies Identified</div>
                <p style="color: var(--text-muted); font-size: 0.95rem; margin-top: 0.25rem;">
                    All analyzed subsystems are operating within nominal empirical thresholds.
                </p>
            </div>
        {{else}}
            <div class="filter-bar">
                <button class="filter-btn active" onclick="filterFindings('ALL')">All ({{len .Report.Findings}})</button>
                <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical ({{.CriticalCount}})</button>
                <button class="filter-btn" onclick="filterFindings('WARNING')">Warning ({{.WarningCount}})</button>
                <button class="filter-btn" onclick="filterFindings('INFO')">Info ({{.InfoCount}})</button>
            </div>

            <div id="findings-container">
            {{range .Report.Findings}}
            <div class="card finding-card {{.Severity}}" data-severity="{{.Severity}}">
                <div class="finding-header">
                    <div class="finding-title">{{.Title}}</div>
                    <span class="badge badge-{{if eq .Severity "CRITICAL"}}critical{{else if eq .Severity "WARNING"}}warning{{else}}info{{end}}">
                        {{.Severity}}
                    </span>
                </div>
                <div class="finding-meta">
                    <div class="meta-item"><span class="meta-label">ID:</span> {{.ID}}</div>
                    <div class="meta-item"><span class="meta-label">Category:</span> {{.Category}}</div>
                    <div class="meta-item"><span class="meta-label">Confidence:</span> {{.Confidence}}</div>
                </div>
                <div class="finding-body">
                    <p><strong>Observation:</strong> {{.Observation}}</p>
                    <p style="margin-top: 0.25rem;"><strong>Interpretation:</strong> {{.Interpretation}}</p>
                    <p style="margin-top: 0.25rem;"><strong>Impact:</strong> {{.PotentialImpact}}</p>
                    <p style="margin-top: 0.25rem; color: var(--text-primary);"><strong>Recommendation:</strong> {{.Recommendation}}</p>
                </div>
                <div class="evidence-drawer">
                    <details>
                        <summary>View Measured Evidence Citation ({{len .Evidence}} data points)</summary>
                        <table class="evidence-table">
                            <thead>
                                <tr>
                                    <th>Measurement</th>
                                    <th>Observed Value</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{range $k, $v := .Evidence}}
                                <tr>
                                    <td><code>{{$k}}</code></td>
                                    <td><strong>{{$v}}</strong></td>
                                </tr>
                                {{end}}
                            </tbody>
                        </table>
                    </details>
                </div>
            </div>
            {{end}}
            </div>
        {{end}}

        <!-- Searchable Subsystem Telemetry -->
        <h2 class="section-title">Subsystem Metric Telemetry</h2>
        <div class="search-container">
            <input type="text" id="telemetry-search" class="search-input" placeholder="Quick search telemetry (e.g. process name, drive, error, adapter, runtime)..." onkeyup="filterTelemetry()">
        </div>

        <div class="metric-grid" id="telemetry-grid">
            <!-- System / OS -->
            {{if .Report.Data.System}}
            <div class="card telemetry-card">
                <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: var(--info);">System &amp; Platform</h3>
                <div class="metric-item"><span class="name">OS Name</span><span class="val">{{.Report.Data.System.OSName}}</span></div>
                <div class="metric-item"><span class="name">OS Build</span><span class="val">{{.Report.Data.System.OSBuild}}</span></div>
                <div class="metric-item"><span class="name">Architecture</span><span class="val">{{.Report.Data.System.Architecture}}</span></div>
                <div class="metric-item"><span class="name">Uptime</span><span class="val">{{printf "%.1f" .UptimeHours}} hours</span></div>
                <div class="metric-item"><span class="name">Platform</span><span class="val">{{if .Report.Data.System.Virtualization.IsVirtual}}Virtual ({{.Report.Data.System.Virtualization.Hypervisor}}){{else}}Physical Hardware{{end}}</span></div>
            </div>
            {{end}}

            <!-- CPU -->
            {{if .Report.Data.CPU}}
            <div class="card telemetry-card">
                <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: var(--info);">CPU &amp; Processing</h3>
                <div class="metric-item"><span class="name">Processor</span><span class="val">{{.Report.Data.CPU.Model}}</span></div>
                <div class="metric-item"><span class="name">Topology</span><span class="val">{{.Report.Data.CPU.PhysicalCores}} Physical / {{.Report.Data.CPU.LogicalCores}} Logical</span></div>
                <div class="metric-item"><span class="name">Total Utilization</span><span class="val">{{printf "%.1f" .Report.Data.CPU.UtilizationPercent}}%</span></div>
                <div class="metric-item"><span class="name">User / Kernel</span><span class="val">{{printf "%.1f" .Report.Data.CPU.UserPercent}}% / {{printf "%.1f" .Report.Data.CPU.KernelPercent}}%</span></div>
            </div>
            {{end}}

            <!-- Memory -->
            {{if .Report.Data.Memory}}
            <div class="card telemetry-card">
                <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: var(--info);">Memory &amp; Commit</h3>
                <div class="metric-item"><span class="name">Physical RAM</span><span class="val">{{printf "%.2f" .TotalRAMGB}} GB</span></div>
                <div class="metric-item"><span class="name">Available RAM</span><span class="val">{{printf "%.2f" .AvailRAMGB}} GB</span></div>
                <div class="metric-item"><span class="name">RAM Used %</span><span class="val">{{printf "%.1f" .Report.Data.Memory.UsedPercent}}%</span></div>
                <div class="metric-item"><span class="name">Commit Total / Limit</span><span class="val">{{printf "%.2f" .CommitTotalGB}} / {{printf "%.2f" .CommitLimitGB}} GB</span></div>
                <div class="metric-item"><span class="name">Commit Charge %</span><span class="val">{{printf "%.1f" .Report.Data.Memory.CommitPercent}}%</span></div>
            </div>
            {{end}}

            <!-- Storage -->
            {{if .Report.Data.Storage}}
            <div class="card telemetry-card">
                <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: var(--info);">Storage &amp; Volumes</h3>
                {{range .Report.Data.Storage.Volumes}}
                <div class="metric-item">
                    <span class="name">{{.MountPoint}} {{if .VolumeName}}({{.VolumeName}}){{end}}</span>
                    <span class="val">{{printf "%.1f" .UsedPercent}}% ({{toGB .FreeBytes}} free / {{toGB .TotalBytes}})</span>
                </div>
                {{end}}
                {{range .Report.Data.Storage.PhysicalDisks}}
                <div class="metric-item">
                    <span class="name">{{.DeviceID}} {{if .Model}}({{.Model}}){{end}}</span>
                    <span class="val">{{.BusType}} {{.MediaType}}</span>
                </div>
                {{end}}
            </div>
            {{end}}

            <!-- Network -->
            {{if .Report.Data.Network}}
            <div class="card telemetry-card">
                <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: var(--info);">Network &amp; Adapters</h3>
                {{range .Report.Data.Network.Adapters}}
                <div class="metric-item">
                    <span class="name">{{.Name}} ({{.Status}})</span>
                    <span class="val">{{if .IPv4Addresses}}{{index .IPv4Addresses 0}}{{else}}No IPv4{{end}}{{if .SpeedMbps}} ({{.SpeedMbps}} Mbps){{end}}</span>
                </div>
                {{end}}
                {{if .Report.Data.Network.DNSTest}}
                <div class="metric-item">
                    <span class="name">DNS Latency ({{.Report.Data.Network.DNSTest.QueryTarget}})</span>
                    <span class="val">{{if .Report.Data.Network.DNSTest.Success}}{{printf "%.1f" .Report.Data.Network.DNSTest.DurationMS}} ms{{else}}Failed{{end}}</span>
                </div>
                {{end}}
            </div>
            {{end}}

            <!-- Processes -->
            {{if .Report.Data.Processes}}
            <div class="card telemetry-card">
                <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: var(--info);">Processes &amp; Resources</h3>
                <div class="metric-item"><span class="name">Total Processes</span><span class="val">{{.Report.Data.Processes.TotalProcesses}} ({{.Report.Data.Processes.TotalThreads}} Threads)</span></div>
                {{if .Report.Data.Processes.TopMemory}}
                <div class="metric-item"><span class="name">Top Memory Process</span><span class="val">{{(index .Report.Data.Processes.TopMemory 0).Name}} ({{toMB (index .Report.Data.Processes.TopMemory 0).WorkingSetBytes}})</span></div>
                {{end}}
                {{if .Report.Data.Processes.TopCPU}}
                <div class="metric-item"><span class="name">Top CPU Time Process</span><span class="val">{{(index .Report.Data.Processes.TopCPU 0).Name}} ({{printf "%.1f" (index .Report.Data.Processes.TopCPU 0).CPUTimeSeconds}}s)</span></div>
                {{end}}
            </div>
            {{end}}

            <!-- Services -->
            {{if .Report.Data.Services}}
            <div class="card telemetry-card">
                <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: var(--info);">Services &amp; Daemons</h3>
                <div class="metric-item"><span class="name">Total Services</span><span class="val">{{.Report.Data.Services.TotalCount}}</span></div>
                <div class="metric-item"><span class="name">Running / Stopped</span><span class="val">{{.Report.Data.Services.RunningCount}} / {{.Report.Data.Services.StoppedCount}}</span></div>
                <div class="metric-item"><span class="name">Failed Auto-Start</span><span class="val" {{if gt .Report.Data.Services.FailedAutoStartCount 0}}style="color: var(--critical);"{{end}}>{{.Report.Data.Services.FailedAutoStartCount}}</span></div>
            </div>
            {{end}}

            <!-- Reliability -->
            {{if .Report.Data.Reliability}}
            <div class="card telemetry-card">
                <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: var(--info);">Reliability &amp; Event Logs</h3>
                <div class="metric-item"><span class="name">Log Window</span><span class="val">Last {{.Report.Data.Reliability.TimeWindowHours}} hours</span></div>
                <div class="metric-item"><span class="name">Logged Errors</span><span class="val">{{.Report.Data.Reliability.TotalErrorsLogged}}</span></div>
                <div class="metric-item"><span class="name">App Crashes</span><span class="val" {{if gt (len .Report.Data.Reliability.AppCrashes) 0}}style="color: var(--warning);"{{end}}>{{len .Report.Data.Reliability.AppCrashes}}</span></div>
                <div class="metric-item"><span class="name">BSODs / Dirty Shutdowns</span><span class="val" {{if or (gt (len .Report.Data.Reliability.BugChecks) 0) (gt (len .Report.Data.Reliability.KernelPowerEvents) 0)}}style="color: var(--critical);"{{end}}>{{len .Report.Data.Reliability.BugChecks}} / {{len .Report.Data.Reliability.KernelPowerEvents}}</span></div>
            </div>
            {{end}}

            <!-- Software -->
            {{if .Report.Data.Software}}
            <div class="card telemetry-card">
                <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: var(--info);">Software &amp; Environment</h3>
                <div class="metric-item"><span class="name">Installed Applications</span><span class="val">{{.Report.Data.Software.TotalInstalledApps}}</span></div>
                <div class="metric-item"><span class="name">HotFixes &amp; Updates</span><span class="val">{{len .Report.Data.Software.HotFixes}}</span></div>
                <div class="metric-item"><span class="name">Runtimes Detected</span><span class="val">{{len .Report.Data.Software.Runtimes}}</span></div>
            </div>
            {{end}}
        </div>

        <!-- Detailed Process Table if available -->
        {{if and .Report.Data.Processes (gt (len .Report.Data.Processes.TopMemory) 0)}}
        <div class="card telemetry-card">
            <h3 style="font-size: 1rem; margin-bottom: 0.75rem; color: var(--info);">Top Memory Processes</h3>
            <div class="data-table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>PID</th>
                            <th>Name</th>
                            <th>Working Set</th>
                            <th>Private Bytes</th>
                            <th>Executable Path</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .Report.Data.Processes.TopMemory}}
                        <tr>
                            <td>{{.PID}}</td>
                            <td><strong>{{.Name}}</strong></td>
                            <td>{{toMB .WorkingSetBytes}}</td>
                            <td>{{toMB .PrivateBytes}}</td>
                            <td style="color: var(--text-muted); font-size: 0.8rem;">{{.ExecutablePath}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
        </div>
        {{end}}

        <!-- Collection Limitations -->
        {{if gt (len .Report.Limitations) 0}}
        <h2 class="section-title">Collection Limitations &amp; Privilege Calls</h2>
        <div class="card">
            {{range .Report.Limitations}}
            <div class="limitation-item">
                <strong>[{{.ProbeID}}] ({{.Category}}):</strong> {{.Reason}}
                {{if .PrivilegeRequired}}<span style="color: var(--critical); font-weight: 600;">[Requires {{.PrivilegeRequired}}]</span>{{end}}
            </div>
            {{end}}
        </div>
        {{end}}

        <footer>
            Generated by <strong>sysdiag v{{.Report.Metadata.ToolVersion}}</strong> on {{.Report.Metadata.ScanTimestamp.Format "2006-01-02 15:04:05 UTC"}} &bull; Scan duration: {{.Report.Metadata.ScanDurationMS}} ms
        </footer>
    </div>

    <!-- Embedded Vanilla JS for Zero-Dependency Client-Side Filtering -->
    <script>
        function filterFindings(sev) {
            const cards = document.querySelectorAll('#findings-container .finding-card');
            const btns = document.querySelectorAll('.filter-btn');
            btns.forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            cards.forEach(c => {
                if (sev === 'ALL' || c.getAttribute('data-severity') === sev) {
                    c.style.display = 'block';
                } else {
                    c.style.display = 'none';
                }
            });
        }

        function filterTelemetry() {
            const query = document.getElementById('telemetry-search').value.toLowerCase();
            const cards = document.querySelectorAll('.telemetry-card');
            cards.forEach(card => {
                const text = card.textContent.toLowerCase();
                card.style.display = text.includes(query) ? 'block' : 'none';
            });
        }
    </script>
</body>
</html>`
