package terminal

import (
	"fmt"
	"io"
	"strings"

	"github.com/systemdiag/sysdiag/internal/models"
)

const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

// Reporter renders a formatted ANSI terminal diagnostic summary.
type Reporter struct{}

// NewReporter instantiates a terminal reporter.
func NewReporter() *Reporter {
	return &Reporter{}
}

func (r *Reporter) Name() string {
	return "terminal"
}

func (r *Reporter) Generate(report *models.DiagnosticReport, w io.Writer) error {
	var criticalCount, warningCount, infoCount int
	for _, f := range report.Findings {
		switch f.Severity {
		case models.SeverityCritical:
			criticalCount++
		case models.SeverityWarning:
			warningCount++
		case models.SeverityInfo:
			infoCount++
		}
	}

	coveragePct := 0.0
	if report.CollectionStatus.TotalProbes > 0 {
		coveragePct = (float64(report.CollectionStatus.Successful) / float64(report.CollectionStatus.TotalProbes)) * 100.0
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s%s================================================================================%s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "%s%s   SYSTEM DIAGNOSTIC TOOLKIT (sysdiag) - EXECUTIVE REPORT%s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "%s%s================================================================================%s\n", colorBold, colorCyan, colorReset)

	// Host & Execution Info
	fmt.Fprintf(w, "%sHost:%s %-20s  %sOS:%s %s (%s)\n",
		colorBold, colorReset, report.Metadata.Hostname,
		colorBold, colorReset, report.Metadata.OSVersion, report.Metadata.Architecture)
	fmt.Fprintf(w, "%sProfile:%s %-17s  %sPrivilege:%s %s (Elevated: %v)\n",
		colorBold, colorReset, strings.ToUpper(report.Metadata.Profile),
		colorBold, colorReset, report.Metadata.PrivilegeLevel, report.Metadata.IsElevated)
	fmt.Fprintf(w, "%sScan Time:%s %-15s  %sDuration:%s %d ms\n",
		colorBold, colorReset, report.Metadata.ScanTimestamp.Format("2006-01-02 15:04:05"),
		colorBold, colorReset, report.Metadata.ScanDurationMS)

	// Findings Dashboard & Coverage
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s%s--- FINDINGS DASHBOARD & COVERAGE ---%s\n", colorBold, colorBlue, colorReset)
	fmt.Fprintf(w, "  Critical: %s%d%s  |  Warning: %s%d%s  |  Info: %s%d%s  |  Collection Coverage: %s%.1f%%%s (%d/%d Probes)\n",
		colorRed, criticalCount, colorReset,
		colorYellow, warningCount, colorReset,
		colorCyan, infoCount, colorReset,
		colorGreen, coveragePct, colorReset,
		report.CollectionStatus.Successful, report.CollectionStatus.TotalProbes,
	)

	if report.CollectionStatus.RequiresAdmin > 0 || report.CollectionStatus.Failed > 0 || report.CollectionStatus.Timeout > 0 {
		fmt.Fprintf(w, "  %sDegraded Probes:%s Admin Required: %d | Failed: %d | Timed Out: %d\n",
			colorYellow, colorReset,
			report.CollectionStatus.RequiresAdmin,
			report.CollectionStatus.Failed,
			report.CollectionStatus.Timeout,
		)
	}

	// Subsystem Snapshots
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s%s--- SUBSYSTEM METRICS SNAPSHOT ---%s\n", colorBold, colorBlue, colorReset)

	if report.Data.System != nil {
		sys := report.Data.System
		virtStr := "Physical Hardware"
		if sys.Virtualization.IsVirtual {
			virtStr = fmt.Sprintf("Virtual Machine (%s)", sys.Virtualization.Hypervisor)
		}
		uptimeHours := float64(sys.UptimeSeconds) / 3600.0
		fmt.Fprintf(w, "  %sSystem:%s %s (Build %s) | Uptime: %.1f hrs | Platform: %s\n",
			colorBold, colorReset, sys.OSName, sys.OSBuild, uptimeHours, virtStr)
	}

	if report.Data.CPU != nil {
		cpu := report.Data.CPU
		fmt.Fprintf(w, "  %sCPU:%s    %s (%d Physical / %d Logical Cores) | Total Load: %s%.1f%%%s (User: %.1f%%, Kernel: %.1f%%)\n",
			colorBold, colorReset, cpu.Model, cpu.PhysicalCores, cpu.LogicalCores,
			colorBold, cpu.UtilizationPercent, colorReset, cpu.UserPercent, cpu.KernelPercent)
	}

	if report.Data.Memory != nil {
		mem := report.Data.Memory
		totalGB := float64(mem.TotalBytes) / (1024 * 1024 * 1024)
		availGB := float64(mem.AvailableBytes) / (1024 * 1024 * 1024)
		commitGB := float64(mem.CommitTotalBytes) / (1024 * 1024 * 1024)
		commitLimitGB := float64(mem.CommitLimitBytes) / (1024 * 1024 * 1024)
		fmt.Fprintf(w, "  %sMemory:%s  %.2f GB Total (%.2f GB Available, %.1f%% Used) | Commit Charge: %.2f / %.2f GB (%.1f%%)\n",
			colorBold, colorReset, totalGB, availGB, mem.UsedPercent, commitGB, commitLimitGB, mem.CommitPercent)
	}

	if report.Data.Storage != nil && len(report.Data.Storage.Volumes) > 0 {
		var volSummaries []string
		for _, v := range report.Data.Storage.Volumes {
			if v.TotalBytes > 0 {
				totalGB := float64(v.TotalBytes) / (1024 * 1024 * 1024)
				freeGB := float64(v.FreeBytes) / (1024 * 1024 * 1024)
				volSummaries = append(volSummaries, fmt.Sprintf("%s (%.1f%% used, %.1f/%.1f GB free)", v.MountPoint, v.UsedPercent, freeGB, totalGB))
			}
		}
		if len(volSummaries) > 0 {
			fmt.Fprintf(w, "  %sStorage:%s %s\n", colorBold, colorReset, strings.Join(volSummaries, " | "))
		}
	}

	if report.Data.Network != nil && len(report.Data.Network.Adapters) > 0 {
		var activeAdapters []string
		for _, a := range report.Data.Network.Adapters {
			if a.Status == "Up" && len(a.IPv4Addresses) > 0 {
				speedPart := ""
				if a.SpeedMbps != nil {
					speedPart = fmt.Sprintf(", %d Mbps", *a.SpeedMbps)
				}
				activeAdapters = append(activeAdapters, fmt.Sprintf("%s [%s, %s%s]", a.Name, strings.Join(a.IPv4Addresses, ","), a.Status, speedPart))
			}
		}
		dnsInfo := ""
		if report.Data.Network.DNSTest != nil {
			if report.Data.Network.DNSTest.Success {
				dnsInfo = fmt.Sprintf(" | DNS Latency: %.1f ms", report.Data.Network.DNSTest.DurationMS)
			} else {
				dnsInfo = " | DNS Lookup: Failed"
			}
		}
		if len(activeAdapters) > 0 {
			fmt.Fprintf(w, "  %sNetwork:%s %s%s\n", colorBold, colorReset, strings.Join(activeAdapters, "; "), dnsInfo)
		}
	}

	if report.Data.Processes != nil {
		p := report.Data.Processes
		topMemStr := ""
		if len(p.TopMemory) > 0 {
			m := p.TopMemory[0]
			topMemStr = fmt.Sprintf(" | Top Mem: %s (PID %d, %.1f MB)", m.Name, m.PID, float64(m.WorkingSetBytes)/(1024*1024))
		}
		topCPUStr := ""
		if len(p.TopCPU) > 0 {
			c := p.TopCPU[0]
			topCPUStr = fmt.Sprintf(" | Top CPU: %s (PID %d, %.1fs)", c.Name, c.PID, c.CPUTimeSeconds)
		}
		fmt.Fprintf(w, "  %sProcess:%s %d Running Processes (%d Threads)%s%s\n",
			colorBold, colorReset, p.TotalProcesses, p.TotalThreads, topCPUStr, topMemStr)
	}

	if report.Data.Services != nil {
		s := report.Data.Services
		failedStr := ""
		if s.FailedAutoStartCount > 0 {
			failedStr = fmt.Sprintf(" | %s%d Failed Auto-Start%s", colorRed, s.FailedAutoStartCount, colorReset)
		}
		fmt.Fprintf(w, "  %sService:%s %d Total Services (%d Running, %d Stopped)%s\n",
			colorBold, colorReset, s.TotalCount, s.RunningCount, s.StoppedCount, failedStr)
	}

	if report.Data.Reliability != nil {
		r := report.Data.Reliability
		fmt.Fprintf(w, "  %sReliable:%s %d Crashes, %d BSODs, %d Dirty Shutdowns, %d Logged Errors (Last %dh)\n",
			colorBold, colorReset, len(r.AppCrashes), len(r.BugChecks), len(r.KernelPowerEvents), r.TotalErrorsLogged, r.TimeWindowHours)
	}

	if report.Data.Software != nil {
		sw := report.Data.Software
		var runtimeNames []string
		for _, rt := range sw.Runtimes {
			if rt.Version != "" {
				runtimeNames = append(runtimeNames, fmt.Sprintf("%s %s", rt.Name, rt.Version))
			} else {
				runtimeNames = append(runtimeNames, rt.Name)
			}
		}
		runtimeStr := ""
		if len(runtimeNames) > 0 {
			runtimeStr = fmt.Sprintf(" | Runtimes: %s", strings.Join(runtimeNames, ", "))
		}
		fmt.Fprintf(w, "  %sSoftware:%s %d Applications, %d HotFixes/Updates%s\n",
			colorBold, colorReset, sw.TotalInstalledApps, len(sw.HotFixes), runtimeStr)
	}

	// Traceable Findings
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s%s--- DETECTED FINDINGS & EVIDENCE ---%s\n", colorBold, colorBlue, colorReset)
	if len(report.Findings) == 0 {
		fmt.Fprintf(w, "  %s[OK] No anomalies or operational bottlenecks identified across collected metrics.%s\n", colorGreen, colorReset)
	} else {
		for _, f := range report.Findings {
			sevColor := colorCyan
			switch f.Severity {
			case models.SeverityCritical:
				sevColor = colorRed
			case models.SeverityWarning:
				sevColor = colorYellow
			}

			fmt.Fprintf(w, "\n  %s[%s]%s %s%s%s (ID: %s, Confidence: %s)\n",
				sevColor, f.Severity, colorReset, colorBold, f.Title, colorReset, f.ID, f.Confidence)
			fmt.Fprintf(w, "    %sObservation:%s %s\n", colorGray, colorReset, f.Observation)
			fmt.Fprintf(w, "    %sImpact:%s      %s\n", colorGray, colorReset, f.PotentialImpact)
			fmt.Fprintf(w, "    %sAction:%s      %s\n", colorGreen, colorReset, f.Recommendation)
		}
	}

	// Limitations
	if len(report.Limitations) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s%s--- COLLECTION LIMITATIONS ---%s\n", colorBold, colorYellow, colorReset)
		for _, lim := range report.Limitations {
			fmt.Fprintf(w, "  * [%s] %s (Category: %s)\n", lim.ProbeID, lim.Reason, lim.Category)
		}
	}

	fmt.Fprintf(w, "%s%s================================================================================%s\n", colorBold, colorCyan, colorReset)
	return nil
}
