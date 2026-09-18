//go:build linux
// +build linux

package reliability

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

var (
	oomRegex      = regexp.MustCompile(`(?i)(?:Out of memory:\s*Kill process|invoked oom-killer|killed process)\s*(\d+)?\s*\(([^)]+)\)?`)
	segfaultRegex = regexp.MustCompile(`(?i)([\w_.-]+)\[\d+\]:\s*segfault at [0-9a-f]+ ip ([0-9a-f]+) sp ([0-9a-f]+) error (\d+)`)
	kernelPanicRe = regexp.MustCompile(`(?i)Kernel panic - not syncing:\s*(.+)`)
)

func (p *Probe) collect(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	timeWindowHours := 24
	if sampleDuration > 500*time.Millisecond {
		timeWindowHours = 72
	}

	metrics := &models.ReliabilityMetrics{
		TimeWindowHours:   timeWindowHours,
		AppCrashes:        make([]models.AppCrashEvent, 0),
		SystemErrors:      make([]models.SystemErrorEvent, 0),
		KernelPowerEvents: make([]models.KernelPowerEvent, 0),
		BugChecks:         make([]models.BugCheckEvent, 0),
	}

	status := collectLinuxLogs(ctx, metrics, timeWindowHours)
	metrics.TotalErrorsLogged = len(metrics.AppCrashes) + len(metrics.SystemErrors) + len(metrics.KernelPowerEvents) + len(metrics.BugChecks)

	return metrics, status, nil
}

func collectLinuxLogs(ctx context.Context, metrics *models.ReliabilityMetrics, timeWindowHours int) collector.ProbeStatus {
	// Try journalctl first if available
	if cmdPath, err := exec.LookPath("journalctl"); err == nil {
		sinceArg := time.Now().Add(-time.Duration(timeWindowHours) * time.Hour).Format("2006-01-02 15:04:05")
		cmd := exec.CommandContext(ctx, cmdPath, "-p", "3", "--since", sinceArg, "--no-pager", "--lines=100")
		if out, err := cmd.Output(); err == nil && len(out) > 0 {
			parseLogLines(string(out), metrics)
			return collector.StatusSuccess
		}
	}

	// Try reading /var/log/syslog or /var/log/messages
	logPaths := []string{"/var/log/syslog", "/var/log/messages", "/var/log/dmesg"}
	readAny := false
	for _, lp := range logPaths {
		f, err := os.Open(lp)
		if err != nil {
			continue
		}
		readAny = true
		scanner := bufio.NewScanner(f)
		var lines []string
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
			if len(lines) > 500 {
				lines = lines[1:]
			}
		}
		f.Close()
		parseLogLines(strings.Join(lines, "\n"), metrics)
		break
	}

	// Also try dmesg if available
	if dmesgPath, err := exec.LookPath("dmesg"); err == nil {
		cmd := exec.CommandContext(ctx, dmesgPath, "-T", "-l", "err,crit,alert,emerg")
		if out, err := cmd.Output(); err == nil && len(out) > 0 {
			readAny = true
			parseLogLines(string(out), metrics)
		}
	}

	if !readAny {
		// Log files require elevation to read on unprivileged user
		return collector.StatusRequiresAdmin
	}

	return collector.StatusSuccess
}

func parseLogLines(content string, metrics *models.ReliabilityMetrics) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Check for OOM killer
		if oomMatches := oomRegex.FindStringSubmatch(line); len(oomMatches) > 0 {
			appName := "unknown"
			if len(oomMatches) >= 3 && oomMatches[2] != "" {
				appName = oomMatches[2]
			}
			metrics.AppCrashes = append(metrics.AppCrashes, models.AppCrashEvent{
				Timestamp:     time.Now().UTC(),
				Application:   appName,
				FaultModule:   "kernel:oom-killer",
				ExceptionCode: "SIGKILL",
				EventID:       9,
				Message:       line,
			})
			continue
		}

		// Check for segfault
		if segMatches := segfaultRegex.FindStringSubmatch(line); len(segMatches) > 0 {
			appName := segMatches[1]
			faultModule := ""
			if len(segMatches) >= 3 {
				faultModule = segMatches[2]
			}
			metrics.AppCrashes = append(metrics.AppCrashes, models.AppCrashEvent{
				Timestamp:     time.Now().UTC(),
				Application:   appName,
				FaultModule:   faultModule,
				ExceptionCode: "SIGSEGV (0xC0000005)",
				EventID:       11,
				Message:       line,
			})
			continue
		}

		// Check for Kernel Panic
		if panicMatches := kernelPanicRe.FindStringSubmatch(line); len(panicMatches) > 0 {
			metrics.BugChecks = append(metrics.BugChecks, models.BugCheckEvent{
				Timestamp:      time.Now().UTC(),
				BugCheckString: "KERNEL_PANIC",
				BugCheckCode:   "0xDEADDEAD",
				Message:        line,
			})
			continue
		}

		// Check for general system / hardware errors
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "i/o error") || strings.Contains(lineLower, "ext4-fs error") ||
			strings.Contains(lineLower, "failed to start") || strings.Contains(lineLower, "machine check exception") ||
			strings.Contains(lineLower, "hardware error") {
			level := "Error"
			if strings.Contains(lineLower, "panic") || strings.Contains(lineLower, "emerg") || strings.Contains(lineLower, "hardware error") {
				level = "Critical"
			}
			provider := "kernel"
			if strings.Contains(lineLower, "systemd") {
				provider = "systemd"
			}
			metrics.SystemErrors = append(metrics.SystemErrors, models.SystemErrorEvent{
				Timestamp: time.Now().UTC(),
				Provider:  provider,
				Level:     level,
				Channel:   "syslog",
				Message:   line,
			})
		}
	}
}
