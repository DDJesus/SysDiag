package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/systemdiag/sysdiag/internal/models"
)

// ReliabilityBugCheckRule identifies Blue Screen of Death (BSOD) crash events.
type ReliabilityBugCheckRule struct{}

func (r *ReliabilityBugCheckRule) ID() string {
	return "RULE-REL-001"
}

func (r *ReliabilityBugCheckRule) Category() string {
	return "reliability"
}

func (r *ReliabilityBugCheckRule) Name() string {
	return "BugCheck BSOD Crash Dump Rule"
}

func (r *ReliabilityBugCheckRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Reliability == nil || len(report.Data.Reliability.BugChecks) == 0 {
		return nil, nil
	}

	bugchecks := report.Data.Reliability.BugChecks
	var findings []models.Finding

	var items []map[string]interface{}
	for _, b := range bugchecks {
		items = append(items, map[string]interface{}{
			"timestamp":       b.Timestamp,
			"bugcheck_code":   b.BugCheckCode,
			"bugcheck_string": b.BugCheckString,
			"dump_file":       b.DumpFile,
			"message":         b.Message,
		})
	}

	findings = append(findings, models.Finding{
		ID:          "FINDING-REL-001",
		Category:    "reliability",
		Severity:    models.SeverityCritical,
		Title:       fmt.Sprintf("%d system crash dump(s) (BSOD) recorded in event log", len(bugchecks)),
		Observation: fmt.Sprintf("Recorded %d BugCheck / system crash event(s) in the System event log within the %d-hour scan window.", len(bugchecks), report.Data.Reliability.TimeWindowHours),
		Evidence: map[string]interface{}{
			"crash_count":        len(bugchecks),
			"time_window_hours":  report.Data.Reliability.TimeWindowHours,
			"bugchecks":          items,
		},
		Interpretation:  "The operating system recorded one or more kernel crash (BSOD) stop errors.",
		PotentialImpact: "System instability, unscheduled reboots, and potential corruption of unwritten volatile state.",
		Recommendation:  "Inspect memory crash dumps using WinDbg to identify the faulting driver, kernel module, or hardware fault.",
		Confidence:      models.ConfidenceHigh,
	})

	return findings, nil
}

// ReliabilityKernelPowerRule evaluates Event ID 41 (dirty reboots / ungraceful shutdowns).
type ReliabilityKernelPowerRule struct{}

func (r *ReliabilityKernelPowerRule) ID() string {
	return "RULE-REL-002"
}

func (r *ReliabilityKernelPowerRule) Category() string {
	return "reliability"
}

func (r *ReliabilityKernelPowerRule) Name() string {
	return "Kernel-Power Dirty Reboot Rule"
}

func (r *ReliabilityKernelPowerRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Reliability == nil || len(report.Data.Reliability.KernelPowerEvents) == 0 {
		return nil, nil
	}

	kpEvents := report.Data.Reliability.KernelPowerEvents
	var findings []models.Finding

	var timestamps []string
	for _, e := range kpEvents {
		timestamps = append(timestamps, e.Timestamp.Format("2006-01-02 15:04:05 UTC"))
	}

	findings = append(findings, models.Finding{
		ID:          "FINDING-REL-002",
		Category:    "reliability",
		Severity:    models.SeverityWarning,
		Title:       fmt.Sprintf("%d ungraceful shutdown/reboot event(s) recorded", len(kpEvents)),
		Observation: fmt.Sprintf("Recorded %d Kernel-Power Event ID 41 occurrence(s) within the last %d hour(s).", len(kpEvents), report.Data.Reliability.TimeWindowHours),
		Evidence: map[string]interface{}{
			"event_count":       len(kpEvents),
			"time_window_hours": report.Data.Reliability.TimeWindowHours,
			"timestamps":        timestamps,
		},
		Interpretation:  "The system rebooted without cleanly completing the standard shutdown sequence (sudden power loss, hard lockup, or reset).",
		PotentialImpact: "Risk of interrupted transactions, unsaved user data loss, and filesystem recovery cycles on boot.",
		Recommendation:  "Inspect power supply health, thermal logs, UPS stability, and verify whether hard resets occurred.",
		Confidence:      models.ConfidenceHigh,
	})

	return findings, nil
}

// ReliabilityAppCrashRule detects frequent application crashes or crash loops.
type ReliabilityAppCrashRule struct{}

func (r *ReliabilityAppCrashRule) ID() string {
	return "RULE-REL-003"
}

func (r *ReliabilityAppCrashRule) Category() string {
	return "reliability"
}

func (r *ReliabilityAppCrashRule) Name() string {
	return "Application Crash Loop Rule"
}

func (r *ReliabilityAppCrashRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Reliability == nil || len(report.Data.Reliability.AppCrashes) == 0 {
		return nil, nil
	}

	crashes := report.Data.Reliability.AppCrashes
	var findings []models.Finding

	appCount := make(map[string]int)
	appDetails := make(map[string][]map[string]interface{})

	for _, c := range crashes {
		app := c.Application
		if app == "" {
			app = "Unknown"
		}
		appCount[app]++
		appDetails[app] = append(appDetails[app], map[string]interface{}{
			"timestamp":      c.Timestamp,
			"fault_module":   c.FaultModule,
			"exception_code": c.ExceptionCode,
			"event_id":       c.EventID,
		})
	}

	for app, count := range appCount {
		if count >= 3 {
			findings = append(findings, models.Finding{
				ID:          "FINDING-REL-003",
				Category:    "reliability",
				Severity:    models.SeverityWarning,
				Title:       fmt.Sprintf("Recurring application crash loop detected for '%s'", app),
				Observation: fmt.Sprintf("Application '%s' logged %d crash event(s) in the Application event log within the last %d hour(s).", app, count, report.Data.Reliability.TimeWindowHours),
				Evidence: map[string]interface{}{
					"application":       app,
					"crash_count":       count,
					"time_window_hours": report.Data.Reliability.TimeWindowHours,
					"crash_instances":   appDetails[app],
				},
				Interpretation:  fmt.Sprintf("Application '%s' suffered repeated unhandled exception or termination faults.", app),
				PotentialImpact: "Service disruptions, failed workflow execution, and lost work in '%s'.",
				Recommendation:  fmt.Sprintf("Review faulting modules and exception codes in '%s' crash logs, update the application, or reinstall corrupt dependencies.", app),
				Confidence:      models.ConfidenceHigh,
			})
		}
	}

	return findings, nil
}

// isClassifiedStorageError checks whether an event matches a known storage or filesystem error classification.
func isClassifiedStorageError(e models.SystemErrorEvent) bool {
	// Ignore informational events for hardware storage failure evaluation
	if e.Level == "Info" || e.Level == "Information" {
		return false
	}

	p := strings.ToLower(e.Provider)
	id := e.EventID

	// Provider "disk" / "Microsoft-Windows-Disk":
	// Event ID 7: Bad block detected
	// Event ID 11: Controller error
	// Event ID 15: Device not ready for access
	// Event ID 51: Paging operation error
	// Event ID 153: I/O operation retried
	// Event ID 154: Hardware error during I/O
	if strings.Contains(p, "disk") {
		switch id {
		case 7, 11, 15, 51, 153, 154:
			return true
		}
	}

	// Provider "ntfs" / "refs" / "Microsoft-Windows-Ntfs" / "Microsoft-Windows-ReFS":
	// Event ID 55: Filesystem structure corruption
	// Event ID 130 / 140: Volume corruption / transaction metadata error
	if strings.Contains(p, "ntfs") || strings.Contains(p, "refs") {
		switch id {
		case 55, 130, 140:
			return true
		}
	}

	// Storage controller / miniport drivers (storahci, stornvme, iastora, iastoravc, atapi, storport):
	// Event ID 9: Device timeout
	// Event ID 129: Reset to device issued
	if strings.Contains(p, "storahci") || strings.Contains(p, "stornvme") ||
		strings.Contains(p, "iastora") || strings.Contains(p, "iastoravc") ||
		strings.Contains(p, "atapi") || strings.Contains(p, "storport") {
		switch id {
		case 9, 129:
			return true
		}
	}

	// Storage Spaces driver (spaceport):
	// Event ID 102 / 103: Storage space/pool read or write failure
	if strings.Contains(p, "spaceport") {
		switch id {
		case 102, 103:
			return true
		}
	}

	return false
}

// ReliabilityDiskErrorsRule checks for genuine storage and filesystem errors logged in System event logs.
type ReliabilityDiskErrorsRule struct{}

func (r *ReliabilityDiskErrorsRule) ID() string {
	return "RULE-REL-004"
}

func (r *ReliabilityDiskErrorsRule) Category() string {
	return "reliability"
}

func (r *ReliabilityDiskErrorsRule) Name() string {
	return "System Event Log Storage Errors Rule"
}

func (r *ReliabilityDiskErrorsRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Reliability == nil || len(report.Data.Reliability.SystemErrors) == 0 {
		return nil, nil
	}

	var diskErrors []models.SystemErrorEvent
	for _, e := range report.Data.Reliability.SystemErrors {
		// Only evaluate events matching the explicit provider + event-ID classification matrix
		if isClassifiedStorageError(e) {
			diskErrors = append(diskErrors, e)
		}
	}

	if len(diskErrors) == 0 {
		return nil, nil
	}

	var samples []map[string]interface{}
	for _, de := range diskErrors {
		samples = append(samples, map[string]interface{}{
			"timestamp": de.Timestamp,
			"provider":  de.Provider,
			"event_id":  de.EventID,
			"level":     de.Level,
			"message":   de.Message,
		})
	}

	var findings []models.Finding
	findings = append(findings, models.Finding{
		ID:          "FINDING-REL-004",
		Category:    "reliability",
		Severity:    models.SeverityWarning,
		Title:       fmt.Sprintf("%d storage or filesystem error event(s) logged", len(diskErrors)),
		Observation: fmt.Sprintf("The System event log recorded %d classified storage driver or filesystem error event(s) within the %d-hour window.", len(diskErrors), report.Data.Reliability.TimeWindowHours),
		Evidence: map[string]interface{}{
			"error_count":       len(diskErrors),
			"time_window_hours": report.Data.Reliability.TimeWindowHours,
			"events":            samples,
		},
		Interpretation:  "The Windows storage driver stack logged I/O controller, paging, bad block, or filesystem error events.",
		PotentialImpact: "Storage I/O latency, bad block degradation, or potential filesystem corruption.",
		Recommendation:  "Run filesystem verification (chkdsk), check disk SMART health status, and inspect storage controller error logs.",
		Confidence:      models.ConfidenceHigh,
	})

	return findings, nil
}
