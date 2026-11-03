package analyzer

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/systemdiag/sysdiag/internal/models"
)

// CPUHighUtilizationRule detects sustained high CPU load.
type CPUHighUtilizationRule struct{}

func (r *CPUHighUtilizationRule) ID() string {
	return "RULE-CPU-001"
}

func (r *CPUHighUtilizationRule) Category() string {
	return "cpu"
}

func (r *CPUHighUtilizationRule) Name() string {
	return "High CPU Utilization Rule"
}

func (r *CPUHighUtilizationRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.CPU == nil {
		return nil, nil
	}

	cpu := report.Data.CPU
	var findings []models.Finding

	if cpu.UtilizationPercent >= 95.0 {
		findings = append(findings, models.Finding{
			ID:          "FINDING-CPU-001",
			Category:    "cpu",
			Severity:    models.SeverityCritical,
			Title:       "Critical CPU saturation detected",
			Observation: fmt.Sprintf("Overall CPU utilization measured %.1f%% during the sampling window across %d logical cores.", cpu.UtilizationPercent, cpu.LogicalCores),
			Evidence: map[string]interface{}{
				"utilization_percent":        cpu.UtilizationPercent,
				"threshold_critical_percent": 95.0,
				"user_percent":               cpu.UserPercent,
				"kernel_percent":             cpu.KernelPercent,
				"logical_cores":              cpu.LogicalCores,
			},
			Interpretation:  "Processor compute capacity was nearly fully consumed during the observation period.",
			PotentialImpact: "Workloads may experience queueing, thread scheduling delays, and increased processing latency.",
			Recommendation:  "Identify high CPU processes using task monitoring utilities or run a deep profile trace to isolate top threads.",
			Confidence:      models.ConfidenceHigh,
		})
	} else if cpu.UtilizationPercent >= 85.0 {
		findings = append(findings, models.Finding{
			ID:          "FINDING-CPU-001",
			Category:    "cpu",
			Severity:    models.SeverityWarning,
			Title:       "High sustained CPU utilization detected",
			Observation: fmt.Sprintf("Overall CPU utilization measured %.1f%% during the sampling window across %d logical cores.", cpu.UtilizationPercent, cpu.LogicalCores),
			Evidence: map[string]interface{}{
				"utilization_percent":       cpu.UtilizationPercent,
				"threshold_warning_percent": 85.0,
				"user_percent":              cpu.UserPercent,
				"kernel_percent":            cpu.KernelPercent,
				"logical_cores":             cpu.LogicalCores,
			},
			Interpretation:  "Processor compute capacity experienced elevated utilization during the observation period.",
			PotentialImpact: "System responsiveness may decrease under additional concurrent compute load.",
			Recommendation:  "Review active processes to identify high CPU consumers and evaluate whether workload demand is expected.",
			Confidence:      models.ConfidenceHigh,
		})
	}

	return findings, nil
}

// MemoryCommitExhaustionRule detects physical memory pressure and commit exhaustion.
type MemoryCommitExhaustionRule struct{}

func (r *MemoryCommitExhaustionRule) ID() string {
	return "RULE-MEM-001"
}

func (r *MemoryCommitExhaustionRule) Category() string {
	return "memory"
}

func (r *MemoryCommitExhaustionRule) Name() string {
	return "Memory Commit & Exhaustion Rule"
}

func (r *MemoryCommitExhaustionRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Memory == nil {
		return nil, nil
	}

	mem := report.Data.Memory
	toGB := func(b uint64) float64 {
		return math.Round((float64(b)/(1024*1024*1024))*100) / 100
	}

	physicalValid := mem.TotalBytes > 0 && mem.AvailableBytes <= mem.TotalBytes
	commitValid := mem.CommitLimitBytes > 0 && !math.IsNaN(mem.CommitPercent) && !math.IsInf(mem.CommitPercent, 0) && mem.CommitPercent >= 0
	if commitValid {
		percentFromBytes := float64(mem.CommitTotalBytes) / float64(mem.CommitLimitBytes) * 100
		commitValid = !math.IsNaN(percentFromBytes) && !math.IsInf(percentFromBytes, 0) && math.Abs(percentFromBytes-mem.CommitPercent) <= 0.11
	}
	physicalCritical, physicalWarning := false, false
	if physicalValid {
		availableMB := mem.AvailableBytes / (1024 * 1024)
		physicalCritical = availableMB < 500
		physicalWarning = availableMB < 1024
	}
	commitCritical := commitValid && mem.CommitPercent >= 95.0
	commitWarning := commitValid && mem.CommitPercent >= 90.0

	severity := models.Severity("")
	if commitCritical || physicalCritical {
		severity = models.SeverityCritical
	} else if commitWarning || physicalWarning {
		severity = models.SeverityWarning
	} else {
		return nil, nil
	}

	evidence := make(map[string]interface{})
	var observations, interpretations, impacts []string
	title := "Low available physical memory"
	if commitWarning || commitCritical {
		evidence["commit_total_gb"] = toGB(mem.CommitTotalBytes)
		evidence["commit_limit_gb"] = toGB(mem.CommitLimitBytes)
		evidence["commit_percent"] = mem.CommitPercent
		if commitCritical {
			evidence["threshold_critical_percent"] = 95.0
			title = "Critical virtual memory commit exhaustion"
		} else {
			evidence["threshold_warning_percent"] = 90.0
			title = "Elevated memory commit pressure detected"
		}
		observations = append(observations, fmt.Sprintf("Commit charge reached %.1f%% (%.2f GB of %.2f GB limit)", mem.CommitPercent, toGB(mem.CommitTotalBytes), toGB(mem.CommitLimitBytes)))
		interpretations = append(interpretations, "Commit utilization is elevated relative to the current commit limit.")
		impacts = append(impacts, "Applications requesting virtual memory may fail if commit capacity is exhausted.")
	}
	if physicalWarning || physicalCritical {
		evidence["total_gb"] = toGB(mem.TotalBytes)
		evidence["available_gb"] = toGB(mem.AvailableBytes)
		evidence["used_percent"] = mem.UsedPercent
		if physicalCritical {
			evidence["threshold_available_critical_mb"] = 500
			if !commitCritical {
				title = "Critical physical memory availability"
			}
		} else {
			evidence["threshold_available_warning_mb"] = 1024
		}
		observations = append(observations, fmt.Sprintf("Available physical memory measured %.2f GB of %.2f GB total", toGB(mem.AvailableBytes), toGB(mem.TotalBytes)))
		interpretations = append(interpretations, "Available physical memory is low relative to the installed total.")
		impacts = append(impacts, "Applications may have reduced physical memory headroom for new or expanding workloads.")
	}

	return []models.Finding{{
		ID:              "FINDING-MEM-001",
		Category:        "memory",
		Severity:        severity,
		Title:           title,
		Observation:     strings.Join(observations, "; ") + ".",
		Evidence:        evidence,
		Interpretation:  strings.Join(interpretations, " "),
		PotentialImpact: strings.Join(impacts, " "),
		Recommendation:  "Review memory consumption by active processes and monitor available capacity.",
		Confidence:      models.ConfidenceHigh,
	}}, nil
}
