package analyzer

import (
	"context"
	"fmt"
	"math"

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
	var findings []models.Finding

	toGB := func(b uint64) float64 {
		return math.Round((float64(b)/(1024*1024*1024))*100) / 100
	}

	availMB := mem.AvailableBytes / (1024 * 1024)

	if mem.CommitPercent >= 95.0 || availMB < 500 {
		findings = append(findings, models.Finding{
			ID:          "FINDING-MEM-001",
			Category:    "memory",
			Severity:    models.SeverityCritical,
			Title:       "Critical virtual memory commit exhaustion",
			Observation: fmt.Sprintf("Commit charge reached %.1f%% (%.2f GB of %.2f GB limit) with %.2f GB available physical RAM.", mem.CommitPercent, toGB(mem.CommitTotalBytes), toGB(mem.CommitLimitBytes), toGB(mem.AvailableBytes)),
			Evidence: map[string]interface{}{
				"total_gb":                   toGB(mem.TotalBytes),
				"available_gb":               toGB(mem.AvailableBytes),
				"used_percent":               mem.UsedPercent,
				"commit_total_gb":            toGB(mem.CommitTotalBytes),
				"commit_limit_gb":            toGB(mem.CommitLimitBytes),
				"commit_percent":             mem.CommitPercent,
				"threshold_critical_percent": 95.0,
			},
			Interpretation:  "The system is operating with minimal remaining commit capacity relative to the current commit limit.",
			PotentialImpact: "Applications requesting new virtual memory allocations may fail if commit capacity is fully exhausted.",
			Recommendation:  "Inspect memory consumption by individual processes to identify primary consumers and close or optimize high-usage tasks.",
			Confidence:      models.ConfidenceHigh,
		})
	} else if mem.CommitPercent >= 90.0 || availMB < 1024 {
		findings = append(findings, models.Finding{
			ID:          "FINDING-MEM-001",
			Category:    "memory",
			Severity:    models.SeverityWarning,
			Title:       "Elevated memory commit pressure detected",
			Observation: fmt.Sprintf("Commit charge reached %.1f%% (%.2f GB of %.2f GB limit) with %.2f GB available physical RAM.", mem.CommitPercent, toGB(mem.CommitTotalBytes), toGB(mem.CommitLimitBytes), toGB(mem.AvailableBytes)),
			Evidence: map[string]interface{}{
				"total_gb":                  toGB(mem.TotalBytes),
				"available_gb":              toGB(mem.AvailableBytes),
				"used_percent":              mem.UsedPercent,
				"commit_total_gb":           toGB(mem.CommitTotalBytes),
				"commit_limit_gb":           toGB(mem.CommitLimitBytes),
				"commit_percent":            mem.CommitPercent,
				"threshold_warning_percent": 90.0,
			},
			Interpretation:  "The system is operating with elevated commit utilization relative to the current commit limit.",
			PotentialImpact: "Available memory headroom for workload spikes is constrained.",
			Recommendation:  "Review active processes for elevated memory consumption and track usage trends.",
			Confidence:      models.ConfidenceHigh,
		})
	}

	return findings, nil
}
