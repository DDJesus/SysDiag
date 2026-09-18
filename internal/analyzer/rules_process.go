package analyzer

import (
	"context"
	"fmt"
	"math"

	"github.com/systemdiag/sysdiag/internal/models"
)

// ProcessHighResourceRule detects individual processes consuming disproportionate CPU or RAM.
type ProcessHighResourceRule struct{}

func (r *ProcessHighResourceRule) ID() string {
	return "RULE-PROC-001"
}

func (r *ProcessHighResourceRule) Category() string {
	return "processes"
}

func (r *ProcessHighResourceRule) Name() string {
	return "High Resource Consumption Process Rule"
}

func (r *ProcessHighResourceRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Processes == nil {
		return nil, nil
	}

	var findings []models.Finding
	toGB := func(b uint64) float64 {
		return math.Round((float64(b)/(1024*1024*1024))*100) / 100
	}

	totalRAM := uint64(0)
	if report.Data.Memory != nil && report.Data.Memory.TotalBytes > 0 {
		totalRAM = report.Data.Memory.TotalBytes
	}

	// Check Top CPU consumers
	for _, p := range report.Data.Processes.TopCPU {
		if p.CPUPercent >= 80.0 {
			severity := models.SeverityWarning
			if p.CPUPercent >= 95.0 {
				severity = models.SeverityCritical
			}
			findings = append(findings, models.Finding{
				ID:          "FINDING-PROC-001",
				Category:    "processes",
				Severity:    severity,
				Title:       fmt.Sprintf("Process '%s' (PID %d) consumed %.1f%% CPU", p.Name, p.PID, p.CPUPercent),
				Observation: fmt.Sprintf("Process '%s' (PID %d) accounted for %.1f%% CPU utilization during the sampling window.", p.Name, p.PID, p.CPUPercent),
				Evidence: map[string]interface{}{
					"pid":                p.PID,
					"name":               p.Name,
					"cpu_percent":        p.CPUPercent,
					"working_set_bytes":  p.WorkingSetBytes,
					"working_set_gb":     toGB(p.WorkingSetBytes),
					"executable_path":    p.ExecutablePath,
				},
				Interpretation:  fmt.Sprintf("A single process ('%s') is dominating available processor cycles.", p.Name),
				PotentialImpact: "Other processes and services may experience CPU starvation and scheduling latency.",
				Recommendation:  fmt.Sprintf("Investigate the workload running inside '%s' (PID %d) or inspect child threads.", p.Name, p.PID),
				Confidence:      models.ConfidenceHigh,
			})
		}
	}

	// Check Top Memory consumers
	for _, p := range report.Data.Processes.TopMemory {
		memPercent := 0.0
		if totalRAM > 0 {
			memPercent = (float64(p.WorkingSetBytes) / float64(totalRAM)) * 100.0
		}

		// Distinguish percentage-of-system-RAM vs absolute-large-working-set triggers
		if memPercent >= 50.0 {
			findings = append(findings, models.Finding{
				ID:          "FINDING-PROC-002",
				Category:    "processes",
				Severity:    models.SeverityWarning,
				Title:       fmt.Sprintf("Process '%s' (PID %d) consumed %.1f%% of physical RAM (%.2f GB)", p.Name, p.PID, memPercent, toGB(p.WorkingSetBytes)),
				Observation: fmt.Sprintf("Process '%s' (PID %d) utilized %.2f GB working set memory, representing %.1f%% of total physical RAM.", p.Name, p.PID, toGB(p.WorkingSetBytes), memPercent),
				Evidence: map[string]interface{}{
					"pid":               p.PID,
					"name":              p.Name,
					"working_set_bytes": p.WorkingSetBytes,
					"working_set_gb":    toGB(p.WorkingSetBytes),
					"memory_percent":    math.Round(memPercent*10) / 10,
					"executable_path":   p.ExecutablePath,
					"trigger":           "percentage_of_ram",
				},
				Interpretation:  fmt.Sprintf("Process '%s' holds a major fraction (%.1f%%) of installed physical memory.", p.Name, memPercent),
				PotentialImpact: "High proportion of memory allocated to a single process reduces RAM headroom for other workloads.",
				Recommendation:  fmt.Sprintf("Review memory usage profile for '%s' or adjust maximum memory allocation limits.", p.Name),
				Confidence:      models.ConfidenceHigh,
			})
		} else if p.WorkingSetBytes >= 8*1024*1024*1024 {
			findings = append(findings, models.Finding{
				ID:          "FINDING-PROC-002",
				Category:    "processes",
				Severity:    models.SeverityWarning,
				Title:       fmt.Sprintf("Process '%s' (PID %d) consumed %.2f GB physical RAM", p.Name, p.PID, toGB(p.WorkingSetBytes)),
				Observation: fmt.Sprintf("Process '%s' (PID %d) utilized %.2f GB working set memory.", p.Name, p.PID, toGB(p.WorkingSetBytes)),
				Evidence: map[string]interface{}{
					"pid":               p.PID,
					"name":              p.Name,
					"working_set_bytes": p.WorkingSetBytes,
					"working_set_gb":    toGB(p.WorkingSetBytes),
					"memory_percent":    math.Round(memPercent*10) / 10,
					"executable_path":   p.ExecutablePath,
					"trigger":           "absolute_working_set",
				},
				Interpretation:  fmt.Sprintf("Process '%s' maintains a large working set (%.2f GB).", p.Name, toGB(p.WorkingSetBytes)),
				PotentialImpact: "Large working sets contribute significantly to total memory commit footprint.",
				Recommendation:  fmt.Sprintf("Verify that '%s' working set (%.2f GB) is expected for its configured workload.", p.Name, toGB(p.WorkingSetBytes)),
				Confidence:      models.ConfidenceHigh,
			})
		}
	}

	return findings, nil
}
