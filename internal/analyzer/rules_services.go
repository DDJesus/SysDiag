package analyzer

import (
	"context"
	"fmt"

	"github.com/systemdiag/sysdiag/internal/models"
)

// ServiceFailedAutoStartRule evaluates automatic-start services that are in a stopped state.
type ServiceFailedAutoStartRule struct{}

func (r *ServiceFailedAutoStartRule) ID() string {
	return "RULE-SVC-001"
}

func (r *ServiceFailedAutoStartRule) Category() string {
	return "services"
}

func (r *ServiceFailedAutoStartRule) Name() string {
	return "Failed or Stopped Auto-Start Services Rule"
}

func (r *ServiceFailedAutoStartRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Services == nil || len(report.Data.Services.FailedAutoStart) == 0 {
		return nil, nil
	}

	var failedList []models.ServiceInfo
	for _, s := range report.Data.Services.FailedAutoStart {
		// Only evaluate services explicitly configured for Automatic or Automatic (Delayed) startup
		if (s.StartType == "Auto" || s.StartType == "Auto (Delayed)") && s.Status == "Stopped" {
			failedList = append(failedList, s)
		}
	}

	if len(failedList) == 0 {
		return nil, nil
	}

	var findings []models.Finding

	var nonZeroExits int
	details := make([]map[string]interface{}, 0, len(failedList))

	for _, s := range failedList {
		if s.ExitCode != 0 {
			nonZeroExits++
		}
		details = append(details, map[string]interface{}{
			"name":         s.Name,
			"display_name": s.DisplayName,
			"start_type":   s.StartType,
			"status":       s.Status,
			"exit_code":    s.ExitCode,
		})
	}

	severity := models.SeverityInfo
	if nonZeroExits > 0 {
		severity = models.SeverityWarning
	}

	title := fmt.Sprintf("%d automatic-start service(s) currently stopped", len(failedList))
	if nonZeroExits > 0 {
		title = fmt.Sprintf("%d automatic-start service(s) stopped with non-zero exit code", nonZeroExits)
	}

	findings = append(findings, models.Finding{
		ID:          "FINDING-SVC-001",
		Category:    "services",
		Severity:    severity,
		Title:       title,
		Observation: fmt.Sprintf("Found %d service(s) configured for automatic startup in Stopped state (%d with non-zero exit code).", len(failedList), nonZeroExits),
		Evidence: map[string]interface{}{
			"stopped_auto_count": len(failedList),
			"non_zero_exit_count": nonZeroExits,
			"services":           details,
		},
		Interpretation:  "Services configured with Automatic or Automatic (Delayed) startup type were not running at the time of collection.",
		PotentialImpact: "Background features or management capabilities provided by these services may be unavailable unless started on demand.",
		Recommendation:  "Inspect Service Control Manager logs (System Event Log IDs 7000/7001/7023) or verify whether these services use trigger-start configurations.",
		Confidence:      models.ConfidenceHigh,
	})

	return findings, nil
}
