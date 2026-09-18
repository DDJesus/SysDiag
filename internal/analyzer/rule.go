package analyzer

import (
	"context"

	"github.com/systemdiag/sysdiag/internal/models"
)

// Rule evaluates normalized diagnostic reports to produce evidence-backed findings.
type Rule interface {
	ID() string
	Category() string
	Name() string
	Evaluate(ctx context.Context, report *models.DiagnosticReport) ([]models.Finding, error)
}
