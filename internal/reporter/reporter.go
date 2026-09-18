package reporter

import (
	"io"

	"github.com/systemdiag/sysdiag/internal/models"
)

// Reporter formats and outputs diagnostic reports.
type Reporter interface {
	Name() string
	Generate(report *models.DiagnosticReport, w io.Writer) error
}
