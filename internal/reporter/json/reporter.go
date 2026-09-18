package json

import (
	"encoding/json"
	"io"

	"github.com/systemdiag/sysdiag/internal/models"
)

// Reporter exports canonical indented JSON.
type Reporter struct{}

// NewReporter instantiates a JSON reporter.
func NewReporter() *Reporter {
	return &Reporter{}
}

func (r *Reporter) Name() string {
	return "json"
}

func (r *Reporter) Generate(report *models.DiagnosticReport, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
