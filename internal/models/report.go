package models

import (
	"encoding/json"
	"time"
)

// ExecutionMetadata captures environment and invocation parameters.
type ExecutionMetadata struct {
	ToolVersion     string    `json:"tool_version"`
	ScanTimestamp   time.Time `json:"scan_timestamp"`
	ScanDurationMS  int64     `json:"scan_duration_ms"`
	Profile         string    `json:"profile"`
	Hostname        string    `json:"hostname"`
	OS              string    `json:"os"`
	OSVersion       string    `json:"os_version"`
	Architecture    string    `json:"architecture"`
	PrivilegeLevel  string    `json:"privilege_level"`
	IsElevated      bool      `json:"is_elevated"`
	ExecutionPath   string    `json:"execution_path"`
	OutputDirectory string    `json:"output_directory"`
}

// ProbeRecord captures granular execution provenance for an individual diagnostic probe.
type ProbeRecord struct {
	ProbeID           string `json:"probe_id"`
	Category          string `json:"category"`
	Name              string `json:"name,omitempty"`
	Status            string `json:"status"` // Success, Partial, Requires Administrator, Unsupported, Failed, Timeout
	DurationMS        int64  `json:"duration_ms"`
	Reason            string `json:"reason,omitempty"`
	PrivilegeRequired string `json:"privilege_required,omitempty"`
}

// CollectionStatus tracks probe execution counters, coverage, and per-probe provenance.
type CollectionStatus struct {
	TotalProbes   int           `json:"total_probes"`
	Successful    int           `json:"successful"`
	Partial       int           `json:"partial"`
	RequiresAdmin int           `json:"requires_admin"`
	Unsupported   int           `json:"unsupported"`
	Failed        int           `json:"failed"`
	Timeout       int           `json:"timeout"`
	Probes        []ProbeRecord `json:"probes,omitempty"`
}

// DiagnosticReport is the canonical root document for diagnostic outcomes.
type DiagnosticReport struct {
	Schema           string                 `json:"$schema"`
	SchemaVersion    string                 `json:"schema_version"`
	Metadata         ExecutionMetadata      `json:"metadata"`
	CollectionStatus CollectionStatus       `json:"collection_status"`
	Data             DiagnosticData         `json:"data"`
	Findings         []Finding              `json:"findings"`
	Limitations      []CollectionLimitation `json:"limitations"`
}

// NewDiagnosticReport instantiates a default versioned diagnostic report container.
func NewDiagnosticReport() *DiagnosticReport {
	return &DiagnosticReport{
		Schema:        "https://systemdiag.io/schema/v1.json",
		SchemaVersion: "1.0.0",
		Findings:      make([]Finding, 0),
		Limitations:   make([]CollectionLimitation, 0),
	}
}

// ToJSON serializes the report to indented JSON bytes.
func (r *DiagnosticReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// FromJSON parses raw JSON into a DiagnosticReport struct.
func FromJSON(data []byte) (*DiagnosticReport, error) {
	var r DiagnosticReport
	err := json.Unmarshal(data, &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}
