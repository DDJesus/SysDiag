package test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/probes/cpu"
	"github.com/systemdiag/sysdiag/internal/probes/memory"
	"github.com/systemdiag/sysdiag/internal/probes/network"
	"github.com/systemdiag/sysdiag/internal/probes/process"
	"github.com/systemdiag/sysdiag/internal/probes/reliability"
	"github.com/systemdiag/sysdiag/internal/probes/services"
	"github.com/systemdiag/sysdiag/internal/probes/software"
	"github.com/systemdiag/sysdiag/internal/probes/storage"
	"github.com/systemdiag/sysdiag/internal/probes/system"
)

// MockFailureProbe simulates a probe that fails outright with an error.
type MockFailureProbe struct{}

func (m *MockFailureProbe) ID() string                              { return "probe_mock_fail" }
func (m *MockFailureProbe) Name() string                            { return "Mock Failing Probe" }
func (m *MockFailureProbe) Category() collector.ProbeCategory       { return collector.CategoryStorage }
func (m *MockFailureProbe) RequiredPrivilege() collector.PrivilegeLevel { return collector.PrivilegeUser }
func (m *MockFailureProbe) SupportedProfiles() []string             { return []string{"quick", "deep"} }
func (m *MockFailureProbe) Run(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	return nil, collector.StatusFailed, errors.New("simulated I/O hardware device failure")
}

// MockUnsupportedProbe simulates a probe for a feature unsupported on the target OS.
type MockUnsupportedProbe struct{}

func (m *MockUnsupportedProbe) ID() string                              { return "probe_mock_unsupported" }
func (m *MockUnsupportedProbe) Name() string                            { return "Mock Unsupported Probe" }
func (m *MockUnsupportedProbe) Category() collector.ProbeCategory       { return collector.CategoryReliability }
func (m *MockUnsupportedProbe) RequiredPrivilege() collector.PrivilegeLevel { return collector.PrivilegeUser }
func (m *MockUnsupportedProbe) SupportedProfiles() []string             { return []string{"quick", "deep"} }
func (m *MockUnsupportedProbe) Run(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	return nil, collector.StatusUnsupported, nil
}

// MockPartialProbe simulates a probe returning partial data with a limitation warning.
type MockPartialProbe struct{}

func (m *MockPartialProbe) ID() string                              { return "probe_mock_partial" }
func (m *MockPartialProbe) Name() string                            { return "Mock Partial Probe" }
func (m *MockPartialProbe) Category() collector.ProbeCategory       { return collector.CategoryProcesses }
func (m *MockPartialProbe) RequiredPrivilege() collector.PrivilegeLevel { return collector.PrivilegeAdmin }
func (m *MockPartialProbe) SupportedProfiles() []string             { return []string{"quick", "deep"} }
func (m *MockPartialProbe) Run(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	return &models.ProcessMetrics{
		TotalProcesses: 42,
		TotalThreads:   120,
	}, collector.StatusPartial, errors.New("access denied reading kernel worker processes")
}

func TestPartialProbeFailureDoesNotAbortRun(t *testing.T) {
	engine := collector.NewEngine(collector.WithProbeTimeout(2 * time.Second))
	report := models.NewDiagnosticReport()
	report.Metadata = models.ExecutionMetadata{
		ToolVersion:    "1.0.0",
		ScanTimestamp:  time.Now().UTC(),
		OS:             "linux",
		Architecture:   "amd64",
		PrivilegeLevel: "User",
	}

	probes := []collector.Probe{
		system.NewProbe(),
		cpu.NewProbe(),
		&MockFailureProbe{},
		&MockUnsupportedProbe{},
		&MockPartialProbe{},
	}

	results := engine.Execute(context.Background(), probes, 50*time.Millisecond)
	engine.Normalize(results, report)

	// Verify total probe counter
	if report.CollectionStatus.TotalProbes != 5 {
		t.Fatalf("expected 5 total probes recorded, got %d", report.CollectionStatus.TotalProbes)
	}

	// Verify failure, unsupported, and partial states were accurately captured
	if report.CollectionStatus.Failed < 1 {
		t.Errorf("expected at least 1 failed probe recorded, got %d", report.CollectionStatus.Failed)
	}
	if report.CollectionStatus.Unsupported < 1 {
		t.Errorf("expected at least 1 unsupported probe recorded, got %d", report.CollectionStatus.Unsupported)
	}
	if report.CollectionStatus.Partial < 1 {
		t.Errorf("expected at least 1 partial probe recorded, got %d", report.CollectionStatus.Partial)
	}

	// Verify probe provenance records are populated
	if len(report.CollectionStatus.Probes) != 5 {
		t.Fatalf("expected 5 probe provenance records, got %d", len(report.CollectionStatus.Probes))
	}

	// Verify report serialization survives probe failures
	jsonBytes, err := report.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize report with partial failures to JSON: %v", err)
	}

	var parsed models.DiagnosticReport
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("failed to parse generated JSON report: %v", err)
	}
}

func TestNormalizedOutputContractAllDomains(t *testing.T) {
	engine := collector.NewEngine(collector.WithProbeTimeout(3 * time.Second))
	report := models.NewDiagnosticReport()
	report.Metadata = models.ExecutionMetadata{
		ToolVersion:    "1.0.0",
		ScanTimestamp:  time.Now().UTC(),
		OS:             "linux",
		Architecture:   "amd64",
		PrivilegeLevel: "User",
	}

	registry := collector.NewRegistry()
	registry.Register(system.NewProbe())
	registry.Register(cpu.NewProbe())
	registry.Register(memory.NewProbe())
	registry.Register(storage.NewProbe())
	registry.Register(network.NewProbe())
	registry.Register(process.NewProbe())
	registry.Register(services.NewProbe())
	registry.Register(reliability.NewProbe())
	registry.Register(software.NewProbe())

	probes := registry.ForProfile("quick")
	results := engine.Execute(context.Background(), probes, 50*time.Millisecond)
	engine.Normalize(results, report)

	// Validate JSON schema compatibility
	jsonBytes, err := report.ToJSON()
	if err != nil {
		t.Fatalf("report serialization failed: %v", err)
	}

	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jsonMap); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}

	// Verify top-level contract fields required by Cayde Core
	requiredFields := []string{"$schema", "schema_version", "metadata", "collection_status", "data", "findings", "limitations"}
	for _, field := range requiredFields {
		if _, ok := jsonMap[field]; !ok {
			t.Errorf("missing mandatory contract root field: %s", field)
		}
	}

	metaMap, ok := jsonMap["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata field is not a JSON object")
	}

	metaFields := []string{"tool_version", "scan_timestamp", "os", "architecture", "privilege_level"}
	for _, mf := range metaFields {
		if _, ok := metaMap[mf]; !ok {
			t.Errorf("missing mandatory metadata field: %s", mf)
		}
	}
}
