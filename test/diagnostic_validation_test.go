package test

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/systemdiag/sysdiag/internal/analyzer"
	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/sanitizer"
)

type expectedFinding struct {
	id       string
	severity models.Severity
}

type expectedEvidence struct {
	findingID string
	key       string
	value     interface{}
}

type diagnosticScenario struct {
	name                string
	probes              []collector.ProbeResult
	statuses            []collector.ProbeStatus
	findings            []expectedFinding
	evidence            []expectedEvidence
	expectedLimitations int
}

func validationProbe(id string, category collector.ProbeCategory, status collector.ProbeStatus, data interface{}, reason string) collector.ProbeResult {
	var err error
	if reason != "" {
		err = errors.New(reason)
	}
	return collector.ProbeResult{ProbeID: id, Name: id, Category: category, Status: status, Data: data, Err: err}
}

func TestDiagnosticValidationScenarios(t *testing.T) {
	const mib = uint64(1024 * 1024)
	const gib = uint64(1024 * 1024 * 1024)
	autoService := models.ServiceInfo{Name: "synthetic-agent", DisplayName: "Synthetic Agent", StartType: "Auto", Status: "Stopped"}
	warningVolume := models.VolumeMetrics{MountPoint: "/validation", TotalBytes: 1000, FreeBytes: 100, UsedPercent: 90}
	criticalVolume := models.VolumeMetrics{MountPoint: "/validation", TotalBytes: 1000, FreeBytes: 50, UsedPercent: 95}

	scenarios := []diagnosticScenario{
		{name: "cpu normal", probes: []collector.ProbeResult{validationProbe("cpu", collector.CategoryCPU, collector.StatusSuccess, &models.CPUMetrics{UtilizationPercent: 60}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}},
		{name: "cpu below warning boundary", probes: []collector.ProbeResult{validationProbe("cpu", collector.CategoryCPU, collector.StatusSuccess, &models.CPUMetrics{UtilizationPercent: 84.9}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}},
		{name: "cpu warning boundary", probes: []collector.ProbeResult{validationProbe("cpu", collector.CategoryCPU, collector.StatusSuccess, &models.CPUMetrics{UtilizationPercent: 85}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-CPU-001", models.SeverityWarning}}, evidence: []expectedEvidence{{"FINDING-CPU-001", "utilization_percent", float64(85)}}},
		{name: "cpu upper warning boundary", probes: []collector.ProbeResult{validationProbe("cpu", collector.CategoryCPU, collector.StatusSuccess, &models.CPUMetrics{UtilizationPercent: 94.9}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-CPU-001", models.SeverityWarning}}},
		{name: "cpu critical boundary", probes: []collector.ProbeResult{validationProbe("cpu", collector.CategoryCPU, collector.StatusSuccess, &models.CPUMetrics{UtilizationPercent: 95}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-CPU-001", models.SeverityCritical}}, evidence: []expectedEvidence{{"FINDING-CPU-001", "utilization_percent", float64(95)}}},
		{name: "cpu measurement unavailable after failure", probes: []collector.ProbeResult{validationProbe("cpu", collector.CategoryCPU, collector.StatusFailed, nil, "synthetic collection failure")}, statuses: []collector.ProbeStatus{collector.StatusFailed}, expectedLimitations: 1},
		{name: "cpu partial topology without utilization finding", probes: []collector.ProbeResult{validationProbe("cpu", collector.CategoryCPU, collector.StatusPartial, &models.CPUMetrics{LogicalCores: 4}, "utilization sample unavailable")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, expectedLimitations: 1},
		{name: "cpu partial high measurement", probes: []collector.ProbeResult{validationProbe("cpu", collector.CategoryCPU, collector.StatusPartial, &models.CPUMetrics{UtilizationPercent: 96}, "one sample source unavailable")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, findings: []expectedFinding{{"FINDING-CPU-001", models.SeverityCritical}}, expectedLimitations: 1},
		{name: "memory normal", probes: []collector.ProbeResult{validationProbe("memory", collector.CategoryMemory, collector.StatusSuccess, &models.MemoryMetrics{TotalBytes: 16 * gib, AvailableBytes: 8 * gib, CommitLimitBytes: 20 * gib, CommitTotalBytes: 10 * gib, CommitPercent: 50}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}},
		{name: "memory warning boundary", probes: []collector.ProbeResult{validationProbe("memory", collector.CategoryMemory, collector.StatusSuccess, &models.MemoryMetrics{TotalBytes: 8 * gib, AvailableBytes: 2 * gib, CommitLimitBytes: 10 * gib, CommitTotalBytes: 9 * gib, CommitPercent: 90}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-MEM-001", models.SeverityWarning}}, evidence: []expectedEvidence{{"FINDING-MEM-001", "commit_percent", float64(90)}}},
		{name: "memory upper warning boundary", probes: []collector.ProbeResult{validationProbe("memory", collector.CategoryMemory, collector.StatusSuccess, &models.MemoryMetrics{TotalBytes: 8 * gib, AvailableBytes: 2 * gib, CommitLimitBytes: 10000 * mib, CommitTotalBytes: 9490 * mib, CommitPercent: 94.9}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-MEM-001", models.SeverityWarning}}},
		{name: "memory critical boundary", probes: []collector.ProbeResult{validationProbe("memory", collector.CategoryMemory, collector.StatusSuccess, &models.MemoryMetrics{TotalBytes: 8 * gib, AvailableBytes: 2 * gib, CommitLimitBytes: 10000 * mib, CommitTotalBytes: 9500 * mib, CommitPercent: 95}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-MEM-001", models.SeverityCritical}}, evidence: []expectedEvidence{{"FINDING-MEM-001", "commit_percent", float64(95)}}},
		{name: "memory incomplete with zero total", probes: []collector.ProbeResult{validationProbe("memory", collector.CategoryMemory, collector.StatusPartial, &models.MemoryMetrics{AvailableBytes: 0}, "total memory measurement unavailable")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, expectedLimitations: 1},
		{name: "memory invalid availability above total", probes: []collector.ProbeResult{validationProbe("memory", collector.CategoryMemory, collector.StatusPartial, &models.MemoryMetrics{TotalBytes: gib, AvailableBytes: 2 * gib}, "inconsistent synthetic measurement")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, expectedLimitations: 1},
		{name: "invalid physical measurements with valid high commit", probes: []collector.ProbeResult{validationProbe("memory", collector.CategoryMemory, collector.StatusPartial, &models.MemoryMetrics{CommitLimitBytes: 10000 * mib, CommitTotalBytes: 9600 * mib, CommitPercent: 96}, "physical memory unavailable")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, findings: []expectedFinding{{"FINDING-MEM-001", models.SeverityCritical}}, evidence: []expectedEvidence{{"FINDING-MEM-001", "commit_percent", float64(96)}}, expectedLimitations: 1},
		{name: "valid low physical memory without commit metrics", probes: []collector.ProbeResult{validationProbe("memory", collector.CategoryMemory, collector.StatusPartial, &models.MemoryMetrics{TotalBytes: 16 * gib, AvailableBytes: 256 * mib, UsedPercent: 98.4}, "commit metrics unavailable")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, findings: []expectedFinding{{"FINDING-MEM-001", models.SeverityCritical}}, evidence: []expectedEvidence{{"FINDING-MEM-001", "available_gb", float64(0.25)}}, expectedLimitations: 1},
		{name: "both memory measurements unavailable", probes: []collector.ProbeResult{validationProbe("memory", collector.CategoryMemory, collector.StatusPartial, &models.MemoryMetrics{}, "memory measurements unavailable")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, expectedLimitations: 1},
		{name: "memory unavailable", probes: []collector.ProbeResult{validationProbe("memory", collector.CategoryMemory, collector.StatusFailed, nil, "synthetic read failure")}, statuses: []collector.ProbeStatus{collector.StatusFailed}, expectedLimitations: 1},
		{name: "storage healthy", probes: []collector.ProbeResult{validationProbe("storage", collector.CategoryStorage, collector.StatusSuccess, &models.StorageMetrics{Volumes: []models.VolumeMetrics{{MountPoint: "/validation", TotalBytes: 1000, FreeBytes: 250, UsedPercent: 75}}}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}},
		{name: "storage warning boundary", probes: []collector.ProbeResult{validationProbe("storage", collector.CategoryStorage, collector.StatusSuccess, &models.StorageMetrics{Volumes: []models.VolumeMetrics{warningVolume}}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-STORAGE-001", models.SeverityWarning}}, evidence: []expectedEvidence{{"FINDING-STORAGE-001", "used_percent", float64(90)}}},
		{name: "storage upper warning boundary", probes: []collector.ProbeResult{validationProbe("storage", collector.CategoryStorage, collector.StatusSuccess, &models.StorageMetrics{Volumes: []models.VolumeMetrics{{MountPoint: "/validation", TotalBytes: 1000, FreeBytes: 51, UsedPercent: 94.9}}}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-STORAGE-001", models.SeverityWarning}}},
		{name: "storage multiple volumes isolate pressure", probes: []collector.ProbeResult{validationProbe("storage", collector.CategoryStorage, collector.StatusSuccess, &models.StorageMetrics{Volumes: []models.VolumeMetrics{{MountPoint: "/healthy", TotalBytes: 1000, FreeBytes: 700, UsedPercent: 30}, criticalVolume}}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-STORAGE-001", models.SeverityCritical}}},
		{name: "storage unavailable", probes: []collector.ProbeResult{validationProbe("storage", collector.CategoryStorage, collector.StatusRequiresAdmin, nil, "synthetic permission limitation")}, statuses: []collector.ProbeStatus{collector.StatusRequiresAdmin}, expectedLimitations: 1},
		{name: "storage partial data", probes: []collector.ProbeResult{validationProbe("storage", collector.CategoryStorage, collector.StatusPartial, &models.StorageMetrics{Volumes: []models.VolumeMetrics{warningVolume}}, "one volume unavailable")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, findings: []expectedFinding{{"FINDING-STORAGE-001", models.SeverityWarning}}, expectedLimitations: 1},
		{name: "service running", probes: []collector.ProbeResult{validationProbe("services", collector.CategoryServices, collector.StatusSuccess, &models.ServicesMetrics{TotalCount: 1, RunningCount: 1, Services: []models.ServiceInfo{{Name: "synthetic-agent", StartType: "Auto", Status: "Running"}}}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}},
		{name: "service stopped auto start", probes: []collector.ProbeResult{validationProbe("services", collector.CategoryServices, collector.StatusSuccess, &models.ServicesMetrics{FailedAutoStartCount: 1, FailedAutoStart: []models.ServiceInfo{autoService}}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-SVC-001", models.SeverityInfo}}},
		{name: "service inaccessible", probes: []collector.ProbeResult{validationProbe("services", collector.CategoryServices, collector.StatusRequiresAdmin, nil, "synthetic permission limitation")}, statuses: []collector.ProbeStatus{collector.StatusRequiresAdmin}, expectedLimitations: 1},
		{name: "service inventory unsupported", probes: []collector.ProbeResult{validationProbe("services", collector.CategoryServices, collector.StatusUnsupported, nil, "synthetic unsupported platform")}, statuses: []collector.ProbeStatus{collector.StatusUnsupported}, expectedLimitations: 1},
		{name: "network and DNS normal", probes: []collector.ProbeResult{validationProbe("network", collector.CategoryNetwork, collector.StatusSuccess, &models.NetworkMetrics{Adapters: []models.NetworkAdapterMetrics{{Name: "eth0", Status: "Up"}}, DNSTest: &models.DNSResolutionTest{QueryTarget: "example.com", Success: true, DurationMS: 1499}}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}},
		{name: "DNS failure", probes: []collector.ProbeResult{validationProbe("network", collector.CategoryNetwork, collector.StatusPartial, &models.NetworkMetrics{DNSTest: &models.DNSResolutionTest{QueryTarget: "missing.invalid", Error: "synthetic name resolution failure", DurationMS: 20}}, "DNS measurement failed")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, findings: []expectedFinding{{"FINDING-NET-002", models.SeverityWarning}}, expectedLimitations: 1},
		{name: "DNS timeout", probes: []collector.ProbeResult{validationProbe("network", collector.CategoryNetwork, collector.StatusPartial, &models.NetworkMetrics{DNSTest: &models.DNSResolutionTest{QueryTarget: "example.com", Error: "synthetic timeout", DurationMS: 1500}}, "DNS timed out")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, findings: []expectedFinding{{"FINDING-NET-002", models.SeverityWarning}}, expectedLimitations: 1},
		{name: "partial network data without DNS", probes: []collector.ProbeResult{validationProbe("network", collector.CategoryNetwork, collector.StatusPartial, &models.NetworkMetrics{Adapters: []models.NetworkAdapterMetrics{{Name: "eth0", Status: "Up"}}}, "DNS unavailable")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, expectedLimitations: 1},
		{name: "network unavailable", probes: []collector.ProbeResult{validationProbe("network", collector.CategoryNetwork, collector.StatusFailed, nil, "synthetic collection failure")}, statuses: []collector.ProbeStatus{collector.StatusFailed}, expectedLimitations: 1},
		{name: "reliability known crash", probes: []collector.ProbeResult{validationProbe("reliability", collector.CategoryReliability, collector.StatusSuccess, &models.ReliabilityMetrics{TimeWindowHours: 24, BugChecks: []models.BugCheckEvent{{BugCheckCode: "synthetic-code"}}}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}, findings: []expectedFinding{{"FINDING-REL-001", models.SeverityCritical}}},
		{name: "reliability no events", probes: []collector.ProbeResult{validationProbe("reliability", collector.CategoryReliability, collector.StatusSuccess, &models.ReliabilityMetrics{TimeWindowHours: 24}, "")}, statuses: []collector.ProbeStatus{collector.StatusSuccess}},
		{name: "reliability access failure", probes: []collector.ProbeResult{validationProbe("reliability", collector.CategoryReliability, collector.StatusFailed, nil, "synthetic event access failure")}, statuses: []collector.ProbeStatus{collector.StatusFailed}, expectedLimitations: 1},
		{name: "reliability unsupported", probes: []collector.ProbeResult{validationProbe("reliability", collector.CategoryReliability, collector.StatusUnsupported, nil, "synthetic unsupported platform")}, statuses: []collector.ProbeStatus{collector.StatusUnsupported}, expectedLimitations: 1},
		{name: "reliability partial events", probes: []collector.ProbeResult{validationProbe("reliability", collector.CategoryReliability, collector.StatusPartial, &models.ReliabilityMetrics{TimeWindowHours: 24, BugChecks: []models.BugCheckEvent{{}}}, "application channel unavailable")}, statuses: []collector.ProbeStatus{collector.StatusPartial}, findings: []expectedFinding{{"FINDING-REL-001", models.SeverityCritical}}, expectedLimitations: 1},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			report := models.NewDiagnosticReport()
			collector.NewEngine().Normalize(scenario.probes, report)
			if report.CollectionStatus.TotalProbes != len(scenario.statuses) {
				t.Errorf("total probes = %d, want %d", report.CollectionStatus.TotalProbes, len(scenario.statuses))
			}
			if len(report.CollectionStatus.Probes) != len(scenario.statuses) {
				t.Fatalf("probe record count = %d, want %d", len(report.CollectionStatus.Probes), len(scenario.statuses))
			}
			counts := map[collector.ProbeStatus]int{}
			for i, want := range scenario.statuses {
				counts[want]++
				if got := collector.ProbeStatus(report.CollectionStatus.Probes[i].Status); got != want {
					t.Errorf("probe %q status = %q, want %q", report.CollectionStatus.Probes[i].ProbeID, got, want)
				}
				if want != collector.StatusSuccess && report.CollectionStatus.Probes[i].Reason == "" {
					t.Errorf("probe %q has status %q without a reason", report.CollectionStatus.Probes[i].ProbeID, want)
				}
			}
			if report.CollectionStatus.Successful != counts[collector.StatusSuccess] || report.CollectionStatus.Partial != counts[collector.StatusPartial] || report.CollectionStatus.Failed != counts[collector.StatusFailed] || report.CollectionStatus.RequiresAdmin != counts[collector.StatusRequiresAdmin] || report.CollectionStatus.Unsupported != counts[collector.StatusUnsupported] {
				t.Errorf("normalized status counters disagree with probe records: success=%d partial=%d failed=%d admin=%d unsupported=%d", report.CollectionStatus.Successful, report.CollectionStatus.Partial, report.CollectionStatus.Failed, report.CollectionStatus.RequiresAdmin, report.CollectionStatus.Unsupported)
			}
			if len(report.Limitations) != scenario.expectedLimitations {
				t.Errorf("limitation count = %d, want %d", len(report.Limitations), scenario.expectedLimitations)
			}

			findings := analyzer.NewDefaultEngine().EvaluateAll(context.Background(), report)
			gotFindings := make([]string, 0, len(findings))
			for _, finding := range findings {
				gotFindings = append(gotFindings, string(finding.ID)+":"+string(finding.Severity))
			}
			sort.Strings(gotFindings)
			wantFindings := make([]string, 0, len(scenario.findings))
			for _, finding := range scenario.findings {
				wantFindings = append(wantFindings, string(finding.id)+":"+string(finding.severity))
			}
			sort.Strings(wantFindings)
			if !reflect.DeepEqual(gotFindings, wantFindings) {
				t.Errorf("findings = %v, want %v", gotFindings, wantFindings)
			}
			for _, want := range scenario.evidence {
				found := false
				for _, finding := range findings {
					if finding.ID == want.findingID && reflect.DeepEqual(finding.Evidence[want.key], want.value) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no %s finding contained evidence %s=%v", want.findingID, want.key, want.value)
				}
			}
		})
	}
}

func TestDiagnosticValidationSanitizationPreservesMeaning(t *testing.T) {
	const syntheticMAC = "02:00:00:00:00:01"
	const syntheticIP = "192.0.2.44"
	report := models.NewDiagnosticReport()
	report.Metadata.Hostname = "VALIDATION-NODE-001"
	report.Data.Network = &models.NetworkMetrics{Adapters: []models.NetworkAdapterMetrics{{
		Name: "eth0", Description: "synthetic adapter", MACAddress: syntheticMAC, Status: "Up", InErrors: 2,
		IPv4Addresses: []string{syntheticIP},
	}}}
	findings := analyzer.NewDefaultEngine().EvaluateAll(context.Background(), report)
	if len(findings) != 1 || findings[0].ID != "FINDING-NET-001" {
		t.Fatalf("synthetic packet-error evidence produced unexpected findings: %v", findingKeys(findings))
	}
	wantEvidence := findings[0].Evidence["in_errors"]
	wantSeverity := findings[0].Severity

	sanitizer.SanitizeReport(report)
	if report.Findings[0].ID != "FINDING-NET-001" || report.Findings[0].Severity != wantSeverity || !reflect.DeepEqual(report.Findings[0].Evidence["in_errors"], wantEvidence) {
		t.Fatal("sanitization changed finding identity, severity, or observed error count")
	}
	if report.Data.Network.Adapters[0].InErrors != 2 || report.Data.Network.Adapters[0].MACAddress != "[MAC_REDACTED]" {
		t.Fatal("sanitization changed diagnostic counters or failed to redact the synthetic MAC")
	}
	encoded, err := report.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), syntheticMAC) || strings.Contains(string(encoded), syntheticIP) || strings.Contains(string(encoded), "VALIDATION-NODE-001") {
		t.Fatal("sanitized synthetic report retained an identifier")
	}
}

func TestMemoryValidationSeparatesCommitAndPhysicalEvidence(t *testing.T) {
	const mib = uint64(1024 * 1024)
	const gib = uint64(1024 * 1024 * 1024)
	tests := []struct {
		name            string
		metrics         *models.MemoryMetrics
		wantTitle       string
		wantEvidenceKey string
		withoutEvidence []string
		withoutText     string
	}{
		{
			name:      "commit critical with unavailable physical memory",
			metrics:   &models.MemoryMetrics{CommitLimitBytes: 10000 * mib, CommitTotalBytes: 9600 * mib, CommitPercent: 96},
			wantTitle: "Critical virtual memory commit exhaustion", wantEvidenceKey: "commit_percent",
			withoutEvidence: []string{"total_gb", "available_gb"}, withoutText: "available physical RAM",
		},
		{
			name:      "physical critical with missing commit metrics",
			metrics:   &models.MemoryMetrics{TotalBytes: 16 * gib, AvailableBytes: 256 * mib},
			wantTitle: "Critical physical memory availability", wantEvidenceKey: "available_gb",
			withoutEvidence: []string{"commit_total_gb", "commit_limit_gb", "commit_percent"}, withoutText: "commit",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := models.NewDiagnosticReport()
			report.Data.Memory = tt.metrics
			findings := analyzer.NewDefaultEngine().EvaluateAll(context.Background(), report)
			if len(findings) != 1 {
				t.Fatalf("finding count = %d, want 1", len(findings))
			}
			finding := findings[0]
			if finding.Title != tt.wantTitle {
				t.Errorf("title = %q, want %q", finding.Title, tt.wantTitle)
			}
			if _, ok := finding.Evidence[tt.wantEvidenceKey]; !ok {
				t.Errorf("evidence is missing %q", tt.wantEvidenceKey)
			}
			for _, key := range tt.withoutEvidence {
				if _, ok := finding.Evidence[key]; ok {
					t.Errorf("evidence unexpectedly contains unavailable measurement %q", key)
				}
			}
			if strings.Contains(strings.ToLower(finding.Observation), tt.withoutText) {
				t.Errorf("observation claims unavailable measurement %q", tt.withoutText)
			}
		})
	}
}

func findingKeys(findings []models.Finding) []string {
	keys := make([]string, 0, len(findings))
	for _, finding := range findings {
		keys = append(keys, string(finding.ID)+":"+string(finding.Severity))
	}
	sort.Strings(keys)
	return keys
}
