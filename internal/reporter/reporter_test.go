package reporter_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/systemdiag/sysdiag/internal/models"
	htmlReporter "github.com/systemdiag/sysdiag/internal/reporter/html"
	jsonReporter "github.com/systemdiag/sysdiag/internal/reporter/json"
	termReporter "github.com/systemdiag/sysdiag/internal/reporter/terminal"
)

func createTestReport() *models.DiagnosticReport {
	r := models.NewDiagnosticReport()
	r.Metadata = models.ExecutionMetadata{
		ToolVersion:     "1.0.0",
		ScanTimestamp:   time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
		ScanDurationMS:  450,
		Profile:         "quick",
		Hostname:        "SRV-TEST-01",
		OS:              "windows",
		OSVersion:       "Microsoft Windows 11",
		Architecture:    "amd64",
		PrivilegeLevel:  "User",
		IsElevated:      false,
		ExecutionPath:   `C:\sysdiag.exe`,
		OutputDirectory: `C:\output`,
	}
	r.CollectionStatus = models.CollectionStatus{
		TotalProbes: 3,
		Successful:  3,
	}
	r.Data.System = &models.SystemMetrics{
		Hostname:      "SRV-TEST-01",
		OSName:        "Microsoft Windows 11 Enterprise",
		OSBuild:       "22631.3007",
		Architecture:  "amd64",
		UptimeSeconds: 86400,
		BootTime:      time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		Virtualization: models.VirtualizationInfo{
			IsVirtual: false,
		},
	}
	r.Data.CPU = &models.CPUMetrics{
		Model:              "13th Gen Intel(R) Core(TM) i7-13700K",
		PhysicalCores:      16,
		LogicalCores:       24,
		UtilizationPercent: 88.0,
		UserPercent:        70.0,
		KernelPercent:      18.0,
	}
	r.Data.Memory = &models.MemoryMetrics{
		TotalBytes:       34359738368,
		AvailableBytes:   8589934592,
		UsedBytes:        25769803776,
		UsedPercent:      75.0,
		CommitLimitBytes: 42949672960,
		CommitTotalBytes: 30064771072,
		CommitPercent:    70.0,
	}
	r.Findings = []models.Finding{
		{
			ID:          "FINDING-CPU-001",
			Category:    "cpu",
			Severity:    models.SeverityWarning,
			Title:       "High CPU Load",
			Observation: "CPU load reached 88%",
			Evidence: map[string]interface{}{
				"utilization_percent": 88.0,
			},
			Interpretation:  "High processor utilization.",
			PotentialImpact: "Potential latency.",
			Recommendation:  "Review task manager.",
			Confidence:      models.ConfidenceHigh,
		},
	}
	return r
}

func TestReporters_JSON(t *testing.T) {
	report := createTestReport()
	rep := jsonReporter.NewReporter()
	var buf bytes.Buffer
	if err := rep.Generate(report, &buf); err != nil {
		t.Fatalf("JSON generation failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"schema_version": "1.0.0"`) {
		t.Errorf("Expected schema_version in JSON, got: %s", out)
	}
	if !strings.Contains(out, `"SRV-TEST-01"`) {
		t.Errorf("Expected hostname in JSON output")
	}
}

func TestReporters_Terminal(t *testing.T) {
	report := createTestReport()
	rep := termReporter.NewReporter()
	var buf bytes.Buffer
	if err := rep.Generate(report, &buf); err != nil {
		t.Fatalf("Terminal generation failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "EXECUTIVE REPORT") {
		t.Errorf("Expected EXECUTIVE REPORT header, got: %s", out)
	}
	if !strings.Contains(out, "FINDING-CPU-001") {
		t.Errorf("Expected FINDING-CPU-001 in terminal output, got: %s", out)
	}
	if !strings.Contains(out, "Collection Coverage:") || !strings.Contains(out, "100.0%") {
		t.Errorf("Expected Collection Coverage 100.0%% in terminal output, got: %s", out)
	}
}

func TestReporters_HTML(t *testing.T) {
	report := createTestReport()
	rep, err := htmlReporter.NewReporter()
	if err != nil {
		t.Fatalf("Failed to initialize HTML reporter: %v", err)
	}

	var buf bytes.Buffer
	if err := rep.Generate(report, &buf); err != nil {
		t.Fatalf("HTML generation failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Errorf("Expected valid HTML header")
	}
	if !strings.Contains(out, "Executive Summary &amp; Findings Dashboard") {
		t.Errorf("Expected Executive Summary section in HTML, got: %s", out)
	}
	if !strings.Contains(out, "FINDING-CPU-001") {
		t.Errorf("Expected finding ID in HTML report")
	}
	if !strings.Contains(out, "Send This File to Support") {
		t.Errorf("Expected handover banner in HTML report")
	}
	if !strings.Contains(out, "Safe &amp; Read-Only (0 Changes Made)") {
		t.Errorf("Expected safe & read-only indicator in HTML report")
	}
	if !strings.Contains(out, "Highest-Confidence Diagnostic Observations") {
		t.Errorf("Expected highest-confidence observations in HTML report")
	}
	if !strings.Contains(out, "filterFindings") || !strings.Contains(out, "filterTelemetry") {
		t.Errorf("Expected embedded client-side filtering scripts in HTML report")
	}
	if strings.Contains(out, "http://") || strings.Contains(out, "https://") && !strings.Contains(out, "systemdiag.io") {
		// Check that there are no remote script or stylesheet URLs embedded
		if strings.Contains(out, `<script src="http`) || strings.Contains(out, `<link rel="stylesheet" href="http`) {
			t.Errorf("Found remote asset link in HTML report; must be 100%% self-contained")
		}
	}
}

func TestReporters_NoAnomaliesAndLimitations(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Metadata = models.ExecutionMetadata{
		ToolVersion:    "1.0.0",
		ScanTimestamp:  time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
		ScanDurationMS: 200,
		Profile:        "quick",
		Hostname:       "CLEAN-NODE-01",
		OS:             "windows",
		OSVersion:      "Windows 11 Pro",
		Architecture:   "amd64",
		PrivilegeLevel: "User",
	}
	report.CollectionStatus = models.CollectionStatus{
		TotalProbes:   4,
		Successful:    3,
		RequiresAdmin: 1,
	}
	report.Limitations = []models.CollectionLimitation{
		{
			ProbeID:           "probe_admin_test",
			Category:          "storage",
			Reason:            "Requires elevated administrator privileges to query SMART telemetry",
			PrivilegeRequired: "Administrator",
		},
	}
	report.Data.System = &models.SystemMetrics{
		Hostname:      "CLEAN-NODE-01",
		OSName:        "Windows 11 Pro",
		Architecture:  "amd64",
		UptimeSeconds: 3600,
	}
	report.Data.Network = &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				Name:      "vEthernet",
				Status:    "Down",
				SpeedMbps: nil, // Must not crash or print 0 Mbps
			},
		},
	}

	// 1. Terminal Reporter
	termRep := termReporter.NewReporter()
	var termBuf bytes.Buffer
	if err := termRep.Generate(report, &termBuf); err != nil {
		t.Fatalf("Terminal reporter failed on clean report: %v", err)
	}
	termStr := termBuf.String()
	if !strings.Contains(termStr, "No anomalies or operational bottlenecks identified") {
		t.Errorf("Expected 'No anomalies' in terminal output, got: %s", termStr)
	}
	if !strings.Contains(termStr, "COLLECTION LIMITATIONS") {
		t.Errorf("Expected 'COLLECTION LIMITATIONS' in terminal output, got: %s", termStr)
	}

	// 2. HTML Reporter
	htmlRep, err := htmlReporter.NewReporter()
	if err != nil {
		t.Fatalf("Failed to initialize HTML reporter: %v", err)
	}
	var htmlBuf bytes.Buffer
	if err := htmlRep.Generate(report, &htmlBuf); err != nil {
		t.Fatalf("HTML reporter failed on clean report: %v", err)
	}
	htmlStr := htmlBuf.String()
	if !strings.Contains(htmlStr, "No Anomalies Identified") {
		t.Errorf("Expected 'No Anomalies Identified' in HTML output")
	}
	if !strings.Contains(htmlStr, "Collection Limitations &amp; Privilege Calls") {
		t.Errorf("Expected 'Collection Limitations' section in HTML output")
	}
}
func TestReporters_HTMLIsSelfContainedAndMatchesJSON(t *testing.T) {
	report := createTestReport()
	htmlRep, err := htmlReporter.NewReporter()
	if err != nil {
		t.Fatal(err)
	}
	var h, j bytes.Buffer
	if err = htmlRep.Generate(report, &h); err != nil {
		t.Fatal(err)
	}
	if err = jsonReporter.NewReporter().Generate(report, &j); err != nil {
		t.Fatal(err)
	}
	out := h.String()
	for _, bad := range []string{"<script src=", "<link rel=\"stylesheet\" href=", "url(http", "fetch(", "XMLHttpRequest"} {
		if strings.Contains(out, bad) {
			t.Errorf("HTML has external runtime dependency marker %q", bad)
		}
	}
	if !strings.Contains(out, "FINDING-CPU-001") || !strings.Contains(j.String(), "FINDING-CPU-001") {
		t.Fatal("HTML and JSON do not contain the same diagnostic finding")
	}
	if !strings.Contains(out, "SRV-TEST-01") || !strings.Contains(j.String(), "SRV-TEST-01") {
		t.Fatal("HTML and JSON do not contain the same host metadata")
	}
}
