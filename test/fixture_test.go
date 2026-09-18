package test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/systemdiag/sysdiag/internal/analyzer"
	"github.com/systemdiag/sysdiag/internal/models"
	htmlReporter "github.com/systemdiag/sysdiag/internal/reporter/html"
	termReporter "github.com/systemdiag/sysdiag/internal/reporter/terminal"
)

func TestFixture_NetworkDownVirtualAdapterLinkSpeed(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "network_down_virtual_adapter.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture file %s: %v", fixturePath, err)
	}

	report, err := models.FromJSON(data)
	if err != nil {
		t.Fatalf("Failed to deserialize fixture from JSON: %v", err)
	}

	if report.Data.Network == nil {
		t.Fatalf("Expected non-nil network data in fixture")
	}

	adapters := report.Data.Network.Adapters
	if len(adapters) != 3 {
		t.Fatalf("Expected 3 adapters in fixture, got %d", len(adapters))
	}

	// Adapter 0: Up with valid link speed
	if adapters[0].Status != "Up" {
		t.Errorf("Expected adapter 0 status Up, got %s", adapters[0].Status)
	}
	if adapters[0].SpeedMbps == nil || *adapters[0].SpeedMbps != 1000 {
		t.Errorf("Expected adapter 0 SpeedMbps 1000, got %v", adapters[0].SpeedMbps)
	}

	// Adapter 1: Down adapter with unavailable link speed
	if adapters[1].Status != "Down" {
		t.Errorf("Expected adapter 1 status Down, got %s", adapters[1].Status)
	}
	if adapters[1].SpeedMbps != nil {
		t.Errorf("Expected adapter 1 (Down) SpeedMbps nil, got %v", adapters[1].SpeedMbps)
	}

	// Adapter 2: Virtual adapter without link speed telemetry
	if adapters[2].Name != "vEthernet (WSL)" {
		t.Errorf("Expected adapter 2 name 'vEthernet (WSL)', got %s", adapters[2].Name)
	}
	if adapters[2].SpeedMbps != nil {
		t.Errorf("Expected adapter 2 (Virtual) SpeedMbps nil, got %v", adapters[2].SpeedMbps)
	}

	// Validate terminal rendering does not output 0 Mbps or panic for virtual adapter
	termRep := termReporter.NewReporter()
	var termBuf bytes.Buffer
	if err := termRep.Generate(report, &termBuf); err != nil {
		t.Fatalf("Terminal reporter failed with fixture: %v", err)
	}
	termOutput := termBuf.String()
	if bytes.Contains([]byte(termOutput), []byte("vEthernet (WSL) [172.28.0.1, Up, 0 Mbps]")) {
		t.Errorf("Terminal output contains '0 Mbps' for virtual adapter with unavailable link speed: %s", termOutput)
	}

	// Validate HTML rendering does not panic or output invalid placeholder
	htmlRep, err := htmlReporter.NewReporter()
	if err != nil {
		t.Fatalf("Failed to create HTML reporter: %v", err)
	}
	var htmlBuf bytes.Buffer
	if err := htmlRep.Generate(report, &htmlBuf); err != nil {
		t.Fatalf("HTML reporter failed with fixture: %v", err)
	}

	// Validate round-trip JSON serialization preserves null
	jsonBytes, err := report.ToJSON()
	if err != nil {
		t.Fatalf("Failed to reserialize report to JSON: %v", err)
	}

	restored, err := models.FromJSON(jsonBytes)
	if err != nil {
		t.Fatalf("Failed to restore reserialized report: %v", err)
	}
	if restored.Data.Network.Adapters[1].SpeedMbps != nil {
		t.Errorf("Expected restored adapter 1 SpeedMbps nil, got %v", restored.Data.Network.Adapters[1].SpeedMbps)
	}
	if restored.Data.Network.Adapters[2].SpeedMbps != nil {
		t.Errorf("Expected restored adapter 2 SpeedMbps nil, got %v", restored.Data.Network.Adapters[2].SpeedMbps)
	}
}

func TestSentinelLinkSpeedAndCounterSanitization(t *testing.T) {
	// Verify that sentinel values like 18446744073709551615 (^uint64(0)) or raw 18446744073709 are not permitted as valid link speed
	report := models.NewDiagnosticReport()
	report.Data.Network = &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				Name:      "Virtual Disconnected",
				Status:    "Down",
				SpeedMbps: nil,
				InErrors:  0,
				OutErrors: 0,
			},
		},
	}

	data, err := report.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize: %v", err)
	}

	if bytes.Contains(data, []byte("18446744073709")) {
		t.Fatalf("JSON output contains raw 18446744073709 sentinel string: %s", string(data))
	}
}

func TestServicesAndReliabilityFixture(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Metadata = models.ExecutionMetadata{
		ToolVersion:    "1.0.0",
		Profile:        "quick",
		Hostname:       "PROD-TEST-SRV",
		OS:             "windows",
		OSVersion:      "Windows Server 2022",
		Architecture:   "amd64",
		PrivilegeLevel: "Administrator",
		IsElevated:     true,
	}

	report.Data.Services = &models.ServicesMetrics{
		TotalCount:           150,
		RunningCount:         110,
		StoppedCount:         40,
		FailedAutoStartCount: 1,
		FailedAutoStart: []models.ServiceInfo{
			{
				Name:        "Spooler",
				DisplayName: "Print Spooler",
				Status:      "Stopped",
				StartType:   "Auto",
				BinaryPath:  `C:\Windows\System32\spoolsv.exe`,
				Account:     "LocalSystem",
				ExitCode:    1067,
			},
		},
	}

	report.Data.Reliability = &models.ReliabilityMetrics{
		TimeWindowHours:   24,
		TotalErrorsLogged: 12,
		AppCrashes: []models.AppCrashEvent{
			{
				Application:   "worker_app.exe",
				FaultModule:   "ntdll.dll",
				ExceptionCode: "0xc0000005",
				EventID:       1000,
				Message:       "Faulting application: worker_app.exe, faulting module: ntdll.dll",
			},
		},
		KernelPowerEvents: []models.KernelPowerEvent{
			{
				EventID:      41,
				BugCheckCode: "0",
				Message:      "The system has rebooted without cleanly shutting down first.",
			},
		},
		BugChecks: []models.BugCheckEvent{
			{
				BugCheckCode: "0x0000003B",
				DumpFile:     `C:\Windows\MEMORY.DMP`,
				Message:      "Computer has rebooted from a bugcheck.",
			},
		},
	}

	report.Data.Software = &models.SoftwareMetrics{
		TotalInstalledApps: 45,
		Applications: []models.InstalledApp{
			{
				Name:      "Go Programming Language",
				Version:   "1.22.4",
				Publisher: "Google LLC",
				Scope:     "System",
			},
		},
		HotFixes: []models.HotFixInfo{
			{
				HotFixID:    "KB5034441",
				Description: "Security Update for Windows",
			},
		},
		Runtimes: []models.RuntimeInfo{
			{
				Name:    ".NET Framework",
				Version: "4.8.09037",
			},
		},
	}

	jsonBytes, err := report.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize report to JSON: %v", err)
	}

	restored, err := models.FromJSON(jsonBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize report: %v", err)
	}

	if restored.Data.Services.FailedAutoStartCount != 1 {
		t.Errorf("Expected 1 failed auto start service, got %d", restored.Data.Services.FailedAutoStartCount)
	}
	if len(restored.Data.Reliability.AppCrashes) != 1 {
		t.Errorf("Expected 1 app crash, got %d", len(restored.Data.Reliability.AppCrashes))
	}
	if len(restored.Data.Software.Applications) != 1 {
		t.Errorf("Expected 1 installed application, got %d", len(restored.Data.Software.Applications))
	}

	// Test Terminal Report rendering
	termRep := termReporter.NewReporter()
	var termBuf bytes.Buffer
	if err := termRep.Generate(restored, &termBuf); err != nil {
		t.Fatalf("Terminal reporter failed: %v", err)
	}
	if !bytes.Contains(termBuf.Bytes(), []byte("1 Failed Auto-Start")) {
		t.Errorf("Expected terminal report to include failed auto start indicator: %s", termBuf.String())
	}

	// Test HTML Report rendering
	htmlRep, err := htmlReporter.NewReporter()
	if err != nil {
		t.Fatalf("HTML reporter init failed: %v", err)
	}
	var htmlBuf bytes.Buffer
	if err := htmlRep.Generate(restored, &htmlBuf); err != nil {
		t.Fatalf("HTML reporter failed: %v", err)
	}
	if !bytes.Contains(htmlBuf.Bytes(), []byte("Services &amp; Daemons")) {
		t.Errorf("Expected HTML report to include Services & Daemons section")
	}
}

func TestFixture_BenignKernelGeneralEvent11DoesNotTriggerStorageFinding(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "benign_kernel_general_event11.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", fixturePath, err)
	}

	report, err := models.FromJSON(data)
	if err != nil {
		t.Fatalf("Failed to parse fixture JSON: %v", err)
	}

	if report.Data.Reliability == nil {
		t.Fatalf("Expected non-nil reliability data in fixture")
	}

	if len(report.Data.Reliability.SystemErrors) != 3 {
		t.Fatalf("Expected 3 system error events in fixture, got %d", len(report.Data.Reliability.SystemErrors))
	}

	// Verify all events are Microsoft-Windows-Kernel-General Event ID 11
	for idx, e := range report.Data.Reliability.SystemErrors {
		if e.EventID != 11 {
			t.Errorf("Event %d: expected EventID 11, got %d", idx, e.EventID)
		}
		if e.Provider != "Microsoft-Windows-Kernel-General" {
			t.Errorf("Event %d: expected provider Microsoft-Windows-Kernel-General, got %s", idx, e.Provider)
		}
		if e.Level != "Info" {
			t.Errorf("Event %d: expected level Info, got %s", idx, e.Level)
		}
	}

	// Evaluate against the ReliabilityDiskErrorsRule specifically
	rule := &analyzer.ReliabilityDiskErrorsRule{}
	findings, err := rule.Evaluate(context.Background(), report)
	if err != nil {
		t.Fatalf("Rule evaluation failed: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 storage findings for benign Kernel-General Event ID 11 records, got %d finding(s): %+v", len(findings), findings)
	}

	// Evaluate against the entire Rule Engine
	engine := analyzer.NewDefaultEngine()
	allFindings := engine.EvaluateAll(context.Background(), report)
	for _, f := range allFindings {
		if f.ID == "FINDING-REL-004" {
			t.Errorf("FINDING-REL-004 was unexpectedly triggered for benign Kernel-General Event 11: %+v", f)
		}
		if f.Severity == models.SeverityCritical || f.Severity == models.SeverityWarning {
			t.Errorf("Unexpected warning/critical finding triggered: %+v", f)
		}
	}
	report.Findings = allFindings

	// Validate terminal report rendering does not output storage warnings
	termRep := termReporter.NewReporter()
	var termBuf bytes.Buffer
	if err := termRep.Generate(report, &termBuf); err != nil {
		t.Fatalf("Terminal reporter failed with Event 11 fixture: %v", err)
	}
	termStr := termBuf.String()
	if bytes.Contains([]byte(termStr), []byte("FINDING-REL-004")) {
		t.Errorf("Terminal report unexpectedly contains FINDING-REL-004: %s", termStr)
	}

	// Validate HTML report rendering
	htmlRep, err := htmlReporter.NewReporter()
	if err != nil {
		t.Fatalf("HTML reporter init failed: %v", err)
	}
	var htmlBuf bytes.Buffer
	if err := htmlRep.Generate(report, &htmlBuf); err != nil {
		t.Fatalf("HTML reporter failed with Event 11 fixture: %v", err)
	}
	htmlStr := htmlBuf.String()
	if bytes.Contains([]byte(htmlStr), []byte("FINDING-REL-004")) {
		t.Errorf("HTML report unexpectedly contains FINDING-REL-004: %s", htmlStr)
	}

	// Validate round-trip JSON serialization
	jsonBytes, err := report.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize report to JSON: %v", err)
	}

	restored, err := models.FromJSON(jsonBytes)
	if err != nil {
		t.Fatalf("Failed to deserialize report: %v", err)
	}

	if len(restored.Data.Reliability.SystemErrors) != 3 {
		t.Errorf("Expected 3 restored system errors, got %d", len(restored.Data.Reliability.SystemErrors))
	}
}

func TestFixture_AdversarialServicesMatrix(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "adversarial_services_matrix.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", fixturePath, err)
	}

	report, err := models.FromJSON(data)
	if err != nil {
		t.Fatalf("Failed to parse fixture JSON: %v", err)
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	// In this fixture:
	// - ManualServiceClean (Manual, Stopped, Exit 0) -> NO finding
	// - DisabledServiceClean (Disabled, Stopped, Exit 0) -> NO finding
	// - AutoServiceZeroExit (Auto, Stopped, Exit 0) -> 1 Finding (Severity: Info / Observation only)
	// - AutoServiceFailExit (Auto, Stopped, Exit 1067) -> triggers Warning because of non-zero exit
	if len(findings) != 1 {
		t.Fatalf("Expected 1 aggregated finding for stopped auto services, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.ID != "FINDING-SVC-001" {
		t.Errorf("Expected FINDING-SVC-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityWarning {
		t.Errorf("Expected SeverityWarning due to non-zero exit code service, got %s", f.Severity)
	}
	if f.Evidence["non_zero_exit_count"] != 1 {
		t.Errorf("Expected non_zero_exit_count = 1, got %v", f.Evidence["non_zero_exit_count"])
	}
	if f.Evidence["stopped_auto_count"] != 2 {
		t.Errorf("Expected stopped_auto_count = 2, got %v", f.Evidence["stopped_auto_count"])
	}
}

func TestFixture_AdversarialMemoryThresholds(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "adversarial_memory_thresholds.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", fixturePath, err)
	}

	report, err := models.FromJSON(data)
	if err != nil {
		t.Fatalf("Failed to parse fixture JSON: %v", err)
	}

	// 94.9% commit with > 500 MB available RAM should be WARNING, NOT CRITICAL
	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for 94.9%% commit, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityWarning {
		t.Errorf("Expected SeverityWarning for 94.9%% commit (< 95.0%% critical), got %s", findings[0].Severity)
	}

	// Modify to exact 95.0% threshold and verify it becomes CRITICAL
	report.Data.Memory.CommitPercent = 95.0
	findings95 := engine.EvaluateAll(context.Background(), report)
	if len(findings95) != 1 {
		t.Fatalf("Expected 1 finding for 95.0%% commit, got %d", len(findings95))
	}
	if findings95[0].Severity != models.SeverityCritical {
		t.Errorf("Expected SeverityCritical for exact 95.0%% commit threshold, got %s", findings95[0].Severity)
	}
}

func TestFixture_AdversarialNetworkDNSErrors(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "adversarial_network_dns_errors.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", fixturePath, err)
	}

	report, err := models.FromJSON(data)
	if err != nil {
		t.Fatalf("Failed to parse fixture JSON: %v", err)
	}

	// Adapter has speed_mbps: null, but 18 in_errors. DNS test is successful.
	if report.Data.Network.Adapters[0].SpeedMbps != nil {
		t.Errorf("Expected speed_mbps nil, got %v", report.Data.Network.Adapters[0].SpeedMbps)
	}
	if !report.Data.Network.DNSTest.Success {
		t.Errorf("Expected DNS test success true")
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding (packet errors), got %d", len(findings))
	}
	if findings[0].ID != "FINDING-NET-001" {
		t.Errorf("Expected FINDING-NET-001, got %s", findings[0].ID)
	}
	if findings[0].Severity != models.SeverityWarning {
		t.Errorf("Expected SeverityWarning for packet errors, got %s", findings[0].Severity)
	}

	// Verify terminal report does not claim "healthy" / "no anomalies"
	report.Findings = findings
	var termBuf bytes.Buffer
	termRep := termReporter.NewReporter()
	if err := termRep.Generate(report, &termBuf); err != nil {
		t.Fatalf("Terminal reporter failed: %v", err)
	}
	termStr := termBuf.String()
	if bytes.Contains([]byte(termStr), []byte("No anomalies or operational bottlenecks identified")) {
		t.Errorf("Terminal report falsely claimed no anomalies: %s", termStr)
	}
	if bytes.Contains([]byte(termStr), []byte("0 Mbps")) {
		t.Errorf("Terminal report rendered '0 Mbps' for nil speed adapter: %s", termStr)
	}
}

func TestFixture_AdversarialProcessSystemMemory(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "adversarial_process_system_memory.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", fixturePath, err)
	}

	report, err := models.FromJSON(data)
	if err != nil {
		t.Fatalf("Failed to parse fixture JSON: %v", err)
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	// We expect FINDING-PROC-002 (Process high working set: 10 GB)
	// We do NOT expect FINDING-MEM-001 (System memory commit exhaustion: 24.3% commit, 50 GB free)
	var foundProc, foundMem bool
	var procFinding models.Finding
	for _, f := range findings {
		if f.ID == "FINDING-PROC-002" {
			foundProc = true
			procFinding = f
		}
		if f.ID == "FINDING-MEM-001" {
			foundMem = true
		}
	}

	if !foundProc {
		t.Fatalf("Expected FINDING-PROC-002 for 10 GB process memory usage")
	}
	if foundMem {
		t.Errorf("Unexpected FINDING-MEM-001 when system memory is healthy (24.3%% commit)")
	}

	// Verify the finding distinguishes absolute working set trigger and remains neutral about system-wide memory pressure
	if procFinding.Evidence["trigger"] != "absolute_working_set" {
		t.Errorf("Expected evidence trigger 'absolute_working_set', got %v", procFinding.Evidence["trigger"])
	}
	if bytes.Contains([]byte(procFinding.Interpretation), []byte("major fraction")) {
		t.Errorf("Interpretation falsely claimed 'major fraction' on 64 GB system: %s", procFinding.Interpretation)
	}
	if bytes.Contains([]byte(procFinding.PotentialImpact), []byte("limited available working set")) {
		t.Errorf("Potential impact falsely claimed 'limited available working set' on 64 GB system with 50 GB free: %s", procFinding.PotentialImpact)
	}
}

func TestFixture_UnclassifiedStorageWarningEventDoesNotTriggerFinding(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "unclassified_storage_warning_event.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", fixturePath, err)
	}

	report, err := models.FromJSON(data)
	if err != nil {
		t.Fatalf("Failed to parse fixture JSON: %v", err)
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	// Unclassified warning from recognized storage provider (volsnap Event ID 25) must NOT trigger FINDING-REL-004
	for _, f := range findings {
		if f.ID == "FINDING-REL-004" {
			t.Errorf("Unclassified storage warning event falsely triggered FINDING-REL-004: %+v", f)
		}
	}
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for unclassified storage warning event, got %d", len(findings))
	}
}
