package analyzer_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/systemdiag/sysdiag/internal/analyzer"
	"github.com/systemdiag/sysdiag/internal/models"
	termReporter "github.com/systemdiag/sysdiag/internal/reporter/terminal"
)

func TestRuleEngine_NominalHealthyReport(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.CPU = &models.CPUMetrics{
		Model:              "AMD Ryzen 9 7950X",
		PhysicalCores:      16,
		LogicalCores:       32,
		UtilizationPercent: 24.5,
		UserPercent:        18.0,
		KernelPercent:      6.5,
	}
	report.Data.Memory = &models.MemoryMetrics{
		TotalBytes:       68719476736,
		AvailableBytes:   42949672960,
		UsedBytes:        25769803776,
		UsedPercent:      37.5,
		CommitLimitBytes: 85899345920,
		CommitTotalBytes: 30064771072,
		CommitPercent:    35.0,
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 0 {
		t.Fatalf("Expected 0 findings on nominal healthy system, got %d", len(findings))
	}
}

func TestRuleEngine_HighCPULoad(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.CPU = &models.CPUMetrics{
		Model:              "Intel(R) Core(TM) i9-14900K",
		PhysicalCores:      24,
		LogicalCores:       32,
		UtilizationPercent: 96.8,
		UserPercent:        82.0,
		KernelPercent:      14.8,
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for 96.8%% CPU load, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-CPU-001" {
		t.Errorf("Expected FINDING-CPU-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Expected CRITICAL severity for >95%% CPU, got %s", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("Expected HIGH confidence, got %s", f.Confidence)
	}
	if util, ok := f.Evidence["utilization_percent"].(float64); !ok || util != 96.8 {
		t.Errorf("Expected evidence utilization_percent = 96.8, got %v", f.Evidence["utilization_percent"])
	}
}

func TestRuleEngine_MemoryCommitExhaustion(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Memory = &models.MemoryMetrics{
		TotalBytes:       17179869184, // 16 GB
		AvailableBytes:   314572800,   // 300 MB (< 500MB)
		UsedBytes:        16865296384,
		UsedPercent:      98.1,
		CommitLimitBytes: 21474836480,
		CommitTotalBytes: 20937965568, // 97.5%
		CommitPercent:    97.5,
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for memory exhaustion, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-MEM-001" {
		t.Errorf("Expected FINDING-MEM-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %s", f.Severity)
	}
	if f.Evidence["commit_percent"] != 97.5 {
		t.Errorf("Expected evidence commit_percent = 97.5, got %v", f.Evidence["commit_percent"])
	}
}

func TestRuleEngine_StorageVolumeLowSpace(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Storage = &models.StorageMetrics{
		Volumes: []models.VolumeMetrics{
			{
				MountPoint:  "C:\\",
				VolumeName:  "OS",
				FileSystem:  "NTFS",
				DriveType:   "Fixed",
				TotalBytes:  1000000000000,
				FreeBytes:   30000000000,
				UsedBytes:   970000000000,
				UsedPercent: 97.0,
			},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for 97%% disk usage, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-STORAGE-001" {
		t.Errorf("Expected FINDING-STORAGE-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Expected CRITICAL severity for 97%% used volume, got %s", f.Severity)
	}
	if f.Evidence["mount_point"] != "C:\\" {
		t.Errorf("Expected mount_point C:\\, got %v", f.Evidence["mount_point"])
	}
}

func TestRuleEngine_StorageDiskQueueDepth(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Storage = &models.StorageMetrics{
		PhysicalDisks: []models.PhysicalDiskMetrics{
			{DeviceID: "0", Model: "Samsung SSD 990 PRO"},
		},
		IOMetrics: &models.StorageIOMetrics{
			AvgQueueDepth: 8.5,
			AvgLatencyMs:  45.2,
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for elevated disk queue depth, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-STORAGE-002" {
		t.Errorf("Expected FINDING-STORAGE-002, got %s", f.ID)
	}
	if f.Severity != models.SeverityWarning {
		t.Errorf("Expected WARNING severity, got %s", f.Severity)
	}
}

func TestRuleEngine_NetworkInterfaceErrors(t *testing.T) {
	speed := uint64(1000)
	report := models.NewDiagnosticReport()
	report.Data.Network = &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				ID:          "eth0",
				Name:        "Ethernet",
				Description: "Intel Controller",
				Status:      "Up",
				SpeedMbps:   &speed,
				InErrors:    15,
				OutErrors:   0,
			},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for network packet errors, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-NET-001" {
		t.Errorf("Expected FINDING-NET-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityWarning {
		t.Errorf("Expected WARNING severity for network errors, got %s", f.Severity)
	}
	if f.Evidence["in_errors"] != uint64(15) {
		t.Errorf("Expected evidence in_errors = 15, got %v", f.Evidence["in_errors"])
	}
}

func TestRuleEngine_NetworkDNSLatency(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Network = &models.NetworkMetrics{
		DNSTest: &models.DNSResolutionTest{
			QueryTarget: "test.local",
			Success:     false,
			Error:       "lookup test.local: no such host",
			DurationMS:  2050,
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for DNS failure, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-NET-002" {
		t.Errorf("Expected FINDING-NET-002, got %s", f.ID)
	}
	if f.Severity != models.SeverityWarning {
		t.Errorf("Expected WARNING severity, got %s", f.Severity)
	}
}

func TestRuleEngine_ServicesFailedAutoStart(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Services = &models.ServicesMetrics{
		FailedAutoStartCount: 1,
		FailedAutoStart: []models.ServiceInfo{
			{
				Name:        "Spooler",
				DisplayName: "Print Spooler",
				Status:      "Stopped",
				StartType:   "Auto",
				ExitCode:    1067,
			},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for failed auto-start services, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-SVC-001" {
		t.Errorf("Expected FINDING-SVC-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityWarning {
		t.Errorf("Expected WARNING severity for non-zero exit code service, got %s", f.Severity)
	}
}

func TestRuleEngine_ReliabilityBSODAndCrashes(t *testing.T) {
	now := time.Now()
	report := models.NewDiagnosticReport()
	report.Data.Reliability = &models.ReliabilityMetrics{
		TimeWindowHours: 24,
		BugChecks: []models.BugCheckEvent{
			{
				Timestamp:      now.Add(-2 * time.Hour),
				BugCheckCode:   "0x0000000a",
				BugCheckString: "IRQL_NOT_LESS_OR_EQUAL",
				DumpFile:       "C:\\Windows\\MEMORY.DMP",
				Message:        "Computer bugchecked with IRQL_NOT_LESS_OR_EQUAL",
			},
		},
		KernelPowerEvents: []models.KernelPowerEvent{
			{
				Timestamp: now.Add(-2 * time.Hour),
				EventID:   41,
				Message:   "System rebooted without cleanly shutting down",
			},
		},
		AppCrashes: []models.AppCrashEvent{
			{Timestamp: now.Add(-1 * time.Hour), Application: "worker.exe", FaultModule: "worker.exe", ExceptionCode: "0xc0000005", EventID: 1000},
			{Timestamp: now.Add(-2 * time.Hour), Application: "worker.exe", FaultModule: "worker.exe", ExceptionCode: "0xc0000005", EventID: 1000},
			{Timestamp: now.Add(-3 * time.Hour), Application: "worker.exe", FaultModule: "worker.exe", ExceptionCode: "0xc0000005", EventID: 1000},
		},
		SystemErrors: []models.SystemErrorEvent{
			{
				Timestamp: now.Add(-4 * time.Hour),
				Provider:  "disk",
				EventID:   15,
				Level:     "Error",
				Channel:   "System",
				Message:   "The device \\Device\\Harddisk0\\DR0 is not ready for access yet",
			},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	// Should trigger:
	// 1. BugCheck (CRITICAL)
	// 2. KernelPower 41 (WARNING)
	// 3. App crash loop for worker.exe (WARNING)
	// 4. Disk error event (WARNING)
	if len(findings) != 4 {
		t.Fatalf("Expected 4 reliability findings, got %d", len(findings))
	}
}

func TestRuleEngine_ProcessHighResource(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Processes = &models.ProcessMetrics{
		TotalProcesses: 150,
		TopCPU: []models.ProcessSummary{
			{
				PID:             4120,
				Name:            "stress_calc.exe",
				CPUPercent:      98.5,
				WorkingSetBytes: 1024 * 1024 * 500,
				ExecutablePath:  "C:\\Tools\\stress_calc.exe",
			},
		},
		TopMemory: []models.ProcessSummary{
			{
				PID:             5500,
				Name:            "large_db.exe",
				WorkingSetBytes: 1024 * 1024 * 1024 * 12,
				ExecutablePath:  "C:\\Program Files\\DB\\large_db.exe",
			},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 2 {
		t.Fatalf("Expected 2 process findings, got %d", len(findings))
	}
}

func TestRuleEngine_MultiFaultMachineScenario(t *testing.T) {
	// Comprehensive degraded machine state simulating a failing database server:
	// - 96% CPU utilization
	// - 96% Memory commit charge
	// - 97% C:\ drive utilization
	// - High queue depth
	// - Network interface errors
	// - Failed auto-start service
	// - BSOD BugCheck in reliability log
	report := models.NewDiagnosticReport()
	report.Data.CPU = &models.CPUMetrics{
		UtilizationPercent: 96.0,
		LogicalCores:       16,
	}
	report.Data.Memory = &models.MemoryMetrics{
		TotalBytes:       32 * 1024 * 1024 * 1024,
		AvailableBytes:   400 * 1024 * 1024,
		CommitPercent:    96.5,
		CommitTotalBytes: 38 * 1024 * 1024 * 1024,
		CommitLimitBytes: 40 * 1024 * 1024 * 1024,
	}
	report.Data.Storage = &models.StorageMetrics{
		Volumes: []models.VolumeMetrics{
			{
				MountPoint:  "C:\\",
				FileSystem:  "NTFS",
				DriveType:   "Fixed",
				TotalBytes:  1000 * 1024 * 1024 * 1024,
				FreeBytes:   30 * 1024 * 1024 * 1024,
				UsedPercent: 97.0,
			},
		},
		PhysicalDisks: []models.PhysicalDiskMetrics{
			{DeviceID: "0", Model: "NVMe Drive"},
		},
		IOMetrics: &models.StorageIOMetrics{
			AvgQueueDepth: 12.0,
			AvgLatencyMs:  65.0,
		},
	}
	speed := uint64(10000)
	report.Data.Network = &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				ID:        "nic1",
				Name:      "Ethernet 10G",
				Status:    "Up",
				SpeedMbps: &speed,
				InErrors:  100,
			},
		},
	}
	report.Data.Services = &models.ServicesMetrics{
		FailedAutoStart: []models.ServiceInfo{
			{
				Name:      "MSSQLSERVER",
				Status:    "Stopped",
				StartType: "Auto",
				ExitCode:  1,
			},
		},
	}
	report.Data.Reliability = &models.ReliabilityMetrics{
		TimeWindowHours: 24,
		BugChecks: []models.BugCheckEvent{
			{
				Timestamp:    time.Now().Add(-1 * time.Hour),
				BugCheckCode: "0x000000D1",
				DumpFile:     "C:\\Windows\\MEMORY.DMP",
			},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	// Expected findings:
	// 1. CPU critical saturation (FINDING-CPU-001)
	// 2. Memory commit exhaustion (FINDING-MEM-001)
	// 3. Storage free space exhaustion (FINDING-STORAGE-001)
	// 4. Storage queue depth (FINDING-STORAGE-002)
	// 5. Network interface packet errors (FINDING-NET-001)
	// 6. Failed auto-start service (FINDING-SVC-001)
	// 7. BSOD crash dump (FINDING-REL-001)
	if len(findings) != 7 {
		t.Fatalf("Expected 7 findings in multi-fault scenario, got %d", len(findings))
	}

	criticalCount := 0
	for _, f := range findings {
		if f.Severity == models.SeverityCritical {
			criticalCount++
		}
		if len(f.Evidence) == 0 {
			t.Errorf("Finding %s missing evidence citations", f.ID)
		}
		if f.Observation == "" || f.Interpretation == "" || f.PotentialImpact == "" || f.Recommendation == "" {
			t.Errorf("Finding %s has empty structured fields", f.ID)
		}
	}

	if criticalCount < 4 {
		t.Errorf("Expected at least 4 CRITICAL findings, got %d", criticalCount)
	}
}

func TestRuleEngine_BenignKernelGeneralEvent11Ignored(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Reliability = &models.ReliabilityMetrics{
		TimeWindowHours:   24,
		TotalErrorsLogged: 5,
		SystemErrors: []models.SystemErrorEvent{
			{
				Timestamp: time.Now().Add(-10 * time.Minute),
				Provider:  "Microsoft-Windows-Kernel-General",
				EventID:   11,
				Level:     "Info",
				Channel:   "System",
				Message:   `ExtraStringLength=81; ExtraString=\??\GLOBALROOT\Device\HarddiskVolumeShadowCopy11\WINDOWS\System32\config\SOFTWARE; Status=0xc00000a2; InternalCode=7`,
			},
			{
				Timestamp: time.Now().Add(-15 * time.Minute),
				Provider:  "Microsoft-Windows-Kernel-General",
				EventID:   11,
				Level:     "Information",
				Channel:   "System",
				Message:   `ExtraStringLength=80; ExtraString=\??\GLOBALROOT\Device\HarddiskVolumeShadowCopy11\WINDOWS\System32\config\DRIVERS; Status=0xc00000a2; InternalCode=7`,
			},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	for _, f := range findings {
		if f.ID == "FINDING-REL-004" {
			t.Errorf("FINDING-REL-004 was unexpectedly triggered for benign Kernel-General Event 11: %+v", f)
		}
	}
}

func TestRuleEngine_UnclassifiedStorageWarningEvent_Ignored(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Reliability = &models.ReliabilityMetrics{
		TimeWindowHours:   24,
		TotalErrorsLogged: 2,
		SystemErrors: []models.SystemErrorEvent{
			{
				Timestamp: time.Now().Add(-20 * time.Minute),
				Provider:  "volsnap",
				EventID:   25,
				Level:     "Warning",
				Channel:   "System",
				Message:   "The shadow copies of volume C: were deleted because the shadow copy storage could not grow in time.",
			},
			{
				Timestamp: time.Now().Add(-30 * time.Minute),
				Provider:  "fltmgr",
				EventID:   4,
				Level:     "Warning",
				Channel:   "System",
				Message:   "File System Filter 'test' (Version 10.0) does not support bypass IO.",
			},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	for _, f := range findings {
		if f.ID == "FINDING-REL-004" {
			t.Errorf("FINDING-REL-004 was unexpectedly triggered for unclassified storage warning events: %+v", f)
		}
	}
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for unclassified storage warning events, got %d", len(findings))
	}
}

func TestRuleEngine_StoppedManualService_NoAutoStartFinding(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Services = &models.ServicesMetrics{
		TotalCount:   10,
		RunningCount: 8,
		StoppedCount: 2,
		Services: []models.ServiceInfo{
			{Name: "ManualService1", DisplayName: "Manual Service 1", Status: "Stopped", StartType: "Manual", ExitCode: 0},
			{Name: "ManualService2", DisplayName: "Manual Service 2", Status: "Stopped", StartType: "Manual", ExitCode: 1067},
		},
		FailedAutoStart: []models.ServiceInfo{
			// Even if manually passed into slice, defensive check in rule must ignore non-Auto services
			{Name: "ManualService1", DisplayName: "Manual Service 1", Status: "Stopped", StartType: "Manual", ExitCode: 0},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	for _, f := range findings {
		if f.ID == "FINDING-SVC-001" {
			t.Errorf("FINDING-SVC-001 was unexpectedly emitted for stopped manual service: %+v", f)
		}
	}
}

func TestRuleEngine_DisabledService_NoAutoStartFinding(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Services = &models.ServicesMetrics{
		TotalCount:   10,
		RunningCount: 8,
		StoppedCount: 2,
		Services: []models.ServiceInfo{
			{Name: "DisabledService1", DisplayName: "Disabled Service 1", Status: "Stopped", StartType: "Disabled", ExitCode: 0},
		},
		FailedAutoStart: []models.ServiceInfo{
			{Name: "DisabledService1", DisplayName: "Disabled Service 1", Status: "Stopped", StartType: "Disabled", ExitCode: 0},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	for _, f := range findings {
		if f.ID == "FINDING-SVC-001" {
			t.Errorf("FINDING-SVC-001 was unexpectedly emitted for disabled service: %+v", f)
		}
	}
}

func TestRuleEngine_AutoStartStopped_ExitCodeZero_ObservationOnly(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Services = &models.ServicesMetrics{
		TotalCount:           10,
		RunningCount:         8,
		StoppedCount:         2,
		FailedAutoStartCount: 1,
		FailedAutoStart: []models.ServiceInfo{
			{Name: "Gpsvc", DisplayName: "Group Policy Client", Status: "Stopped", StartType: "Auto", ExitCode: 0},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected exactly 1 finding for stopped auto-start service with exit code 0, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-SVC-001" {
		t.Errorf("Expected FINDING-SVC-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityInfo {
		t.Errorf("Expected SeverityInfo (observation only) for exit code 0, got %s", f.Severity)
	}
	if f.Evidence["non_zero_exit_count"] != 0 {
		t.Errorf("Expected non_zero_exit_count = 0 in evidence, got %v", f.Evidence["non_zero_exit_count"])
	}
}

func TestRuleEngine_AutoStartStopped_ExitCodeNonZero_WarningFinding(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Services = &models.ServicesMetrics{
		TotalCount:           10,
		RunningCount:         8,
		StoppedCount:         2,
		FailedAutoStartCount: 1,
		FailedAutoStart: []models.ServiceInfo{
			{Name: "Spooler", DisplayName: "Print Spooler", Status: "Stopped", StartType: "Auto", ExitCode: 1067},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected exactly 1 finding for stopped auto-start service with failure exit code, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-SVC-001" {
		t.Errorf("Expected FINDING-SVC-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityWarning {
		t.Errorf("Expected SeverityWarning for non-zero exit code failure evidence, got %s", f.Severity)
	}
	if f.Evidence["non_zero_exit_count"] != 1 {
		t.Errorf("Expected non_zero_exit_count = 1 in evidence, got %v", f.Evidence["non_zero_exit_count"])
	}
}

func TestRuleEngine_CommitThreshold_94_9_Percent_BelowCritical(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Memory = &models.MemoryMetrics{
		TotalBytes:       16 * 1024 * 1024 * 1024,
		AvailableBytes:   2 * 1024 * 1024 * 1024, // 2 GB (> 500 MB)
		UsedBytes:        14 * 1024 * 1024 * 1024,
		UsedPercent:      87.5,
		CommitLimitBytes: 16 * 1024 * 1024 * 1024,
		CommitTotalBytes: 16303695856, // 94.9%
		CommitPercent:    94.9,
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for 94.9%% commit, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-MEM-001" {
		t.Errorf("Expected FINDING-MEM-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityWarning {
		t.Errorf("Expected WARNING severity for 94.9%% commit (< 95.0%% critical threshold), got %s", f.Severity)
	}
}

func TestRuleEngine_CommitThreshold_95_0_Percent_ExactCritical(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Memory = &models.MemoryMetrics{
		TotalBytes:       16 * 1024 * 1024 * 1024,
		AvailableBytes:   2 * 1024 * 1024 * 1024,
		UsedBytes:        14 * 1024 * 1024 * 1024,
		UsedPercent:      87.5,
		CommitLimitBytes: 16 * 1024 * 1024 * 1024,
		CommitTotalBytes: 16320875725, // 95.0%
		CommitPercent:    95.0,
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding for 95.0%% commit, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-MEM-001" {
		t.Errorf("Expected FINDING-MEM-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Expected CRITICAL severity for exact 95.0%% commit threshold, got %s", f.Severity)
	}
}

func TestRuleEngine_DNSSuccessWithInterfaceErrors_NotClaimedHealthy(t *testing.T) {
	report := models.NewDiagnosticReport()
	speed := uint64(1000)
	report.Data.Network = &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				ID:        "nic1",
				Name:      "Ethernet",
				Status:    "Up",
				SpeedMbps: &speed,
				InErrors:  24,
				OutErrors: 0,
			},
		},
		DNSTest: &models.DNSResolutionTest{
			QueryTarget: "TEST-HOST-01",
			Success:     true,
			DurationMS:  14.2,
			ResolvedIPs: []string{"192.168.1.100"},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	if len(findings) != 1 {
		t.Fatalf("Expected exactly 1 finding for packet errors, got %d", len(findings))
	}

	f := findings[0]
	if f.ID != "FINDING-NET-001" {
		t.Errorf("Expected FINDING-NET-001, got %s", f.ID)
	}
	if f.Severity != models.SeverityWarning {
		t.Errorf("Expected SeverityWarning, got %s", f.Severity)
	}

	// Verify that the report when evaluated has 1 warning finding and is not considered anomaly-free
	report.Findings = findings
	var termBuf bytes.Buffer
	termRep := termReporter.NewReporter()
	if err := termRep.Generate(report, &termBuf); err != nil {
		t.Fatalf("Failed to generate terminal report: %v", err)
	}
	termStr := termBuf.String()
	if bytes.Contains([]byte(termStr), []byte("No anomalies or operational bottlenecks identified")) {
		t.Errorf("Terminal summary falsely claimed no anomalies when interface packet errors were present: %s", termStr)
	}
}

func TestRuleEngine_HighProcessMemory_NormalSystemMemory_NoSystemPressure(t *testing.T) {
	report := models.NewDiagnosticReport()
	// System has 64 GB RAM, only 25% commit, 50 GB available (completely healthy system memory)
	report.Data.Memory = &models.MemoryMetrics{
		TotalBytes:       64 * 1024 * 1024 * 1024,
		AvailableBytes:   50 * 1024 * 1024 * 1024,
		UsedBytes:        14 * 1024 * 1024 * 1024,
		UsedPercent:      21.8,
		CommitLimitBytes: 70 * 1024 * 1024 * 1024,
		CommitTotalBytes: 17 * 1024 * 1024 * 1024,
		CommitPercent:    24.2,
	}

	// Single high process with 10 GB working set (>= 8 GB threshold)
	report.Data.Processes = &models.ProcessMetrics{
		TotalProcesses: 150,
		TotalThreads:   2000,
		TopMemory: []models.ProcessSummary{
			{
				PID:             4096,
				Name:            "database_engine.exe",
				WorkingSetBytes: 10 * 1024 * 1024 * 1024,
				PrivateBytes:    10 * 1024 * 1024 * 1024,
				ExecutablePath:  "C:\\Program Files\\DB\\database_engine.exe",
			},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	// We expect Process finding (FINDING-PROC-002) for the 10 GB process
	// but NO system memory commit/exhaustion finding (FINDING-MEM-001)
	var foundProc bool
	var procFinding models.Finding
	for _, f := range findings {
		if f.ID == "FINDING-MEM-001" {
			t.Errorf("FINDING-MEM-001 (system memory exhaustion) was falsely emitted despite healthy system memory: %+v", f)
		}
		if f.ID == "FINDING-PROC-002" {
			foundProc = true
			procFinding = f
			if f.Category != "processes" {
				t.Errorf("Expected category 'processes', got %s", f.Category)
			}
		}
	}

	if !foundProc {
		t.Fatalf("Expected FINDING-PROC-002 for 10 GB process, but none was emitted")
	}

	if procFinding.Evidence["trigger"] != "absolute_working_set" {
		t.Errorf("Expected trigger 'absolute_working_set', got %v", procFinding.Evidence["trigger"])
	}
	if bytes.Contains([]byte(procFinding.Interpretation), []byte("major fraction")) {
		t.Errorf("Interpretation falsely claimed 'major fraction' on 64 GB system: %s", procFinding.Interpretation)
	}
	if bytes.Contains([]byte(procFinding.PotentialImpact), []byte("limited available working set")) {
		t.Errorf("Potential impact falsely claimed 'limited available working set': %s", procFinding.PotentialImpact)
	}
}

func TestRuleEngine_HighSystemMemory_HighProcessMemory_CorrelatesStrictEvidence(t *testing.T) {
	report := models.NewDiagnosticReport()
	// System has 16 GB RAM, 96% commit, 1.2 GB available (exhausted system memory)
	report.Data.Memory = &models.MemoryMetrics{
		TotalBytes:       16 * 1024 * 1024 * 1024,
		AvailableBytes:   1200 * 1024 * 1024,
		UsedBytes:        14800 * 1024 * 1024,
		UsedPercent:      90.3,
		CommitLimitBytes: 18 * 1024 * 1024 * 1024,
		CommitTotalBytes: 18 * 1024 * 1024 * 1024 * 96 / 100, // 96.0%
		CommitPercent:    96.0,
	}

	// Dominant process holding 12 GB working set (75% of RAM)
	report.Data.Processes = &models.ProcessMetrics{
		TotalProcesses: 200,
		TotalThreads:   2500,
		TopMemory: []models.ProcessSummary{
			{
				PID:             8192,
				Name:            "memory_hog.exe",
				WorkingSetBytes: 12 * 1024 * 1024 * 1024,
				PrivateBytes:    12 * 1024 * 1024 * 1024,
				ExecutablePath:  "C:\\Tools\\memory_hog.exe",
			},
		},
	}

	engine := analyzer.NewDefaultEngine()
	findings := engine.EvaluateAll(context.Background(), report)

	var foundSysMem, foundProcMem bool
	for _, f := range findings {
		if f.ID == "FINDING-MEM-001" {
			foundSysMem = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("Expected CRITICAL severity for 96%% commit, got %s", f.Severity)
			}
			if f.Evidence["commit_percent"] != 96.0 {
				t.Errorf("Expected system commit_percent 96.0 in evidence, got %v", f.Evidence["commit_percent"])
			}
		}
		if f.ID == "FINDING-PROC-002" {
			foundProcMem = true
			if f.Evidence["pid"] != uint32(8192) || f.Evidence["name"] != "memory_hog.exe" {
				t.Errorf("Expected process evidence pid 8192 and name memory_hog.exe, got %v", f.Evidence)
			}
		}
	}

	if !foundSysMem {
		t.Errorf("Expected FINDING-MEM-001 for high system commit")
	}
	if !foundProcMem {
		t.Errorf("Expected FINDING-PROC-002 for high process memory")
	}
}
