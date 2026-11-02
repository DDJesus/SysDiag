package models_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/systemdiag/sysdiag/internal/models"
)

func TestDiagnosticReport_JSONSchemaConformance(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Metadata = models.ExecutionMetadata{
		ToolVersion:     "1.0.0",
		ScanTimestamp:   time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC),
		ScanDurationMS:  1250,
		Profile:         "quick",
		Hostname:        "TEST-HOST",
		OS:              "windows",
		OSVersion:       "Microsoft Windows 11 Pro",
		Architecture:    "amd64",
		PrivilegeLevel:  "User",
		IsElevated:      false,
		ExecutionPath:   `C:\sysdiag.exe`,
		OutputDirectory: `C:\sysdiag_output`,
	}
	report.CollectionStatus = models.CollectionStatus{
		TotalProbes: 3,
		Successful:  3,
	}
	report.Data.System = &models.SystemMetrics{
		Hostname:      "TEST-HOST",
		OSName:        "Microsoft Windows 11 Pro",
		OSBuild:       "22631.3007",
		Architecture:  "amd64",
		UptimeSeconds: 7200,
		BootTime:      time.Date(2026, 9, 15, 22, 0, 0, 0, time.UTC),
		Virtualization: models.VirtualizationInfo{
			IsVirtual:  true,
			Hypervisor: "Hyper-V",
		},
	}
	report.Data.CPU = &models.CPUMetrics{
		Model:              "Intel(R) Core(TM) i7-13700K",
		PhysicalCores:      16,
		LogicalCores:       24,
		UtilizationPercent: 42.5,
		UserPercent:        30.0,
		KernelPercent:      12.5,
	}
	report.Data.Memory = &models.MemoryMetrics{
		TotalBytes:       34359738368,
		AvailableBytes:   17179869184,
		UsedBytes:        17179869184,
		UsedPercent:      50.0,
		CommitLimitBytes: 42949672960,
		CommitTotalBytes: 21474836480,
		CommitPercent:    50.0,
	}
	report.Data.Storage = &models.StorageMetrics{
		Volumes: []models.VolumeMetrics{
			{
				MountPoint:  "C:\\",
				VolumeName:  "OS",
				FileSystem:  "NTFS",
				DriveType:   "Fixed",
				TotalBytes:  1000000000000,
				FreeBytes:   600000000000,
				UsedBytes:   400000000000,
				UsedPercent: 40.0,
			},
		},
	}
	speed := uint64(1000)
	report.Data.Network = &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				ID:            "eth0",
				Name:          "Ethernet",
				Status:        "Up",
				SpeedMbps:     &speed,
				IPv4Addresses: []string{"192.168.1.50"},
			},
		},
	}
	report.Data.Processes = &models.ProcessMetrics{
		TotalProcesses: 150,
		TotalThreads:   1200,
		TopCPU: []models.ProcessSummary{
			{
				PID:            1234,
				Name:           "app.exe",
				CPUTimeSeconds: 12.5,
			},
		},
	}

	data, err := report.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize report: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Serialized JSON is not valid JSON: %v", err)
	}

	if parsed["$schema"] != "https://systemdiag.io/schema/v1.json" {
		t.Errorf("Expected $schema 'https://systemdiag.io/schema/v1.json', got %v", parsed["$schema"])
	}

	if parsed["schema_version"] != "1.0.0" {
		t.Errorf("Expected schema_version '1.0.0', got %v", parsed["schema_version"])
	}

	restored, err := models.FromJSON(data)
	if err != nil {
		t.Fatalf("Failed to restore report from JSON: %v", err)
	}

	if restored.Metadata.Hostname != "TEST-HOST" {
		t.Errorf("Expected restored hostname TEST-HOST, got %s", restored.Metadata.Hostname)
	}
	if restored.Data.CPU.LogicalCores != 24 {
		t.Errorf("Expected CPU logical cores 24, got %d", restored.Data.CPU.LogicalCores)
	}
	if restored.Data.Network.Adapters[0].SpeedMbps == nil || *restored.Data.Network.Adapters[0].SpeedMbps != 1000 {
		t.Errorf("Expected restored SpeedMbps 1000, got %v", restored.Data.Network.Adapters[0].SpeedMbps)
	}
}

func TestNetworkAdapter_UnavailableLinkSpeed(t *testing.T) {
	report := models.NewDiagnosticReport()
	speedUp := uint64(1000)

	report.Data.Network = &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				ID:            "{GUID-UP-01}",
				Name:          "Ethernet",
				Description:   "Physical Intel I225-V",
				Status:        "Up",
				IfType:        "Ethernet",
				SpeedMbps:     &speedUp,
				IPv4Addresses: []string{"192.168.1.100"},
			},
			{
				ID:            "{GUID-DOWN-02}",
				Name:          "Ethernet 2",
				Description:   "Disconnected Realtek PCIe",
				Status:        "Down",
				IfType:        "Ethernet",
				SpeedMbps:     nil, // Unavailable / null on disconnected link
				IPv4Addresses: nil,
			},
			{
				ID:            "{GUID-VIRT-03}",
				Name:          "vEthernet (WSL)",
				Description:   "Hyper-V Virtual Ethernet Adapter",
				Status:        "Up",
				IfType:        "Ethernet",
				SpeedMbps:     nil, // Unavailable / null on virtual adapter without fixed link speed
				IPv4Addresses: []string{"172.28.0.1"},
			},
		},
	}

	data, err := report.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize report: %v", err)
	}

	// Verify that speed_mbps for Down and Virtual adapters is explicitly serialized as null
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		t.Fatalf("Failed to unmarshal JSON into map: %v", err)
	}

	dataMap := rawMap["data"].(map[string]interface{})
	netMap := dataMap["network"].(map[string]interface{})
	adapters := netMap["adapters"].([]interface{})

	if len(adapters) != 3 {
		t.Fatalf("Expected 3 adapters, got %d", len(adapters))
	}

	// Adapter 0 (Up, Physical): speed_mbps should be 1000
	a0 := adapters[0].(map[string]interface{})
	if a0["speed_mbps"] != float64(1000) {
		t.Errorf("Expected adapter 0 speed_mbps = 1000, got %v", a0["speed_mbps"])
	}

	// Adapter 1 (Down): speed_mbps should be explicit null
	a1 := adapters[1].(map[string]interface{})
	if a1["speed_mbps"] != nil {
		t.Errorf("Expected adapter 1 (Down) speed_mbps = null, got %v", a1["speed_mbps"])
	}

	// Adapter 2 (Virtual with no link speed): speed_mbps should be explicit null
	a2 := adapters[2].(map[string]interface{})
	if a2["speed_mbps"] != nil {
		t.Errorf("Expected adapter 2 (Virtual) speed_mbps = null, got %v", a2["speed_mbps"])
	}

	// Verify deserialization back to Go struct preserves nil pointers
	restored, err := models.FromJSON(data)
	if err != nil {
		t.Fatalf("Failed to restore from JSON: %v", err)
	}

	if restored.Data.Network.Adapters[0].SpeedMbps == nil || *restored.Data.Network.Adapters[0].SpeedMbps != 1000 {
		t.Errorf("Expected restored adapter 0 SpeedMbps = 1000, got %v", restored.Data.Network.Adapters[0].SpeedMbps)
	}
	if restored.Data.Network.Adapters[1].SpeedMbps != nil {
		t.Errorf("Expected restored adapter 1 SpeedMbps = nil, got %v", restored.Data.Network.Adapters[1].SpeedMbps)
	}
	if restored.Data.Network.Adapters[2].SpeedMbps != nil {
		t.Errorf("Expected restored adapter 2 SpeedMbps = nil, got %v", restored.Data.Network.Adapters[2].SpeedMbps)
	}
}

func TestDiagnosticReport_InvalidJSON(t *testing.T) {
	_, err := models.FromJSON([]byte(`{invalid json`))
	if err == nil {
		t.Errorf("Expected error when unmarshaling invalid JSON, got nil")
	}
}

func TestDiagnosticReport_CompleteSubsystemRoundTrip(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Data.Services = &models.ServicesMetrics{
		TotalCount:           10,
		RunningCount:         8,
		StoppedCount:         2,
		FailedAutoStartCount: 1,
		Services: []models.ServiceInfo{
			{Name: "Svc1", DisplayName: "Service 1", Status: "Running", StartType: "Auto"},
		},
		FailedAutoStart: []models.ServiceInfo{
			{Name: "FailedSvc", DisplayName: "Failed Service", Status: "Stopped", StartType: "Auto", ExitCode: 1067},
		},
	}
	report.Data.Reliability = &models.ReliabilityMetrics{
		TimeWindowHours:   24,
		TotalErrorsLogged: 1,
		AppCrashes: []models.AppCrashEvent{
			{Application: "app.exe", ExceptionCode: "0xc0000005"},
		},
		BugChecks: []models.BugCheckEvent{
			{BugCheckCode: "0x0000007E"},
		},
		KernelPowerEvents: []models.KernelPowerEvent{
			{EventID: 41},
		},
		SystemErrors: []models.SystemErrorEvent{
			{Provider: "Disk", EventID: 15, Message: "Device error"},
		},
	}
	report.Data.Software = &models.SoftwareMetrics{
		Applications: []models.InstalledApp{
			{Name: "Test App", Version: "1.0.0", Publisher: "Vendor"},
		},
		HotFixes: []models.HotFixInfo{
			{HotFixID: "KB5001234"},
		},
		Runtimes: []models.RuntimeInfo{
			{Name: ".NET Framework", Version: "4.8.0", Path: "C:\\Windows"},
		},
	}

	bytes, err := report.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize full report: %v", err)
	}

	assertContract(t, bytes)
	restored, err := models.FromJSON(bytes)
	if err != nil {
		t.Fatalf("Failed to restore full report: %v", err)
	}

	if restored.Data.Services.TotalCount != 10 {
		t.Errorf("Expected services total count 10, got %d", restored.Data.Services.TotalCount)
	}
	if len(restored.Data.Reliability.AppCrashes) != 1 {
		t.Errorf("Expected 1 app crash restored, got %d", len(restored.Data.Reliability.AppCrashes))
	}
	if len(restored.Data.Software.Applications) != 1 {
		t.Errorf("Expected 1 application restored, got %d", len(restored.Data.Software.Applications))
	}
}
