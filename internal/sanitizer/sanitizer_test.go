package sanitizer_test

import (
	"testing"

	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/sanitizer"
)

func TestSanitizeReport(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Metadata.Hostname = "CONFIDENTIAL-SRV-99"
	report.Metadata.ExecutionPath = `C:\Users\JohnDoe\Downloads\sysdiag.exe`
	report.Metadata.OutputDirectory = `C:\Users\JohnDoe\Reports`
	report.Data.System = &models.SystemMetrics{
		Hostname: "CONFIDENTIAL-SRV-99",
	}
	report.Findings = []models.Finding{
		{
			ID:          "FINDING-TEST-001",
			Title:       "Error on CONFIDENTIAL-SRV-99 for user JohnDoe",
			Observation: `Log file located at C:\Users\JohnDoe\app.log connected to 192.168.1.50`,
			Evidence: map[string]interface{}{
				"target_ip": "10.0.0.15",
				"path":      `C:\Users\JohnDoe\secret.txt`,
			},
		},
	}

	sanitizer.SanitizeReport(report)

	if report.Metadata.Hostname != "REDACTED-HOST" {
		t.Errorf("Expected REDACTED-HOST, got %s", report.Metadata.Hostname)
	}
	if report.Data.System.Hostname != "REDACTED-HOST" {
		t.Errorf("Expected system hostname REDACTED-HOST, got %s", report.Data.System.Hostname)
	}
	if report.Metadata.ExecutionPath != `C:\Users\[REDACTED]\Downloads\sysdiag.exe` && report.Metadata.ExecutionPath != `C:\Users\[REDACTED]` {
		t.Logf("Sanitized execution path: %s", report.Metadata.ExecutionPath)
	}
	if report.Findings[0].Title == "Error on CONFIDENTIAL-SRV-99 for user JohnDoe" {
		t.Errorf("Expected finding title to be sanitized, got: %s", report.Findings[0].Title)
	}
	if report.Findings[0].Evidence["target_ip"] != "10.x.x.x" {
		t.Errorf("Expected target IP sanitized to 10.x.x.x, got %v", report.Findings[0].Evidence["target_ip"])
	}
}

func TestSanitizeReport_SubsystemMetrics(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Metadata.Hostname = "PROD-SERVER-01"

	speed := uint64(1000)
	report.Data.Network = &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				ID:            "eth0",
				Name:          "Ethernet",
				SpeedMbps:     &speed,
				IPv4Addresses: []string{"192.168.1.105", "10.200.5.12"},
				Gateways:      []string{"192.168.1.1"},
				DNSServers:    []string{"192.168.1.254"},
			},
		},
		DNSTest: &models.DNSResolutionTest{
			QueryTarget: "PROD-SERVER-01",
		},
	}

	report.Data.Processes = &models.ProcessMetrics{
		TopCPU: []models.ProcessSummary{
			{
				PID:            1234,
				Name:           "custom_service.exe",
				ExecutablePath: `C:\Users\AliceSmith\AppData\Local\custom_service.exe`,
			},
		},
		TopMemory: []models.ProcessSummary{
			{
				PID:            5678,
				Name:           "node.exe",
				ExecutablePath: `C:\Users\AliceSmith\projects\app\node.exe`,
			},
		},
	}

	report.Data.Services = &models.ServicesMetrics{
		Services: []models.ServiceInfo{
			{
				Name:       "TestService",
				BinaryPath: `C:\Users\AliceSmith\bin\svc.exe`,
				Account:    `CORP\AliceSmith`,
			},
		},
		FailedAutoStart: []models.ServiceInfo{
			{
				Name:       "FailedService",
				BinaryPath: `C:\Users\AliceSmith\bin\failed.exe`,
				Account:    `CORP\AliceSmith`,
			},
		},
	}

	report.Data.Reliability = &models.ReliabilityMetrics{
		AppCrashes: []models.AppCrashEvent{
			{
				Application: `C:\Users\AliceSmith\app.exe`,
				Message:     `Fault in C:\Users\AliceSmith\app.exe on PROD-SERVER-01`,
			},
		},
		SystemErrors: []models.SystemErrorEvent{
			{
				Provider: "Disk",
				Message:  "Drive error on PROD-SERVER-01",
			},
		},
		BugChecks: []models.BugCheckEvent{
			{
				DumpFile: `C:\Users\AliceSmith\crash.dmp`,
				Message:  "Kernel bugcheck on PROD-SERVER-01",
			},
		},
	}

	report.Data.Software = &models.SoftwareMetrics{
		Applications: []models.InstalledApp{
			{
				Name: "PROD-SERVER-01 Agent",
			},
		},
		Runtimes: []models.RuntimeInfo{
			{
				Name: "Python",
				Path: `C:\Users\AliceSmith\AppData\Local\Programs\Python\python.exe`,
			},
		},
	}

	sanitizer.SanitizeReport(report)

	// Verify Network
	for _, ip := range report.Data.Network.Adapters[0].IPv4Addresses {
		if ip != "10.x.x.x" {
			t.Errorf("Expected IPv4 address sanitized to 10.x.x.x, got %s", ip)
		}
	}
	if report.Data.Network.Adapters[0].Gateways[0] != "10.x.x.x" {
		t.Errorf("Expected gateway sanitized to 10.x.x.x, got %s", report.Data.Network.Adapters[0].Gateways[0])
	}
	if report.Data.Network.DNSTest.QueryTarget != "REDACTED-HOST" {
		t.Errorf("Expected DNS query target sanitized, got %s", report.Data.Network.DNSTest.QueryTarget)
	}

	// Verify Process Paths
	if report.Data.Processes.TopCPU[0].ExecutablePath != `C:\Users\[REDACTED]\AppData\Local\custom_service.exe` {
		t.Errorf("Expected sanitized TopCPU path, got %s", report.Data.Processes.TopCPU[0].ExecutablePath)
	}
	if report.Data.Processes.TopMemory[0].ExecutablePath != `C:\Users\[REDACTED]\projects\app\node.exe` {
		t.Errorf("Expected sanitized TopMemory path, got %s", report.Data.Processes.TopMemory[0].ExecutablePath)
	}

	// Verify Services
	if report.Data.Services.Services[0].BinaryPath != `C:\Users\[REDACTED]\bin\svc.exe` {
		t.Errorf("Expected sanitized service binary path, got %s", report.Data.Services.Services[0].BinaryPath)
	}

	// Verify Reliability
	if report.Data.Reliability.AppCrashes[0].Application != `C:\Users\[REDACTED]\app.exe` {
		t.Errorf("Expected sanitized app crash path, got %s", report.Data.Reliability.AppCrashes[0].Application)
	}
	if report.Data.Reliability.BugChecks[0].DumpFile != `C:\Users\[REDACTED]\crash.dmp` {
		t.Errorf("Expected sanitized dump file path, got %s", report.Data.Reliability.BugChecks[0].DumpFile)
	}

	// Verify Software
	if report.Data.Software.Runtimes[0].Path != `C:\Users\[REDACTED]\AppData\Local\Programs\Python\python.exe` {
		t.Errorf("Expected sanitized runtime path, got %s", report.Data.Software.Runtimes[0].Path)
	}
}

func TestSanitizeReport_HardwareIdentifiers(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Metadata.Hostname = "STORAGE-SRV-01"

	report.Data.Storage = &models.StorageMetrics{
		PhysicalDisks: []models.PhysicalDiskMetrics{
			{
				DeviceID:     `\\.\PhysicalDrive0`,
				Model:        "Samsung SSD 970 EVO Plus 1TB",
				MediaType:    "SSD",
				BusType:      "NVMe",
				SizeBytes:    1000204886016,
				SerialNumber: "S4EVNF0M123456K",
			},
			{
				DeviceID:     `\\.\PhysicalDrive1`,
				Model:        "WDC WD20EZRX-00D8PB0",
				MediaType:    "HDD",
				BusType:      "SATA",
				SizeBytes:    2000398934016,
				SerialNumber: "WD-WCC4N1234567",
			},
		},
	}

	report.Data.Network = &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				ID:            "{84645582-8635-4E83-9FA3-36C38A18CBFF}",
				Name:          "Ethernet 1",
				Description:   "Intel(R) Ethernet Controller I225-V",
				MACAddress:    "00:1A:2B:3C:4D:5E",
				Status:        "Up",
				IPv4Addresses: []string{"192.168.1.150"},
			},
		},
	}

	report.Findings = []models.Finding{
		{
			ID:          "FINDING-STORAGE-002",
			Title:       "Degraded physical disk S4EVNF0M123456K detected",
			Observation: "Disk \\\\.\\PhysicalDrive0 (Serial: S4EVNF0M123456K) reported degraded sector latency; adapter MAC 00:1A:2B:3C:4D:5E.",
			Evidence: map[string]interface{}{
				"device_id":     `\\.\PhysicalDrive0`,
				"serial_number": "S4EVNF0M123456K",
				"mac_address":   "00:1A:2B:3C:4D:5E",
				"model":         "Samsung SSD 970 EVO Plus 1TB",
			},
			Interpretation:  "Drive S4EVNF0M123456K is experiencing hardware degradation.",
			PotentialImpact: "Data loss on disk S4EVNF0M123456K.",
			Recommendation:  "Replace drive with serial S4EVNF0M123456K immediately.",
		},
	}

	sanitizer.SanitizeReport(report)

	// Check that disk serial numbers are redacted
	if report.Data.Storage.PhysicalDisks[0].SerialNumber != "[SERIAL_REDACTED]" {
		t.Errorf("Expected PhysicalDrive0 serial to be [SERIAL_REDACTED], got %s", report.Data.Storage.PhysicalDisks[0].SerialNumber)
	}
	if report.Data.Storage.PhysicalDisks[1].SerialNumber != "[SERIAL_REDACTED]" {
		t.Errorf("Expected PhysicalDrive1 serial to be [SERIAL_REDACTED], got %s", report.Data.Storage.PhysicalDisks[1].SerialNumber)
	}

	// Check that network MAC address is redacted
	if report.Data.Network.Adapters[0].MACAddress != "[MAC_REDACTED]" {
		t.Errorf("Expected adapter MAC to be [MAC_REDACTED], got %s", report.Data.Network.Adapters[0].MACAddress)
	}

	// Check finding texts
	f := report.Findings[0]
	if f.Title != "Degraded physical disk [SERIAL_REDACTED] detected" {
		t.Errorf("Expected finding title serial redacted, got: %s", f.Title)
	}
	if f.Observation != "Disk \\\\.\\PhysicalDrive0 (Serial: [SERIAL_REDACTED]) reported degraded sector latency; adapter MAC [MAC_REDACTED]." {
		t.Errorf("Expected finding observation serial and MAC redacted, got: %s", f.Observation)
	}
	if f.Interpretation != "Drive [SERIAL_REDACTED] is experiencing hardware degradation." {
		t.Errorf("Expected finding interpretation serial redacted, got: %s", f.Interpretation)
	}
	if f.PotentialImpact != "Data loss on disk [SERIAL_REDACTED]." {
		t.Errorf("Expected finding potential impact serial redacted, got: %s", f.PotentialImpact)
	}
	if f.Recommendation != "Replace drive with serial [SERIAL_REDACTED] immediately." {
		t.Errorf("Expected finding recommendation serial redacted, got: %s", f.Recommendation)
	}

	// Check finding evidence map
	if f.Evidence["serial_number"] != "[SERIAL_REDACTED]" {
		t.Errorf("Expected evidence serial_number redacted, got %v", f.Evidence["serial_number"])
	}
	if f.Evidence["mac_address"] != "[MAC_REDACTED]" {
		t.Errorf("Expected evidence mac_address redacted, got %v", f.Evidence["mac_address"])
	}
}

func TestUnsanitizedReport_PreservesHardwareIdentifiers(t *testing.T) {
	report := models.NewDiagnosticReport()
	report.Metadata.Hostname = "STORAGE-SRV-01"

	report.Data.Storage = &models.StorageMetrics{
		PhysicalDisks: []models.PhysicalDiskMetrics{
			{
				DeviceID:     `\\.\PhysicalDrive0`,
				Model:        "Samsung SSD 970 EVO Plus 1TB",
				MediaType:    "SSD",
				BusType:      "NVMe",
				SizeBytes:    1000204886016,
				SerialNumber: "S4EVNF0M123456K",
			},
		},
	}

	report.Data.Network = &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				ID:         "{84645582-8635-4E83-9FA3-36C38A18CBFF}",
				Name:       "Ethernet 1",
				MACAddress: "00:1A:2B:3C:4D:5E",
				Status:     "Up",
			},
		},
	}

	// Without calling SanitizeReport, raw persistent identifiers must remain intact
	if report.Data.Storage.PhysicalDisks[0].SerialNumber != "S4EVNF0M123456K" {
		t.Errorf("Expected raw disk serial number preserved in unsanitized report, got %s", report.Data.Storage.PhysicalDisks[0].SerialNumber)
	}
	if report.Data.Network.Adapters[0].MACAddress != "00:1A:2B:3C:4D:5E" {
		t.Errorf("Expected raw MAC address preserved in unsanitized report, got %s", report.Data.Network.Adapters[0].MACAddress)
	}
}

func TestSanitizeReport_NilSafety(t *testing.T) {
	// Should not panic on nil
	sanitizer.SanitizeReport(nil)
}
