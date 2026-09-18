package sanitizer

import (
	"os"
	"regexp"
	"strings"

	"github.com/systemdiag/sysdiag/internal/models"
)

var (
	userPathRegex = regexp.MustCompile(`(?i)[a-z]:\\users\\[^\\]+`)
	ipv4Regex     = regexp.MustCompile(`\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.\d{1,3}){2})\b`)
	macRegex      = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
)

// SanitizeReport redacts user accounts, private network paths, hostnames, and persistent hardware identifiers in-place.
func SanitizeReport(report *models.DiagnosticReport) {
	if report == nil {
		return
	}

	rawHost := report.Metadata.Hostname
	report.Metadata.Hostname = "REDACTED-HOST"

	currentUser := os.Getenv("USERNAME")
	if currentUser == "" {
		currentUser = os.Getenv("USER")
	}

	currentDomain := os.Getenv("USERDOMAIN")

	var rawDiskSerials []string
	if report.Data.Storage != nil {
		for i := range report.Data.Storage.PhysicalDisks {
			d := &report.Data.Storage.PhysicalDisks[i]
			if d.SerialNumber != "" && d.SerialNumber != "[SERIAL_REDACTED]" && !strings.EqualFold(d.SerialNumber, "unknown") && !strings.EqualFold(d.SerialNumber, "none") {
				rawDiskSerials = append(rawDiskSerials, d.SerialNumber)
			}
			if d.SerialNumber != "" {
				d.SerialNumber = "[SERIAL_REDACTED]"
			}
		}
	}

	var rawMACs []string
	if report.Data.Network != nil {
		for i := range report.Data.Network.Adapters {
			a := &report.Data.Network.Adapters[i]
			if a.MACAddress != "" && a.MACAddress != "[MAC_REDACTED]" && !strings.EqualFold(a.MACAddress, "unknown") {
				rawMACs = append(rawMACs, a.MACAddress)
			}
			if a.MACAddress != "" {
				a.MACAddress = "[MAC_REDACTED]"
			}
		}
	}

	var cleanString func(s string) string
	cleanString = func(s string) string {
		if s == "" {
			return s
		}
		res := s
		if rawHost != "" && rawHost != "UNKNOWN-HOST" {
			res = strings.ReplaceAll(res, rawHost, "REDACTED-HOST")
		}
		if currentUser != "" {
			res = strings.ReplaceAll(res, currentUser, "[USER_REDACTED]")
		}
		if currentDomain != "" && currentDomain != rawHost {
			res = strings.ReplaceAll(res, currentDomain, "[DOMAIN_REDACTED]")
		}
		for _, serial := range rawDiskSerials {
			if serial != "" {
				res = strings.ReplaceAll(res, serial, "[SERIAL_REDACTED]")
			}
		}
		for _, mac := range rawMACs {
			if mac != "" {
				res = strings.ReplaceAll(res, mac, "[MAC_REDACTED]")
			}
		}
		res = userPathRegex.ReplaceAllString(res, `C:\Users\[REDACTED]`)
		res = ipv4Regex.ReplaceAllString(res, "10.x.x.x")
		res = macRegex.ReplaceAllString(res, "[MAC_REDACTED]")
		return res
	}

	var cleanValue func(v interface{}) interface{}
	cleanValue = func(v interface{}) interface{} {
		switch val := v.(type) {
		case string:
			return cleanString(val)
		case map[string]interface{}:
			res := make(map[string]interface{}, len(val))
			for k, inner := range val {
				res[k] = cleanValue(inner)
			}
			return res
		case []map[string]interface{}:
			res := make([]map[string]interface{}, len(val))
			for i, inner := range val {
				res[i] = cleanValue(inner).(map[string]interface{})
			}
			return res
		case []string:
			res := make([]string, len(val))
			for i, s := range val {
				res[i] = cleanString(s)
			}
			return res
		default:
			return v
		}
	}

	report.Metadata.ExecutionPath = cleanString(report.Metadata.ExecutionPath)
	report.Metadata.OutputDirectory = cleanString(report.Metadata.OutputDirectory)

	if report.Data.System != nil {
		report.Data.System.Hostname = "REDACTED-HOST"
	}

	for i := range report.Findings {
		f := &report.Findings[i]
		f.Title = cleanString(f.Title)
		f.Observation = cleanString(f.Observation)
		f.Interpretation = cleanString(f.Interpretation)
		f.PotentialImpact = cleanString(f.PotentialImpact)
		f.Recommendation = cleanString(f.Recommendation)

		for k, v := range f.Evidence {
			f.Evidence[k] = cleanValue(v)
		}
	}

	for i := range report.Limitations {
		lim := &report.Limitations[i]
		lim.Reason = cleanString(lim.Reason)
	}

	if report.Data.CPU != nil {
		report.Data.CPU.Model = cleanString(report.Data.CPU.Model)
	}

	if report.Data.Storage != nil {
		for i := range report.Data.Storage.Volumes {
			v := &report.Data.Storage.Volumes[i]
			v.VolumeName = cleanString(v.VolumeName)
		}
		for i := range report.Data.Storage.PhysicalDisks {
			d := &report.Data.Storage.PhysicalDisks[i]
			d.Model = cleanString(d.Model)
			d.DeviceID = cleanString(d.DeviceID)
		}
	}

	if report.Data.Network != nil {
		for i := range report.Data.Network.Adapters {
			a := &report.Data.Network.Adapters[i]
			a.ID = cleanString(a.ID)
			a.Description = cleanString(a.Description)
			for j := range a.IPv4Addresses {
				a.IPv4Addresses[j] = ipv4Regex.ReplaceAllString(a.IPv4Addresses[j], "10.x.x.x")
			}
			for j := range a.Gateways {
				a.Gateways[j] = ipv4Regex.ReplaceAllString(a.Gateways[j], "10.x.x.x")
			}
			for j := range a.DNSServers {
				a.DNSServers[j] = ipv4Regex.ReplaceAllString(a.DNSServers[j], "10.x.x.x")
			}
		}
		if report.Data.Network.DNSTest != nil {
			report.Data.Network.DNSTest.QueryTarget = cleanString(report.Data.Network.DNSTest.QueryTarget)
		}
	}

	if report.Data.Processes != nil {
		for i := range report.Data.Processes.TopCPU {
			p := &report.Data.Processes.TopCPU[i]
			p.ExecutablePath = cleanString(p.ExecutablePath)
		}
		for i := range report.Data.Processes.TopMemory {
			p := &report.Data.Processes.TopMemory[i]
			p.ExecutablePath = cleanString(p.ExecutablePath)
		}
	}

	if report.Data.Services != nil {
		for i := range report.Data.Services.FailedAutoStart {
			s := &report.Data.Services.FailedAutoStart[i]
			s.BinaryPath = cleanString(s.BinaryPath)
			s.Account = cleanString(s.Account)
		}
		for i := range report.Data.Services.Services {
			s := &report.Data.Services.Services[i]
			s.BinaryPath = cleanString(s.BinaryPath)
			s.Account = cleanString(s.Account)
		}
	}

	if report.Data.Reliability != nil {
		for i := range report.Data.Reliability.AppCrashes {
			c := &report.Data.Reliability.AppCrashes[i]
			c.Application = cleanString(c.Application)
			c.FaultModule = cleanString(c.FaultModule)
			c.Message = cleanString(c.Message)
		}
		for i := range report.Data.Reliability.SystemErrors {
			e := &report.Data.Reliability.SystemErrors[i]
			e.Message = cleanString(e.Message)
		}
		for i := range report.Data.Reliability.BugChecks {
			b := &report.Data.Reliability.BugChecks[i]
			b.DumpFile = cleanString(b.DumpFile)
			b.Message = cleanString(b.Message)
		}
		for i := range report.Data.Reliability.KernelPowerEvents {
			kp := &report.Data.Reliability.KernelPowerEvents[i]
			kp.Message = cleanString(kp.Message)
		}
	}

	if report.Data.Software != nil {
		for i := range report.Data.Software.Applications {
			app := &report.Data.Software.Applications[i]
			app.Name = cleanString(app.Name)
			app.Publisher = cleanString(app.Publisher)
		}
		for i := range report.Data.Software.Runtimes {
			r := &report.Data.Software.Runtimes[i]
			r.Path = cleanString(r.Path)
		}
	}
}
