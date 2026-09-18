package analyzer

import (
	"context"
	"fmt"

	"github.com/systemdiag/sysdiag/internal/models"
)

// NetworkInterfaceErrorsRule detects packet transmission or reception errors on active adapters.
type NetworkInterfaceErrorsRule struct{}

func (r *NetworkInterfaceErrorsRule) ID() string {
	return "RULE-NET-001"
}

func (r *NetworkInterfaceErrorsRule) Category() string {
	return "network"
}

func (r *NetworkInterfaceErrorsRule) Name() string {
	return "Network Interface Error Rule"
}

func (r *NetworkInterfaceErrorsRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Network == nil || len(report.Data.Network.Adapters) == 0 {
		return nil, nil
	}

	var findings []models.Finding

	for _, a := range report.Data.Network.Adapters {
		if a.Status != "Up" {
			continue
		}

		if a.InErrors > 0 || a.OutErrors > 0 {
			findings = append(findings, models.Finding{
				ID:          "FINDING-NET-001",
				Category:    "network",
				Severity:    models.SeverityWarning,
				Title:       fmt.Sprintf("Packet errors recorded on network adapter %s", a.Name),
				Observation: fmt.Sprintf("Adapter '%s' (%s) recorded %d incoming error(s) and %d outgoing error(s).", a.Name, a.Description, a.InErrors, a.OutErrors),
				Evidence: map[string]interface{}{
					"adapter_name": a.Name,
					"description":  a.Description,
					"mac_address":  a.MACAddress,
					"in_errors":    a.InErrors,
					"out_errors":   a.OutErrors,
					"status":       a.Status,
					"speed_mbps":   a.SpeedMbps,
				},
				Interpretation:  "Network interface packet errors were measured on this active adapter.",
				PotentialImpact: "Network communication over this interface may experience packet loss, retransmissions, or degraded throughput.",
				Recommendation:  fmt.Sprintf("Check network cabling, switch port statistics, and adapter driver status for interface '%s'.", a.Name),
				Confidence:      models.ConfidenceHigh,
			})
		}
	}

	return findings, nil
}

// NetworkDNSLatencyRule evaluates DNS resolution failure or latency degradation.
type NetworkDNSLatencyRule struct{}

func (r *NetworkDNSLatencyRule) ID() string {
	return "RULE-NET-002"
}

func (r *NetworkDNSLatencyRule) Category() string {
	return "network"
}

func (r *NetworkDNSLatencyRule) Name() string {
	return "DNS Resolution Latency & Availability Rule"
}

func (r *NetworkDNSLatencyRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Network == nil || report.Data.Network.DNSTest == nil {
		return nil, nil
	}

	dns := report.Data.Network.DNSTest
	var findings []models.Finding

	if !dns.Success && dns.Error != "" {
		findings = append(findings, models.Finding{
			ID:          "FINDING-NET-002",
			Category:    "network",
			Severity:    models.SeverityWarning,
			Title:       "DNS resolution failure during diagnostic check",
			Observation: fmt.Sprintf("Lookup for target '%s' failed: %s (after %.1f ms).", dns.QueryTarget, dns.Error, dns.DurationMS),
			Evidence: map[string]interface{}{
				"query_target": dns.QueryTarget,
				"success":      dns.Success,
				"duration_ms":  dns.DurationMS,
				"error":        dns.Error,
			},
			Interpretation:  "Local host was unable to resolve the test domain name via configured DNS servers.",
			PotentialImpact: "Applications relying on domain name resolution may fail to connect to network resources.",
			Recommendation:  "Verify DNS server IP configuration, gateway reachability, and network connection state.",
			Confidence:      models.ConfidenceHigh,
		})
	} else if dns.Success && dns.DurationMS >= 1500 {
		findings = append(findings, models.Finding{
			ID:          "FINDING-NET-002",
			Category:    "network",
			Severity:    models.SeverityWarning,
			Title:       "High DNS resolution latency measured",
			Observation: fmt.Sprintf("DNS lookup for target '%s' took %.1f ms (resolved to %v).", dns.QueryTarget, dns.DurationMS, dns.ResolvedIPs),
			Evidence: map[string]interface{}{
				"query_target":              dns.QueryTarget,
				"duration_ms":               dns.DurationMS,
				"threshold_warn_latency_ms": 1500.0,
				"resolved_ips":              dns.ResolvedIPs,
			},
			Interpretation:  "DNS lookup time exceeded expected local resolution latency thresholds.",
			PotentialImpact: "Network requests and initial service handshakes may experience noticeable delay.",
			Recommendation:  "Inspect upstream DNS server response times and verify whether primary DNS servers are reachable.",
			Confidence:      models.ConfidenceHigh,
		})
	}

	return findings, nil
}
