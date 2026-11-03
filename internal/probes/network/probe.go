package network

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

const dnsQueryTarget = "example.com"

// networkCollectionResult preserves adapter observations while accurately
// marking a failed DNS query as partial collection.
func networkCollectionResult(metrics *models.NetworkMetrics) (interface{}, collector.ProbeStatus, error) {
	if metrics.DNSTest == nil || !metrics.DNSTest.Success {
		reason := "no DNS result was produced"
		if metrics.DNSTest != nil {
			reason = metrics.DNSTest.Error
		}
		return metrics, collector.StatusPartial, fmt.Errorf("DNS lookup for %q failed: %s", dnsQueryTarget, reason)
	}
	return metrics, collector.StatusSuccess, nil
}

type dnsLookupFunc func(context.Context, string) ([]net.IPAddr, error)

// runBoundedDNSTest performs one resolver lookup with a fixed upper time bound.
func runBoundedDNSTest(parentCtx context.Context, lookup dnsLookupFunc) *models.DNSResolutionTest {
	ctx, cancel := context.WithTimeout(parentCtx, 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	ips, err := lookup(ctx, dnsQueryTarget)
	result := &models.DNSResolutionTest{
		QueryTarget: dnsQueryTarget,
		DurationMS:  float64(time.Since(start).Microseconds()) / 1000,
		Success:     err == nil,
	}
	if err != nil {
		result.Error = err.Error()
		return result
	}
	for _, ip := range ips {
		result.ResolvedIPs = append(result.ResolvedIPs, ip.String())
	}
	return result
}

// Probe collects network interface telemetry, IP configurations, and DNS timing.
type Probe struct{}

// NewProbe creates a new Network Probe instance.
func NewProbe() *Probe {
	return &Probe{}
}

func (p *Probe) ID() string {
	return "probe_network"
}

func (p *Probe) Name() string {
	return "Network Adapters & DNS Probe"
}

func (p *Probe) Category() collector.ProbeCategory {
	return collector.CategoryNetwork
}

func (p *Probe) RequiredPrivilege() collector.PrivilegeLevel {
	return collector.PrivilegeUser
}

func (p *Probe) SupportedProfiles() []string {
	return []string{"quick", "deep", "all"}
}

func (p *Probe) Run(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	return p.collect(ctx, sampleDuration)
}
