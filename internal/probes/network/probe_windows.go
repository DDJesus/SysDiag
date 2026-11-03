//go:build windows
// +build windows

package network

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	adapters, err := winapi.GetNetworkAdapters()
	if err != nil {
		return nil, collector.StatusFailed, err
	}

	var adapterMetrics []models.NetworkAdapterMetrics
	for _, a := range adapters {
		adapterMetrics = append(adapterMetrics, models.NetworkAdapterMetrics{
			ID:            a.ID,
			Name:          a.Name,
			Description:   a.Description,
			MACAddress:    a.MACAddress,
			Status:        a.Status,
			IfType:        a.IfType,
			SpeedMbps:     a.SpeedMbps,
			IPv4Addresses: a.IPv4Addresses,
			IPv6Addresses: a.IPv6Addresses,
			Gateways:      a.Gateways,
			DNSServers:    a.DNSServers,
			DHCPEnabled:   a.DHCPEnabled,
			InOctets:      a.InOctets,
			OutOctets:     a.OutOctets,
			InErrors:      a.InErrors,
			OutErrors:     a.OutErrors,
			InDiscards:    a.InDiscards,
			OutDiscards:   a.OutDiscards,
		})
	}

	// Deterministic DNS resolution timing test
	dnsTest := runDNSTest(ctx)

	metrics := &models.NetworkMetrics{
		Adapters: adapterMetrics,
		DNSTest:  dnsTest,
	}
	if !dnsTest.Success {
		return metrics, collector.StatusPartial, fmt.Errorf("DNS lookup for %q failed: %s", dnsTest.QueryTarget, dnsTest.Error)
	}
	return metrics, collector.StatusSuccess, nil
}

func runDNSTest(parentCtx context.Context) *models.DNSResolutionTest {
	// A public DNS name checks name resolution without claiming internet access.
	target := "example.com"

	dnsCtx, cancel := context.WithTimeout(parentCtx, 1500*time.Millisecond)
	defer cancel()

	start := time.Now()
	ips, err := net.DefaultResolver.LookupIPAddr(dnsCtx, target)
	duration := float64(time.Since(start).Microseconds()) / 1000.0

	testResult := &models.DNSResolutionTest{
		QueryTarget: target,
		DurationMS:  duration,
	}

	if err != nil {
		testResult.Success = false
		testResult.Error = err.Error()
	} else {
		testResult.Success = true
		for _, ip := range ips {
			testResult.ResolvedIPs = append(testResult.ResolvedIPs, ip.String())
		}
	}

	return testResult
}
