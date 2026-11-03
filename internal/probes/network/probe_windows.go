//go:build windows
// +build windows

package network

import (
	"context"
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
	return networkCollectionResult(metrics)
}

func runDNSTest(parentCtx context.Context) *models.DNSResolutionTest {
	return runBoundedDNSTest(parentCtx, net.DefaultResolver.LookupIPAddr)
}
