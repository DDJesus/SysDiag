//go:build darwin
// +build darwin

package network

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, collector.StatusFailed, err
	}

	var adapterMetrics []models.NetworkAdapterMetrics
	for _, iface := range ifaces {
		status := "Down"
		if iface.Flags&net.FlagUp != 0 {
			status = "Up"
		}
		ifType := "Ethernet"
		if iface.Flags&net.FlagLoopback != 0 {
			ifType = "Loopback"
		}

		var ipv4List, ipv6List []string
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					ipv4List = append(ipv4List, ipnet.IP.String())
				} else {
					ipv6List = append(ipv6List, ipnet.IP.String())
				}
			}
		}

		adapterMetrics = append(adapterMetrics, models.NetworkAdapterMetrics{
			ID:            iface.Name,
			Name:          iface.Name,
			Description:   iface.Name,
			MACAddress:    iface.HardwareAddr.String(),
			Status:        status,
			IfType:        ifType,
			IPv4Addresses: ipv4List,
			IPv6Addresses: ipv6List,
		})
	}

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
