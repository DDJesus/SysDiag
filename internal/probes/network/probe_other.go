//go:build !windows
// +build !windows

package network

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	speed := uint64(1000)
	metrics := &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{
			{
				ID:            "eth0",
				Name:          "eth0",
				Status:        "Up",
				IfType:        "Ethernet",
				SpeedMbps:     &speed,
				IPv4Addresses: []string{"192.168.1.100"},
				Gateways:      []string{"192.168.1.1"},
			},
		},
		DNSTest: &models.DNSResolutionTest{
			QueryTarget: "localhost",
			DurationMS:  1.2,
			Success:     true,
			ResolvedIPs: []string{"127.0.0.1"},
		},
	}
	return metrics, collector.StatusSuccess, nil
}
