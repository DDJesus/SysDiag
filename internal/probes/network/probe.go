package network

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

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
	return "Network Adapters & Connectivity Probe"
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
