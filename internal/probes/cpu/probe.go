package cpu

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

// Probe collects CPU architecture, core counts, and real-time utilization.
type Probe struct{}

// NewProbe creates a new CPU probe instance.
func NewProbe() *Probe {
	return &Probe{}
}

func (p *Probe) ID() string {
	return "probe_cpu"
}

func (p *Probe) Name() string {
	return "CPU Topology & Utilization Probe"
}

func (p *Probe) Category() collector.ProbeCategory {
	return collector.CategoryCPU
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
