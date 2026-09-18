package reliability

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

// Probe queries the Windows Event Log and crash logs for system reliability diagnostics.
type Probe struct{}

// NewProbe creates a new Reliability Probe instance.
func NewProbe() *Probe {
	return &Probe{}
}

func (p *Probe) ID() string {
	return "probe_reliability"
}

func (p *Probe) Name() string {
	return "Reliability & Event Log Diagnostics Probe"
}

func (p *Probe) Category() collector.ProbeCategory {
	return collector.CategoryReliability
}

func (p *Probe) RequiredPrivilege() collector.PrivilegeLevel {
	return collector.PrivilegeUser
}

func (p *Probe) SupportedProfiles() []string {
	return []string{"quick", "deep", "reliability", "all"}
}

func (p *Probe) Run(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	return p.collect(ctx, sampleDuration)
}
