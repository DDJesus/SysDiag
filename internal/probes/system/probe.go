package system

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

// Probe collects operating system identity, host metadata, and uptime.
type Probe struct{}

// NewProbe creates a new SystemProbe instance.
func NewProbe() *Probe {
	return &Probe{}
}

func (p *Probe) ID() string {
	return "probe_system"
}

func (p *Probe) Name() string {
	return "System & Host Identity Probe"
}

func (p *Probe) Category() collector.ProbeCategory {
	return collector.CategorySystem
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
