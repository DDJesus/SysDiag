package software

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

// Probe inspects installed software, Windows hotfixes, and system runtimes.
type Probe struct{}

// NewProbe creates a new Software Probe instance.
func NewProbe() *Probe {
	return &Probe{}
}

func (p *Probe) ID() string {
	return "probe_software"
}

func (p *Probe) Name() string {
	return "Installed Software & Runtimes Probe"
}

func (p *Probe) Category() collector.ProbeCategory {
	return collector.CategorySoftware
}

func (p *Probe) RequiredPrivilege() collector.PrivilegeLevel {
	return collector.PrivilegeUser
}

func (p *Probe) SupportedProfiles() []string {
	return []string{"quick", "deep", "inventory", "all"}
}

func (p *Probe) Run(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	return p.collect(ctx, sampleDuration)
}
