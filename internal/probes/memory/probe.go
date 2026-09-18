package memory

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

// Probe collects physical RAM, available memory, and virtual commit limits.
type Probe struct{}

// NewProbe creates a new Memory probe instance.
func NewProbe() *Probe {
	return &Probe{}
}

func (p *Probe) ID() string {
	return "probe_memory"
}

func (p *Probe) Name() string {
	return "Physical & Virtual Memory Probe"
}

func (p *Probe) Category() collector.ProbeCategory {
	return collector.CategoryMemory
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
