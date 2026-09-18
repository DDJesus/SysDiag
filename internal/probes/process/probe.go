package process

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

// Probe collects running process inventory and top CPU / memory consumers.
type Probe struct{}

// NewProbe creates a new Process Probe instance.
func NewProbe() *Probe {
	return &Probe{}
}

func (p *Probe) ID() string {
	return "probe_process"
}

func (p *Probe) Name() string {
	return "Processes & Resource Consumers Probe"
}

func (p *Probe) Category() collector.ProbeCategory {
	return collector.CategoryProcesses
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
