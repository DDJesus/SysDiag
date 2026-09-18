package services

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

// Probe collects installed services, operational states, and failed auto-start services.
type Probe struct{}

// NewProbe creates a new Services Probe instance.
func NewProbe() *Probe {
	return &Probe{}
}

func (p *Probe) ID() string {
	return "probe_services"
}

func (p *Probe) Name() string {
	return "Services & Daemon Status Probe"
}

func (p *Probe) Category() collector.ProbeCategory {
	return collector.CategoryServices
}

func (p *Probe) RequiredPrivilege() collector.PrivilegeLevel {
	return collector.PrivilegeUser
}

func (p *Probe) SupportedProfiles() []string {
	return []string{"quick", "deep", "services", "all"}
}

func (p *Probe) Run(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	return p.collect(ctx, sampleDuration)
}
