package storage

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

// Probe collects logical volume capacities, filesystems, and physical disk properties.
type Probe struct{}

// NewProbe creates a new Storage Probe instance.
func NewProbe() *Probe {
	return &Probe{}
}

func (p *Probe) ID() string {
	return "probe_storage"
}

func (p *Probe) Name() string {
	return "Storage Volumes & Disks Probe"
}

func (p *Probe) Category() collector.ProbeCategory {
	return collector.CategoryStorage
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
