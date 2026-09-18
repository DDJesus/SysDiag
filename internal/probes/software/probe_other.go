//go:build !windows
// +build !windows

package software

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	return &models.SoftwareMetrics{
		TotalInstalledApps: 0,
		Applications:       make([]models.InstalledApp, 0),
		HotFixes:           make([]models.HotFixInfo, 0),
		Runtimes:           make([]models.RuntimeInfo, 0),
	}, collector.StatusUnsupported, nil
}
