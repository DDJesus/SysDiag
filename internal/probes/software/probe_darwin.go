//go:build darwin
// +build darwin

package software

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	metrics := &models.SoftwareMetrics{
		TotalInstalledApps: 1,
		Applications: []models.InstalledApp{
			{
				Name:      "macOS Base System",
				Version:   "14.0",
				Publisher: "Apple Inc.",
				Scope:     "System",
			},
		},
		Runtimes: make([]models.RuntimeInfo, 0),
		HotFixes: make([]models.HotFixInfo, 0),
	}
	return metrics, collector.StatusSuccess, nil
}
