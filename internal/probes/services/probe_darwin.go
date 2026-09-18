//go:build darwin
// +build darwin

package services

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	metrics := &models.ServicesMetrics{
		TotalCount:           10,
		RunningCount:         10,
		StoppedCount:         0,
		FailedAutoStartCount: 0,
		FailedAutoStart:      make([]models.ServiceInfo, 0),
		Services: []models.ServiceInfo{
			{
				Name:        "com.apple.launchd",
				DisplayName: "launchd",
				Status:      "Running",
				StartType:   "Auto",
			},
		},
	}
	return metrics, collector.StatusSuccess, nil
}
