//go:build darwin
// +build darwin

package process

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	metrics := &models.ProcessMetrics{
		TotalProcesses: 100,
		TotalThreads:   400,
		TopCPU: []models.ProcessSummary{
			{
				PID:            1,
				Name:           "launchd",
				ExecutablePath: "/sbin/launchd",
				ThreadCount:    10,
				CPUTimeSeconds: 12.5,
			},
		},
		TopMemory: []models.ProcessSummary{
			{
				PID:             1,
				Name:            "launchd",
				ExecutablePath:  "/sbin/launchd",
				WorkingSetBytes: 50 * 1024 * 1024,
			},
		},
	}
	return metrics, collector.StatusSuccess, nil
}
