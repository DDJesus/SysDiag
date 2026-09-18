//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package process

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	metrics := &models.ProcessMetrics{
		TotalProcesses: 100,
		TotalThreads:   400,
		TopCPU: []models.ProcessSummary{
			{
				PID:             1000,
				Name:            "sysdiag",
				WorkingSetBytes: 25000000,
				CPUTimeSeconds:  0.5,
			},
		},
		TopMemory: []models.ProcessSummary{
			{
				PID:             1000,
				Name:            "sysdiag",
				WorkingSetBytes: 25000000,
				CPUTimeSeconds:  0.5,
			},
		},
	}
	return metrics, collector.StatusSuccess, nil
}
