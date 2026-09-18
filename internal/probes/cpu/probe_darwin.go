//go:build darwin
// +build darwin

package cpu

import (
	"context"
	"runtime"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	numCPU := runtime.NumCPU()
	metrics := &models.CPUMetrics{
		Model:         "Apple Silicon / Generic macOS CPU",
		PhysicalCores: numCPU,
		LogicalCores:  numCPU,
	}
	return metrics, collector.StatusSuccess, nil
}
