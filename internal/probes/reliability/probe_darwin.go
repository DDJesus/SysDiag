//go:build darwin
// +build darwin

package reliability

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	metrics := &models.ReliabilityMetrics{
		TimeWindowHours:   24,
		TotalErrorsLogged: 0,
		AppCrashes:        make([]models.AppCrashEvent, 0),
		SystemErrors:      make([]models.SystemErrorEvent, 0),
		KernelPowerEvents: make([]models.KernelPowerEvent, 0),
		BugChecks:         make([]models.BugCheckEvent, 0),
	}
	return metrics, collector.StatusSuccess, nil
}
