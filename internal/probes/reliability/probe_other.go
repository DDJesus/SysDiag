//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package reliability

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	return &models.ReliabilityMetrics{
		TimeWindowHours:   24,
		TotalErrorsLogged: 0,
		AppCrashes:        make([]models.AppCrashEvent, 0),
		SystemErrors:      make([]models.SystemErrorEvent, 0),
		KernelPowerEvents: make([]models.KernelPowerEvent, 0),
		BugChecks:         make([]models.BugCheckEvent, 0),
	}, collector.StatusUnsupported, nil
}
