//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package services

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	return &models.ServicesMetrics{
		TotalCount:      0,
		FailedAutoStart: make([]models.ServiceInfo, 0),
		Services:        make([]models.ServiceInfo, 0),
	}, collector.StatusUnsupported, nil
}
