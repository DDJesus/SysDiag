//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package system

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	hostname, _ := os.Hostname()
	metrics := &models.SystemMetrics{
		Hostname:       hostname,
		OSName:         runtime.GOOS,
		OSBuild:        "generic",
		Architecture:   runtime.GOARCH,
		UptimeSeconds:  3600,
		BootTime:       time.Now().Add(-1 * time.Hour).UTC(),
		Virtualization: models.VirtualizationInfo{IsVirtual: false},
	}
	return metrics, collector.StatusSuccess, nil
}
