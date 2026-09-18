//go:build darwin
// +build darwin

package system

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "UNKNOWN-HOST"
	}

	metrics := &models.SystemMetrics{
		Hostname:      hostname,
		OSName:        "macOS",
		OSVersion:     "Darwin",
		OSBuild:       runtime.Version(),
		Architecture:  runtime.GOARCH,
		UptimeSeconds: 0,
		BootTime:      time.Now().UTC(),
		Virtualization: models.VirtualizationInfo{
			IsVirtual: false,
		},
	}

	return metrics, collector.StatusSuccess, nil
}
