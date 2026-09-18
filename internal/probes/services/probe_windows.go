//go:build windows
// +build windows

package services

import (
	"context"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func (p *Probe) collect(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	services, err := winapi.GetServices()
	if err != nil {
		return nil, collector.StatusFailed, err
	}

	metrics := &models.ServicesMetrics{
		TotalCount:      len(services),
		FailedAutoStart: make([]models.ServiceInfo, 0),
		Services:        services,
	}

	for _, s := range services {
		switch s.Status {
		case "Running":
			metrics.RunningCount++
		case "Stopped":
			metrics.StoppedCount++
		}

		// Detect failed auto-start:
		// Startup is Auto or Auto (Delayed), but service is stopped and not trigger-start/stopped with clean 0 unless unexpected.
		// Exclude known on-demand / trigger-start services that legitimately stop (e.g. EdgeUpdate, MapsBroker, gupdate).
		if (s.StartType == "Auto" || s.StartType == "Auto (Delayed)") && s.Status == "Stopped" {
			// Filter out benign background trigger updaters that stop when task completes
			nameLower := strings.ToLower(s.Name)
			if !strings.Contains(nameLower, "update") && !strings.Contains(nameLower, "edgeupdate") && !strings.Contains(nameLower, "googleupdate") {
				metrics.FailedAutoStart = append(metrics.FailedAutoStart, s)
			}
		}
	}

	metrics.FailedAutoStartCount = len(metrics.FailedAutoStart)

	return metrics, collector.StatusSuccess, nil
}
