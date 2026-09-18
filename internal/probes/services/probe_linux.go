//go:build linux
// +build linux

package services

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	services, probeStatus, err := collectLinuxSystemdServices(ctx)
	if err != nil && len(services) == 0 {
		return &models.ServicesMetrics{
			TotalCount:      0,
			FailedAutoStart: make([]models.ServiceInfo, 0),
			Services:        make([]models.ServiceInfo, 0),
		}, collector.StatusPartial, err
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
		case "Stopped", "Failed":
			metrics.StoppedCount++
		}

		if (s.StartType == "Auto" || s.StartType == "Auto (Delayed)") && (s.Status == "Stopped" || s.Status == "Failed") {
			metrics.FailedAutoStart = append(metrics.FailedAutoStart, s)
		}
	}

	metrics.FailedAutoStartCount = len(metrics.FailedAutoStart)

	return metrics, probeStatus, nil
}

func collectLinuxSystemdServices(ctx context.Context) ([]models.ServiceInfo, collector.ProbeStatus, error) {
	var services []models.ServiceInfo

	// Check if systemctl binary exists
	cmdPath, err := exec.LookPath("systemctl")
	if err != nil {
		return services, collector.StatusUnsupported, nil
	}

	// 1. Read unit file enablement states
	enabledMap := make(map[string]string)
	cmdFiles := exec.CommandContext(ctx, cmdPath, "list-unit-files", "--type=service", "--no-pager", "--no-legend", "--plain")
	if out, err := cmdFiles.Output(); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 {
				unit := fields[0]
				state := fields[1]
				switch state {
				case "enabled", "enabled-runtime":
					enabledMap[unit] = "Auto"
				case "disabled", "static", "indirect", "generated":
					enabledMap[unit] = "Manual"
				case "masked", "masked-runtime":
					enabledMap[unit] = "Disabled"
				default:
					enabledMap[unit] = "Unknown"
				}
			}
		}
	}

	// 2. Read active / loaded service units
	cmdUnits := exec.CommandContext(ctx, cmdPath, "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain")
	out, err := cmdUnits.Output()
	if err != nil {
		return services, collector.StatusPartial, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		unitName := fields[0]
		loadState := fields[1]
		activeState := fields[2]
		subState := fields[3]
		desc := ""
		if len(fields) >= 5 {
			desc = strings.Join(fields[4:], " ")
		}

		if !strings.HasSuffix(unitName, ".service") {
			continue
		}

		startType := "Manual"
		if st, ok := enabledMap[unitName]; ok {
			startType = st
		}

		status := "Stopped"
		var exitCode uint32

		if activeState == "active" {
			status = "Running"
		} else if activeState == "failed" || subState == "failed" {
			status = "Stopped"
			exitCode = 1
		} else if activeState == "activating" {
			status = "StartPending"
		} else if activeState == "deactivating" {
			status = "StopPending"
		} else if activeState == "inactive" {
			status = "Stopped"
		}

		if loadState == "not-found" || loadState == "error" {
			continue
		}

		displayName := desc
		if displayName == "" {
			displayName = unitName
		}

		services = append(services, models.ServiceInfo{
			Name:        unitName,
			DisplayName: displayName,
			Status:      status,
			StartType:   startType,
			ExitCode:    exitCode,
		})
	}

	return services, collector.StatusSuccess, nil
}
