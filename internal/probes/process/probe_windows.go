//go:build windows
// +build windows

package process

import (
	"context"
	"sort"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	procs, err := winapi.GetProcesses()
	if err != nil {
		return nil, collector.StatusFailed, err
	}

	totalProcs := len(procs)
	totalThreads := 0

	var list []models.ProcessSummary
	for _, pr := range procs {
		totalThreads += int(pr.ThreadCount)
		var startTime *time.Time
		if !pr.CreationTime.IsZero() {
			st := pr.CreationTime.UTC()
			startTime = &st
		}
		list = append(list, models.ProcessSummary{
			PID:             pr.PID,
			PPID:            pr.PPID,
			Name:            pr.Name,
			ExecutablePath:  pr.ExecutablePath,
			ThreadCount:     pr.ThreadCount,
			WorkingSetBytes: pr.WorkingSetBytes,
			PrivateBytes:    pr.PrivateBytes,
			CPUTimeSeconds:  round1(pr.CPUTimeSeconds),
			StartTime:       startTime,
		})
	}

	// Sort Top Memory
	memList := make([]models.ProcessSummary, len(list))
	copy(memList, list)
	sort.Slice(memList, func(i, j int) bool {
		return memList[i].WorkingSetBytes > memList[j].WorkingSetBytes
	})
	topMemCount := 5
	if len(memList) < topMemCount {
		topMemCount = len(memList)
	}

	// Sort Top CPU Time
	cpuList := make([]models.ProcessSummary, len(list))
	copy(cpuList, list)
	sort.Slice(cpuList, func(i, j int) bool {
		return cpuList[i].CPUTimeSeconds > cpuList[j].CPUTimeSeconds
	})
	topCPUCount := 5
	if len(cpuList) < topCPUCount {
		topCPUCount = len(cpuList)
	}

	metrics := &models.ProcessMetrics{
		TotalProcesses: totalProcs,
		TotalThreads:   totalThreads,
		TopCPU:         cpuList[:topCPUCount],
		TopMemory:      memList[:topMemCount],
	}

	return metrics, collector.StatusSuccess, nil
}

func round1(val float64) float64 {
	return float64(int(val*10+0.5)) / 10.0
}
