//go:build windows
// +build windows

package memory

import (
	"context"
	"math"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	mem, err := winapi.GetMemoryStatus()
	if err != nil {
		return nil, collector.StatusFailed, err
	}

	totalPhys := mem.TotalPhys
	availPhys := mem.AvailPhys
	usedPhys := totalPhys - availPhys

	var usedPercent float64
	if totalPhys > 0 {
		usedPercent = (float64(usedPhys) / float64(totalPhys)) * 100.0
	}

	commitLimit := mem.TotalPageFile
	commitAvail := mem.AvailPageFile
	var commitTotal uint64
	if commitLimit >= commitAvail {
		commitTotal = commitLimit - commitAvail
	}

	var commitPercent float64
	if commitLimit > 0 {
		commitPercent = (float64(commitTotal) / float64(commitLimit)) * 100.0
	}

	metrics := &models.MemoryMetrics{
		TotalBytes:       totalPhys,
		AvailableBytes:   availPhys,
		UsedBytes:        usedPhys,
		UsedPercent:      math.Round(usedPercent*10) / 10,
		CommitLimitBytes: commitLimit,
		CommitTotalBytes: commitTotal,
		CommitPercent:    math.Round(commitPercent*10) / 10,
	}

	return metrics, collector.StatusSuccess, nil
}
