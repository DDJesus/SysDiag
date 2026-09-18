//go:build linux
// +build linux

package memory

import (
	"bufio"
	"context"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, collector.StatusFailed, err
	}
	defer f.Close()

	memMap := make(map[string]uint64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			valStr := strings.TrimSpace(parts[1])
			valFields := strings.Fields(valStr)
			if len(valFields) > 0 {
				if valKB, err := strconv.ParseUint(valFields[0], 10, 64); err == nil {
					memMap[key] = valKB * 1024
				}
			}
		}
	}

	totalPhys := memMap["MemTotal"]
	availPhys := memMap["MemAvailable"]
	if availPhys == 0 {
		availPhys = memMap["MemFree"] + memMap["Buffers"] + memMap["Cached"]
	}

	var usedPhys uint64
	if totalPhys >= availPhys {
		usedPhys = totalPhys - availPhys
	}

	var usedPercent float64
	if totalPhys > 0 {
		usedPercent = (float64(usedPhys) / float64(totalPhys)) * 100.0
	}

	swapTotal := memMap["SwapTotal"]
	swapFree := memMap["SwapFree"]
	var swapUsed uint64
	if swapTotal >= swapFree {
		swapUsed = swapTotal - swapFree
	}

	var swapPercent float64
	if swapTotal > 0 {
		swapPercent = (float64(swapUsed) / float64(swapTotal)) * 100.0
	}

	commitLimit := memMap["CommitLimit"]
	if commitLimit == 0 {
		commitLimit = totalPhys + swapTotal
	}

	commitTotal := memMap["Committed_AS"]
	if commitTotal == 0 {
		commitTotal = usedPhys + swapUsed
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
		CachedBytes:      memMap["Cached"],
		BuffersBytes:     memMap["Buffers"],
		SwapTotalBytes:   swapTotal,
		SwapUsedBytes:    swapUsed,
		SwapFreeBytes:    swapFree,
		SwapPercent:      math.Round(swapPercent*10) / 10,
	}

	return metrics, collector.StatusSuccess, nil
}
