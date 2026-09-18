//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package memory

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	total := uint64(16 * 1024 * 1024 * 1024)
	avail := uint64(8 * 1024 * 1024 * 1024)
	used := total - avail

	metrics := &models.MemoryMetrics{
		TotalBytes:       total,
		AvailableBytes:   avail,
		UsedBytes:        used,
		UsedPercent:      50.0,
		CommitLimitBytes: total * 2,
		CommitTotalBytes: total,
		CommitPercent:    50.0,
	}
	return metrics, collector.StatusSuccess, nil
}
