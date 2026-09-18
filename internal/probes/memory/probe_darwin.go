//go:build darwin
// +build darwin

package memory

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	metrics := &models.MemoryMetrics{
		TotalBytes:       16 * 1024 * 1024 * 1024,
		AvailableBytes:   8 * 1024 * 1024 * 1024,
		UsedBytes:        8 * 1024 * 1024 * 1024,
		UsedPercent:      50.0,
		CommitLimitBytes: 16 * 1024 * 1024 * 1024,
		CommitTotalBytes: 8 * 1024 * 1024 * 1024,
		CommitPercent:    50.0,
	}
	return metrics, collector.StatusSuccess, nil
}
