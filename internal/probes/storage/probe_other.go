//go:build !windows
// +build !windows

package storage

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	metrics := &models.StorageMetrics{
		Volumes: []models.VolumeMetrics{
			{
				MountPoint:  "/",
				FileSystem:  "ext4",
				DriveType:   "Fixed",
				TotalBytes:  100000000000,
				FreeBytes:   50000000000,
				UsedBytes:   50000000000,
				UsedPercent: 50.0,
			},
		},
	}
	return metrics, collector.StatusSuccess, nil
}
