//go:build darwin
// +build darwin

package storage

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	metrics := &models.StorageMetrics{
		Volumes: []models.VolumeMetrics{
			{
				MountPoint:  "/",
				VolumeName:  "/dev/disk1s1",
				FileSystem:  "apfs",
				DriveType:   "Fixed",
				TotalBytes:  500 * 1024 * 1024 * 1024,
				FreeBytes:   250 * 1024 * 1024 * 1024,
				UsedBytes:   250 * 1024 * 1024 * 1024,
				UsedPercent: 50.0,
			},
		},
		PhysicalDisks: []models.PhysicalDiskMetrics{
			{
				DeviceID:  "/dev/disk0",
				Model:     "Apple Internal NVMe SSD",
				MediaType: "NVMe SSD",
				BusType:   "NVMe",
				SizeBytes: 500 * 1024 * 1024 * 1024,
			},
		},
	}
	return metrics, collector.StatusSuccess, nil
}
