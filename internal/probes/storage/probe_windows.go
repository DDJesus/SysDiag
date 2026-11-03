//go:build windows
// +build windows

package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	vols, err := winapi.GetVolumes()
	if err != nil {
		return nil, collector.StatusFailed, err
	}

	var volumeMetrics []models.VolumeMetrics
	for _, v := range vols {
		volumeMetrics = append(volumeMetrics, models.VolumeMetrics{
			MountPoint:  v.MountPoint,
			VolumeName:  v.VolumeName,
			FileSystem:  v.FileSystem,
			DriveType:   v.DriveType,
			TotalBytes:  v.TotalBytes,
			FreeBytes:   v.FreeBytes,
			UsedBytes:   v.UsedBytes,
			UsedPercent: round2(v.UsedPercent),
		})
	}

	var diskMetrics []models.PhysicalDiskMetrics
	disks, diskErr := winapi.GetPhysicalDisks()
	for _, d := range disks {
		diskMetrics = append(diskMetrics, models.PhysicalDiskMetrics{
			DeviceID:     d.DeviceID,
			Model:        d.Model,
			MediaType:    d.MediaType,
			BusType:      d.BusType,
			SizeBytes:    d.SizeBytes,
			SerialNumber: d.SerialNumber,
		})
	}

	metrics := &models.StorageMetrics{
		Volumes:       volumeMetrics,
		PhysicalDisks: diskMetrics,
	}

	if diskErr != nil {
		return metrics, collector.StatusPartial, fmt.Errorf("physical disk collection failed: %w", diskErr)
	}
	return metrics, collector.StatusSuccess, nil
}

func round2(val float64) float64 {
	return float64(int(val*10+0.5)) / 10.0
}
