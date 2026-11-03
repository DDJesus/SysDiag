package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

// Probe collects logical volume capacities, filesystems, and physical disk properties.
type Probe struct{}

// NewProbe creates a new Storage Probe instance.
func NewProbe() *Probe {
	return &Probe{}
}

// buildWindowsStorageResult keeps successful volume observations when the
// separate physical-disk query fails.
func buildWindowsStorageResult(volumes []winapi.VolumeInfo, disks []winapi.PhysicalDiskInfo, volumeErr, diskErr error) (interface{}, collector.ProbeStatus, error) {
	if volumeErr != nil {
		return nil, collector.StatusFailed, volumeErr
	}
	volumeMetrics := make([]models.VolumeMetrics, 0, len(volumes))
	for _, v := range volumes {
		volumeMetrics = append(volumeMetrics, models.VolumeMetrics{
			MountPoint: v.MountPoint, VolumeName: v.VolumeName, FileSystem: v.FileSystem, DriveType: v.DriveType,
			TotalBytes: v.TotalBytes, FreeBytes: v.FreeBytes, UsedBytes: v.UsedBytes,
			UsedPercent: float64(int(v.UsedPercent*10+0.5)) / 10,
		})
	}
	diskMetrics := make([]models.PhysicalDiskMetrics, 0, len(disks))
	for _, d := range disks {
		diskMetrics = append(diskMetrics, models.PhysicalDiskMetrics{
			DeviceID: d.DeviceID, Model: d.Model, MediaType: d.MediaType,
			BusType: d.BusType, SizeBytes: d.SizeBytes, SerialNumber: d.SerialNumber,
		})
	}
	metrics := &models.StorageMetrics{Volumes: volumeMetrics, PhysicalDisks: diskMetrics}
	if diskErr != nil {
		return metrics, collector.StatusPartial, fmt.Errorf("physical disk collection failed: %w", diskErr)
	}
	return metrics, collector.StatusSuccess, nil
}

func (p *Probe) ID() string {
	return "probe_storage"
}

func (p *Probe) Name() string {
	return "Storage Volumes & Disks Probe"
}

func (p *Probe) Category() collector.ProbeCategory {
	return collector.CategoryStorage
}

func (p *Probe) RequiredPrivilege() collector.PrivilegeLevel {
	return collector.PrivilegeUser
}

func (p *Probe) SupportedProfiles() []string {
	return []string{"quick", "deep", "all"}
}

func (p *Probe) Run(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	return p.collect(ctx, sampleDuration)
}
