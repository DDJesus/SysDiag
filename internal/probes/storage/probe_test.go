package storage

import (
	"errors"
	"testing"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func TestBuildWindowsStorageResultSuccess(t *testing.T) {
	data, status, err := buildWindowsStorageResult(
		[]winapi.VolumeInfo{{MountPoint: "C:\\", TotalBytes: 100, FreeBytes: 40, UsedBytes: 60, UsedPercent: 60}},
		[]winapi.PhysicalDiskInfo{{DeviceID: "disk0", Model: "test disk"}}, nil, nil,
	)
	if err != nil || status != collector.StatusSuccess {
		t.Fatalf("got status %q, error %v", status, err)
	}
	metrics := data.(*models.StorageMetrics)
	if len(metrics.Volumes) != 1 || len(metrics.PhysicalDisks) != 1 {
		t.Fatalf("expected volume and disk observations, got %#v", metrics)
	}
}

func TestBuildWindowsStorageResultPreservesVolumesOnDiskFailure(t *testing.T) {
	diskErr := errors.New("disk query denied")
	data, status, err := buildWindowsStorageResult(
		[]winapi.VolumeInfo{{MountPoint: "C:\\", TotalBytes: 100, FreeBytes: 40, UsedBytes: 60}}, nil, nil, diskErr,
	)
	if status != collector.StatusPartial || !errors.Is(err, diskErr) {
		t.Fatalf("got status %q, error %v; want Partial wrapping disk error", status, err)
	}
	metrics := data.(*models.StorageMetrics)
	if len(metrics.Volumes) != 1 || metrics.Volumes[0].TotalBytes != 100 {
		t.Fatalf("volume observations were not preserved: %#v", metrics.Volumes)
	}
}

func TestBuildWindowsStorageResultVolumeFailure(t *testing.T) {
	volumeErr := errors.New("volume query failed")
	data, status, err := buildWindowsStorageResult(nil, nil, volumeErr, nil)
	if data != nil || status != collector.StatusFailed || !errors.Is(err, volumeErr) {
		t.Fatalf("got data %#v, status %q, error %v; want nil, Failed, original error", data, status, err)
	}
}
