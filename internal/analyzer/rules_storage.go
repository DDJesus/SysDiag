package analyzer

import (
	"context"
	"fmt"
	"math"

	"github.com/systemdiag/sysdiag/internal/models"
)

// StorageVolumeCapacityRule checks logical volume free space thresholds.
type StorageVolumeCapacityRule struct{}

func (r *StorageVolumeCapacityRule) ID() string {
	return "RULE-STORAGE-001"
}

func (r *StorageVolumeCapacityRule) Category() string {
	return "storage"
}

func (r *StorageVolumeCapacityRule) Name() string {
	return "Storage Volume Free Space Rule"
}

func (r *StorageVolumeCapacityRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Storage == nil || len(report.Data.Storage.Volumes) == 0 {
		return nil, nil
	}

	var findings []models.Finding
	toGB := func(b uint64) float64 {
		return math.Round((float64(b)/(1024*1024*1024))*100) / 100
	}

	for _, vol := range report.Data.Storage.Volumes {
		if vol.TotalBytes == 0 || vol.DriveType == "CD-ROM" {
			continue
		}

		if vol.UsedPercent >= 95.0 {
			findings = append(findings, models.Finding{
				ID:          "FINDING-STORAGE-001",
				Category:    "storage",
				Severity:    models.SeverityCritical,
				Title:       fmt.Sprintf("Critical free space exhaustion on volume %s", vol.MountPoint),
				Observation: fmt.Sprintf("Volume %s measured %.1f%% used capacity with %.2f GB free of %.2f GB total.", vol.MountPoint, vol.UsedPercent, toGB(vol.FreeBytes), toGB(vol.TotalBytes)),
				Evidence: map[string]interface{}{
					"mount_point":                vol.MountPoint,
					"volume_name":                vol.VolumeName,
					"filesystem":                 vol.FileSystem,
					"total_gb":                   toGB(vol.TotalBytes),
					"free_gb":                    toGB(vol.FreeBytes),
					"used_percent":               vol.UsedPercent,
					"threshold_critical_percent": 95.0,
				},
				Interpretation:  fmt.Sprintf("Volume %s has less than 5%% remaining free capacity.", vol.MountPoint),
				PotentialImpact: "Applications or system services writing data, temporary files, or logs to this volume may encounter write failures.",
				Recommendation:  fmt.Sprintf("Identify large files or unneeded temporary data on %s to restore free storage headroom.", vol.MountPoint),
				Confidence:      models.ConfidenceHigh,
			})
		} else if vol.UsedPercent >= 90.0 {
			findings = append(findings, models.Finding{
				ID:          "FINDING-STORAGE-001",
				Category:    "storage",
				Severity:    models.SeverityWarning,
				Title:       fmt.Sprintf("Low free space on volume %s", vol.MountPoint),
				Observation: fmt.Sprintf("Volume %s measured %.1f%% used capacity with %.2f GB free of %.2f GB total.", vol.MountPoint, vol.UsedPercent, toGB(vol.FreeBytes), toGB(vol.TotalBytes)),
				Evidence: map[string]interface{}{
					"mount_point":               vol.MountPoint,
					"volume_name":               vol.VolumeName,
					"filesystem":                vol.FileSystem,
					"total_gb":                  toGB(vol.TotalBytes),
					"free_gb":                   toGB(vol.FreeBytes),
					"used_percent":              vol.UsedPercent,
					"threshold_warning_percent": 90.0,
				},
				Interpretation:  fmt.Sprintf("Volume %s has less than 10%% remaining free capacity.", vol.MountPoint),
				PotentialImpact: "Available storage capacity for ongoing data accumulation is constrained.",
				Recommendation:  fmt.Sprintf("Review storage consumption trends on volume %s and clean up unnecessary files.", vol.MountPoint),
				Confidence:      models.ConfidenceHigh,
			})
		}
	}

	return findings, nil
}

// StorageDiskQueueDepthRule evaluates disk queue depth and latency if I/O telemetry is measured.
type StorageDiskQueueDepthRule struct{}

func (r *StorageDiskQueueDepthRule) ID() string {
	return "RULE-STORAGE-002"
}

func (r *StorageDiskQueueDepthRule) Category() string {
	return "storage"
}

func (r *StorageDiskQueueDepthRule) Name() string {
	return "Storage Disk Queue Depth & Latency Rule"
}

func (r *StorageDiskQueueDepthRule) Evaluate(_ context.Context, report *models.DiagnosticReport) ([]models.Finding, error) {
	if report.Data.Storage == nil || report.Data.Storage.IOMetrics == nil {
		return nil, nil
	}

	io := report.Data.Storage.IOMetrics
	if io.AvgQueueDepth <= 0 {
		return nil, nil
	}

	diskCount := len(report.Data.Storage.PhysicalDisks)
	if diskCount == 0 {
		diskCount = 1
	}

	// Threshold: avg queue depth sustained above 2.0 per physical spindle/drive
	threshold := float64(diskCount) * 2.0

	var findings []models.Finding
	if io.AvgQueueDepth > threshold {
		findings = append(findings, models.Finding{
			ID:          "FINDING-STORAGE-002",
			Category:    "storage",
			Severity:    models.SeverityWarning,
			Title:       "Elevated disk queue depth measured during sampling",
			Observation: fmt.Sprintf("Average disk queue depth measured %.2f across %d physical disk(s) with %.1f ms average transfer latency.", io.AvgQueueDepth, diskCount, io.AvgLatencyMs),
			Evidence: map[string]interface{}{
				"avg_queue_depth":       io.AvgQueueDepth,
				"avg_latency_ms":        io.AvgLatencyMs,
				"read_bytes_per_sec":    io.ReadBytesPerSec,
				"write_bytes_per_sec":   io.WriteBytesPerSec,
				"physical_disks_count":  diskCount,
				"threshold_queue_depth": threshold,
			},
			Interpretation:  "Pending disk I/O requests exceeded the baseline threshold during the sampling period.",
			PotentialImpact: "Disk-bound applications may experience delayed I/O completion and increased read/write latency.",
			Recommendation:  "Inspect active processes generating high disk I/O and verify storage subsystem health.",
			Confidence:      models.ConfidenceHigh,
		})
	}

	return findings, nil
}
