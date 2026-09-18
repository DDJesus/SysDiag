//go:build linux
// +build linux

package storage

import (
	"bufio"
	"context"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

type ioSample struct {
	sectorsRead    uint64
	sectorsWritten uint64
	readTimeMs     uint64
	writeTimeMs    uint64
	inProgress     uint64
	ioTimeMs       uint64
	readOps        uint64
	writeOps       uint64
}

func (p *Probe) collect(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	if sampleDuration <= 0 {
		sampleDuration = 300 * time.Millisecond
	}

	volumeMetrics := collectLinuxVolumes()
	diskMetrics := collectLinuxPhysicalDisks()

	// Sample disk I/O metrics
	io1 := readLinuxDiskStats()

	select {
	case <-time.After(sampleDuration):
	case <-ctx.Done():
		return nil, collector.StatusTimeout, ctx.Err()
	}

	io2 := readLinuxDiskStats()
	ioMetrics := calculateLinuxIOMetrics(io1, io2, sampleDuration)

	metrics := &models.StorageMetrics{
		Volumes:       volumeMetrics,
		PhysicalDisks: diskMetrics,
		IOMetrics:     ioMetrics,
	}

	return metrics, collector.StatusSuccess, nil
}

func collectLinuxVolumes() []models.VolumeMetrics {
	var volumes []models.VolumeMetrics
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return volumes
	}
	defer f.Close()

	seenMounts := make(map[string]bool)
	ignoredFSTypes := map[string]bool{
		"sysfs": true, "proc": true, "devpts": true, "cgroup": true, "cgroup2": true,
		"pstore": true, "bpf": true, "autofs": true, "mqueue": true, "hugetlbfs": true,
		"debugfs": true, "tracefs": true, "fusectl": true, "securityfs": true, "configfs": true,
		"ramfs": true, "devtmpfs": true, "overlay": false, // overlay may be root in container
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		dev := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]
		options := fields[3]

		if ignoredFSTypes[fsType] {
			continue
		}

		// Skip pseudo tmpfs mounts unless root or /tmp
		if fsType == "tmpfs" && mountPoint != "/" && mountPoint != "/tmp" && mountPoint != "/dev/shm" {
			continue
		}

		// Avoid duplicate mounts
		if seenMounts[mountPoint] {
			continue
		}
		seenMounts[mountPoint] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountPoint, &stat); err != nil {
			continue
		}

		if stat.Blocks == 0 {
			continue
		}

		totalBytes := stat.Blocks * uint64(stat.Bsize)
		freeBytes := stat.Bavail * uint64(stat.Bsize)
		var usedBytes uint64
		if totalBytes >= freeBytes {
			usedBytes = totalBytes - freeBytes
		}

		var usedPercent float64
		if totalBytes > 0 {
			usedPercent = (float64(usedBytes) / float64(totalBytes)) * 100.0
		}

		isReadOnly := strings.Contains(options, "ro,") || strings.HasSuffix(options, ",ro") || options == "ro"

		volumes = append(volumes, models.VolumeMetrics{
			MountPoint:  mountPoint,
			VolumeName:  dev,
			FileSystem:  fsType,
			DriveType:   "Fixed",
			TotalBytes:  totalBytes,
			FreeBytes:   freeBytes,
			UsedBytes:   usedBytes,
			UsedPercent: math.Round(usedPercent*10) / 10,
			IsReadOnly:  isReadOnly,
		})
	}

	return volumes
}

func collectLinuxPhysicalDisks() []models.PhysicalDiskMetrics {
	var disks []models.PhysicalDiskMetrics
	blockDir := "/sys/block"
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		return disks
	}

	for _, entry := range entries {
		devName := entry.Name()
		// Skip loop, ram, optical disks
		if strings.HasPrefix(devName, "loop") || strings.HasPrefix(devName, "ram") || strings.HasPrefix(devName, "sr") {
			continue
		}

		devPath := filepath.Join(blockDir, devName)

		// Size in 512-byte sectors
		var sizeBytes uint64
		if sizeData, err := os.ReadFile(filepath.Join(devPath, "size")); err == nil {
			if sectors, err := strconv.ParseUint(strings.TrimSpace(string(sizeData)), 10, 64); err == nil {
				sizeBytes = sectors * 512
			}
		}

		// Model
		model := "Generic Block Device"
		if modelData, err := os.ReadFile(filepath.Join(devPath, "device", "model")); err == nil {
			model = strings.TrimSpace(string(modelData))
		} else if nameData, err := os.ReadFile(filepath.Join(devPath, "device", "name")); err == nil {
			model = strings.TrimSpace(string(nameData))
		}

		// Media type (SSD vs HDD)
		mediaType := "HDD"
		if rotData, err := os.ReadFile(filepath.Join(devPath, "queue", "rotational")); err == nil {
			if strings.TrimSpace(string(rotData)) == "0" {
				mediaType = "SSD"
			}
		}

		// Bus Type
		busType := "SCSI/SATA"
		if strings.HasPrefix(devName, "nvme") {
			busType = "NVMe"
			mediaType = "NVMe SSD"
		} else if strings.HasPrefix(devName, "vd") {
			busType = "VirtIO"
		} else if strings.HasPrefix(devName, "xvd") {
			busType = "Xen Virtual Disk"
		}

		// Serial number
		serial := ""
		if serData, err := os.ReadFile(filepath.Join(devPath, "serial")); err == nil {
			serial = strings.TrimSpace(string(serData))
		} else if serData, err := os.ReadFile(filepath.Join(devPath, "device", "serial")); err == nil {
			serial = strings.TrimSpace(string(serData))
		}

		disks = append(disks, models.PhysicalDiskMetrics{
			DeviceID:     "/dev/" + devName,
			Model:        model,
			MediaType:    mediaType,
			BusType:      busType,
			SizeBytes:    sizeBytes,
			SerialNumber: serial,
		})
	}

	return disks
}

func readLinuxDiskStats() map[string]ioSample {
	samples := make(map[string]ioSample)
	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return samples
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}

		devName := fields[2]
		if strings.HasPrefix(devName, "loop") || strings.HasPrefix(devName, "ram") {
			continue
		}

		readOps, _ := strconv.ParseUint(fields[3], 10, 64)
		sectorsRead, _ := strconv.ParseUint(fields[5], 10, 64)
		readTimeMs, _ := strconv.ParseUint(fields[6], 10, 64)
		writeOps, _ := strconv.ParseUint(fields[7], 10, 64)
		sectorsWritten, _ := strconv.ParseUint(fields[9], 10, 64)
		writeTimeMs, _ := strconv.ParseUint(fields[10], 10, 64)
		inProgress, _ := strconv.ParseUint(fields[11], 10, 64)
		ioTimeMs, _ := strconv.ParseUint(fields[12], 10, 64)

		samples[devName] = ioSample{
			readOps:        readOps,
			sectorsRead:    sectorsRead,
			readTimeMs:     readTimeMs,
			writeOps:       writeOps,
			sectorsWritten: sectorsWritten,
			writeTimeMs:    writeTimeMs,
			inProgress:     inProgress,
			ioTimeMs:       ioTimeMs,
		}
	}

	return samples
}

func calculateLinuxIOMetrics(io1, io2 map[string]ioSample, sampleDuration time.Duration) *models.StorageIOMetrics {
	if len(io1) == 0 || len(io2) == 0 {
		return nil
	}

	durationSec := sampleDuration.Seconds()
	if durationSec <= 0 {
		durationSec = 0.3
	}

	var totalReadBytes, totalWriteBytes uint64
	var totalInProgress uint64
	var totalOps uint64
	var totalIOTimeMs uint64
	var diskCount int

	for dev, s2 := range io2 {
		s1, ok := io1[dev]
		if !ok {
			continue
		}

		// Only compute for top-level disks (e.g. sda, nvme0n1, vda), ignore partitions like sda1
		if strings.Contains(dev, "p") && (strings.HasPrefix(dev, "nvme") || strings.HasPrefix(dev, "mmc")) {
			continue
		}
		if len(dev) > 3 && (strings.HasPrefix(dev, "sd") || strings.HasPrefix(dev, "vd")) && (dev[len(dev)-1] >= '0' && dev[len(dev)-1] <= '9') {
			continue
		}

		if s2.sectorsRead >= s1.sectorsRead {
			totalReadBytes += (s2.sectorsRead - s1.sectorsRead) * 512
		}
		if s2.sectorsWritten >= s1.sectorsWritten {
			totalWriteBytes += (s2.sectorsWritten - s1.sectorsWritten) * 512
		}
		if s2.readOps >= s1.readOps && s2.writeOps >= s1.writeOps {
			totalOps += (s2.readOps - s1.readOps) + (s2.writeOps - s1.writeOps)
		}
		if s2.ioTimeMs >= s1.ioTimeMs {
			totalIOTimeMs += (s2.ioTimeMs - s1.ioTimeMs)
		}
		totalInProgress += s2.inProgress
		diskCount++
	}

	readBytesPerSec := uint64(float64(totalReadBytes) / durationSec)
	writeBytesPerSec := uint64(float64(totalWriteBytes) / durationSec)

	var avgQueue float64
	if diskCount > 0 {
		avgQueue = float64(totalInProgress) / float64(diskCount)
	}

	var avgLatency float64
	if totalOps > 0 {
		avgLatency = float64(totalIOTimeMs) / float64(totalOps)
	}

	return &models.StorageIOMetrics{
		ReadBytesPerSec:  readBytesPerSec,
		WriteBytesPerSec: writeBytesPerSec,
		AvgQueueDepth:    math.Round(avgQueue*100) / 100,
		AvgLatencyMs:     math.Round(avgLatency*100) / 100,
	}
}
