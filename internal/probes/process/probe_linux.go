//go:build linux
// +build linux

package process

import (
	"bufio"
	"context"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, collector.StatusFailed, err
	}

	bootTime := readBootTime()
	pageSize := uint64(os.Getpagesize())
	if pageSize == 0 {
		pageSize = 4096
	}

	var list []models.ProcessSummary
	totalThreads := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pidStr := entry.Name()
		pid, err := strconv.ParseUint(pidStr, 10, 32)
		if err != nil {
			continue
		}

		pidDir := filepath.Join(procDir, pidStr)
		statData, err := os.ReadFile(filepath.Join(pidDir, "stat"))
		if err != nil {
			continue
		}

		statStr := string(statData)
		lastParen := strings.LastIndex(statStr, ")")
		firstParen := strings.Index(statStr, "(")
		if firstParen == -1 || lastParen == -1 || lastParen <= firstParen {
			continue
		}

		comm := statStr[firstParen+1 : lastParen]
		rest := strings.Fields(statStr[lastParen+1:])
		if len(rest) < 22 {
			continue
		}

		ppid, _ := strconv.ParseUint(rest[1], 10, 32)
		utime, _ := strconv.ParseUint(rest[11], 10, 64)
		stime, _ := strconv.ParseUint(rest[12], 10, 64)
		threads, _ := strconv.ParseUint(rest[17], 10, 32)
		startTimeTicks, _ := strconv.ParseUint(rest[19], 10, 64)
		rssPages, _ := strconv.ParseUint(rest[21], 10, 64)

		if threads == 0 {
			threads = 1
		}
		totalThreads += int(threads)

		workingSet := rssPages * pageSize
		cpuTimeSec := float64(utime+stime) / 100.0 // Linux USER_HZ default is 100

		var startTime *time.Time
		if !bootTime.IsZero() && startTimeTicks > 0 {
			st := bootTime.Add(time.Duration(float64(startTimeTicks)/100.0 * float64(time.Second))).UTC()
			startTime = &st
		}

		exePath, _ := os.Readlink(filepath.Join(pidDir, "exe"))

		privateBytes := readProcessPrivateBytes(pidDir)

		list = append(list, models.ProcessSummary{
			PID:             uint32(pid),
			PPID:            uint32(ppid),
			Name:            comm,
			ExecutablePath:  exePath,
			ThreadCount:     uint32(threads),
			WorkingSetBytes: workingSet,
			PrivateBytes:    privateBytes,
			CPUTimeSeconds:  math.Round(cpuTimeSec*10) / 10,
			StartTime:       startTime,
		})
	}

	totalProcs := len(list)

	// Sort Top Memory
	memList := make([]models.ProcessSummary, len(list))
	copy(memList, list)
	sort.Slice(memList, func(i, j int) bool {
		return memList[i].WorkingSetBytes > memList[j].WorkingSetBytes
	})
	topMemCount := 5
	if len(memList) < topMemCount {
		topMemCount = len(memList)
	}

	// Sort Top CPU Time
	cpuList := make([]models.ProcessSummary, len(list))
	copy(cpuList, list)
	sort.Slice(cpuList, func(i, j int) bool {
		return cpuList[i].CPUTimeSeconds > cpuList[j].CPUTimeSeconds
	})
	topCPUCount := 5
	if len(cpuList) < topCPUCount {
		topCPUCount = len(cpuList)
	}

	metrics := &models.ProcessMetrics{
		TotalProcesses: totalProcs,
		TotalThreads:   totalThreads,
		TopCPU:         cpuList[:topCPUCount],
		TopMemory:      memList[:topMemCount],
	}

	return metrics, collector.StatusSuccess, nil
}

func readProcessPrivateBytes(pidDir string) uint64 {
	f, err := os.Open(filepath.Join(pidDir, "status"))
	if err != nil {
		return 0
	}
	defer f.Close()

	var vmData, vmStk uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "VmData:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				vmData = val * 1024
			}
		} else if strings.HasPrefix(line, "VmStk:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				vmStk = val * 1024
			}
		}
	}

	return vmData + vmStk
}

func readBootTime() time.Time {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Now().UTC()
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return time.Now().UTC()
	}

	uptimeFloat, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Now().UTC()
	}

	return time.Now().Add(-time.Duration(uptimeFloat * float64(time.Second))).UTC().Truncate(time.Second)
}
