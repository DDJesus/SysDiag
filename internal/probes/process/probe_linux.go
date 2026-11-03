//go:build linux
// +build linux

package process

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, collector.StatusCanceled, err
	}
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, collector.StatusFailed, err
	}

	bootTime := readBootTime()
	clockTicks, clockErr := linuxClockTicks(ctx)
	pageSize := uint64(os.Getpagesize())
	if pageSize == 0 {
		pageSize = 4096
	}

	var list []models.ProcessSummary
	totalThreads := 0
	malformed := 0
	denied := 0

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			metrics := buildProcessMetrics(list, totalThreads, clockErr == nil)
			return metrics, collector.StatusPartial, fmt.Errorf("process enumeration canceled after partial results: %w", err)
		}
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
			if os.IsPermission(err) {
				denied++
			}
			continue
		}

		record, parseErr := parseLinuxProcessStat(string(statData))
		if parseErr != nil {
			malformed++
			continue
		}
		ppid, utime, stime := record.ppid, record.utime, record.stime
		threads, startTimeTicks, rssPages := record.threads, record.startTicks, record.rssPages

		if threads == 0 {
			threads = 1
		}
		totalThreads += int(threads)

		workingSet := rssPages * pageSize
		var cpuTimeSec float64
		if clockErr == nil {
			cpuTimeSec, _ = ticksToSeconds(utime+stime, clockTicks)
		}

		var startTime *time.Time
		if clockErr == nil && !bootTime.IsZero() && startTimeTicks > 0 {
			st := bootTime.Add(time.Duration(float64(startTimeTicks) / float64(clockTicks) * float64(time.Second))).UTC()
			startTime = &st
		}

		exePath, _ := os.Readlink(filepath.Join(pidDir, "exe"))

		privateBytes := readProcessPrivateBytes(pidDir)

		list = append(list, models.ProcessSummary{
			PID:             uint32(pid),
			PPID:            uint32(ppid),
			Name:            record.comm,
			ExecutablePath:  exePath,
			ThreadCount:     uint32(threads),
			WorkingSetBytes: workingSet,
			PrivateBytes:    privateBytes,
			CPUTimeSeconds:  math.Round(cpuTimeSec*10) / 10,
			StartTime:       startTime,
		})
	}

	metrics := buildProcessMetrics(list, totalThreads, clockErr == nil)
	if ctx.Err() != nil {
		return metrics, collector.StatusPartial, fmt.Errorf("process enumeration canceled after partial results: %w", ctx.Err())
	}
	if clockErr != nil {
		return metrics, collector.StatusPartial, fmt.Errorf("process CPU time and start time unavailable: %w", clockErr)
	}
	if bootTime.IsZero() {
		return metrics, collector.StatusPartial, fmt.Errorf("process start times unavailable: could not read /proc/uptime")
	}
	if malformed > 0 {
		return metrics, collector.StatusPartial, fmt.Errorf("skipped %d malformed /proc process-stat records", malformed)
	}
	if denied > 0 {
		return metrics, collector.StatusPartial, fmt.Errorf("permission denied reading %d /proc process-stat records", denied)
	}
	return metrics, collector.StatusSuccess, nil
}

func ticksToSeconds(ticks, clockTicks uint64) (float64, bool) {
	if clockTicks == 0 {
		return 0, false
	}
	return float64(ticks) / float64(clockTicks), true
}

type linuxProcessStat struct {
	comm                               string
	ppid, threads                      uint64
	utime, stime, startTicks, rssPages uint64
}

// Linux comm is parenthesized but may itself contain spaces and parentheses;
// the final right parenthesis marks the end of the comm field.
func parseLinuxProcessStat(stat string) (linuxProcessStat, error) {
	first := strings.IndexByte(stat, '(')
	last := strings.LastIndexByte(stat, ')')
	if first < 0 || last <= first || len(stat[last+1:]) == 0 {
		return linuxProcessStat{}, fmt.Errorf("invalid stat comm field")
	}
	fields := strings.Fields(stat[last+1:])
	if len(fields) < 22 {
		return linuxProcessStat{}, fmt.Errorf("stat has %d fields after comm, want at least 22", len(fields))
	}
	parse := func(index int, name string) (uint64, error) {
		value, err := strconv.ParseUint(fields[index], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid %s: %w", name, err)
		}
		return value, nil
	}
	var out linuxProcessStat
	out.comm = stat[first+1 : last]
	var err error
	if out.ppid, err = parse(1, "ppid"); err != nil {
		return out, err
	}
	if out.utime, err = parse(11, "utime"); err != nil {
		return out, err
	}
	if out.stime, err = parse(12, "stime"); err != nil {
		return out, err
	}
	if out.threads, err = parse(17, "threads"); err != nil {
		return out, err
	}
	if out.startTicks, err = parse(19, "starttime"); err != nil {
		return out, err
	}
	if out.rssPages, err = parse(21, "rss"); err != nil {
		return out, err
	}
	return out, nil
}

func linuxClockTicks(ctx context.Context) (uint64, error) {
	path, err := exec.LookPath("getconf")
	if err != nil {
		return 0, err
	}
	cmd := exec.CommandContext(ctx, path, "CLK_TCK")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("getconf CLK_TCK: %w", err)
	}
	ticks, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || ticks == 0 {
		return 0, fmt.Errorf("invalid getconf CLK_TCK result %q", strings.TrimSpace(string(output)))
	}
	return ticks, nil
}

func buildProcessMetrics(list []models.ProcessSummary, totalThreads int, cpuTimeAvailable bool) *models.ProcessMetrics {
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

	topCPU := make([]models.ProcessSummary, 0)
	if cpuTimeAvailable {
		cpuList := make([]models.ProcessSummary, len(list))
		copy(cpuList, list)
		sort.Slice(cpuList, func(i, j int) bool {
			return cpuList[i].CPUTimeSeconds > cpuList[j].CPUTimeSeconds
		})
		topCPUCount := 5
		if len(cpuList) < topCPUCount {
			topCPUCount = len(cpuList)
		}
		topCPU = cpuList[:topCPUCount]
	}

	return &models.ProcessMetrics{
		TotalProcesses: totalProcs,
		TotalThreads:   totalThreads,
		TopCPU:         topCPU,
		TopMemory:      memList[:topMemCount],
	}
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
		return time.Time{}
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return time.Time{}
	}

	uptimeFloat, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}
	}

	return time.Now().Add(-time.Duration(uptimeFloat * float64(time.Second))).UTC().Truncate(time.Second)
}
