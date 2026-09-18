//go:build linux
// +build linux

package cpu

import (
	"bufio"
	"context"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

type cpuStat struct {
	user    uint64
	nice    uint64
	system  uint64
	idle    uint64
	iowait  uint64
	irq     uint64
	softirq uint64
	steal   uint64
}

func (p *Probe) collect(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	if sampleDuration <= 0 {
		sampleDuration = 300 * time.Millisecond
	}

	model, physicalCores := readLinuxCPUInfo()
	logicalCores := runtime.NumCPU()
	if physicalCores <= 0 {
		physicalCores = logicalCores
	}

	load1, load5, load15 := readLinuxLoadAvg()

	stat1, err := readLinuxCPUStat()
	if err != nil {
		return &models.CPUMetrics{
			Model:         model,
			PhysicalCores: physicalCores,
			LogicalCores:  logicalCores,
			Load1:         load1,
			Load5:         load5,
			Load15:        load15,
		}, collector.StatusPartial, err
	}

	select {
	case <-time.After(sampleDuration):
	case <-ctx.Done():
		return nil, collector.StatusTimeout, ctx.Err()
	}

	stat2, err := readLinuxCPUStat()
	if err != nil {
		return &models.CPUMetrics{
			Model:         model,
			PhysicalCores: physicalCores,
			LogicalCores:  logicalCores,
			Load1:         load1,
			Load5:         load5,
			Load15:        load15,
		}, collector.StatusPartial, err
	}

	total1 := stat1.user + stat1.nice + stat1.system + stat1.idle + stat1.iowait + stat1.irq + stat1.softirq + stat1.steal
	total2 := stat2.user + stat2.nice + stat2.system + stat2.idle + stat2.iowait + stat2.irq + stat2.softirq + stat2.steal

	deltaTotal := float64(total2 - total1)
	var utilPercent, userPercent, kernelPercent, iowaitPercent, stealPercent float64

	if deltaTotal > 0 {
		deltaUser := float64((stat2.user + stat2.nice) - (stat1.user + stat1.nice))
		deltaKernel := float64((stat2.system + stat2.irq + stat2.softirq) - (stat1.system + stat1.irq + stat1.softirq))
		deltaIdle := float64(stat2.idle - stat1.idle)
		deltaIOWait := float64(stat2.iowait - stat1.iowait)
		deltaSteal := float64(stat2.steal - stat1.steal)

		busyDelta := deltaTotal - deltaIdle - deltaIOWait
		if busyDelta < 0 {
			busyDelta = 0
		}

		utilPercent = (busyDelta / deltaTotal) * 100.0
		userPercent = (deltaUser / deltaTotal) * 100.0
		kernelPercent = (deltaKernel / deltaTotal) * 100.0
		iowaitPercent = (deltaIOWait / deltaTotal) * 100.0
		stealPercent = (deltaSteal / deltaTotal) * 100.0
	}

	metrics := &models.CPUMetrics{
		Model:              model,
		PhysicalCores:      physicalCores,
		LogicalCores:       logicalCores,
		UtilizationPercent: math.Round(utilPercent*10) / 10,
		UserPercent:        math.Round(userPercent*10) / 10,
		KernelPercent:      math.Round(kernelPercent*10) / 10,
		IOWaitPercent:      math.Round(iowaitPercent*10) / 10,
		StealPercent:       math.Round(stealPercent*10) / 10,
		Load1:              load1,
		Load5:              load5,
		Load15:             load15,
	}

	return metrics, collector.StatusSuccess, nil
}

func readLinuxCPUStat() (cpuStat, error) {
	var stat cpuStat
	f, err := os.Open("/proc/stat")
	if err != nil {
		return stat, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 8 {
				stat.user, _ = strconv.ParseUint(fields[1], 10, 64)
				stat.nice, _ = strconv.ParseUint(fields[2], 10, 64)
				stat.system, _ = strconv.ParseUint(fields[3], 10, 64)
				stat.idle, _ = strconv.ParseUint(fields[4], 10, 64)
				stat.iowait, _ = strconv.ParseUint(fields[5], 10, 64)
				stat.irq, _ = strconv.ParseUint(fields[6], 10, 64)
				stat.softirq, _ = strconv.ParseUint(fields[7], 10, 64)
			}
			if len(fields) >= 9 {
				stat.steal, _ = strconv.ParseUint(fields[8], 10, 64)
			}
			return stat, nil
		}
	}

	return stat, nil
}

func readLinuxCPUInfo() (model string, physicalCores int) {
	model = "Generic Linux CPU"
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return model, runtime.NumCPU()
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	coreKeys := make(map[string]bool)
	var currentPhysID string
	var currentCoreID string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Processor") || strings.HasPrefix(line, "Hardware") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && model == "Generic Linux CPU" {
				model = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "physical id") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentPhysID = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "core id") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentCoreID = strings.TrimSpace(parts[1])
			}
		}

		if currentPhysID != "" && currentCoreID != "" {
			coreKeys[currentPhysID+"-"+currentCoreID] = true
			currentPhysID = ""
			currentCoreID = ""
		}
	}

	if len(coreKeys) > 0 {
		physicalCores = len(coreKeys)
	} else {
		physicalCores = runtime.NumCPU()
	}

	return model, physicalCores
}

func readLinuxLoadAvg() (*float64, *float64, *float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil, nil, nil
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil, nil, nil
	}

	l1, err1 := strconv.ParseFloat(fields[0], 64)
	l5, err2 := strconv.ParseFloat(fields[1], 64)
	l15, err3 := strconv.ParseFloat(fields[2], 64)

	if err1 != nil || err2 != nil || err3 != nil {
		return nil, nil, nil
	}

	return &l1, &l5, &l15
}
