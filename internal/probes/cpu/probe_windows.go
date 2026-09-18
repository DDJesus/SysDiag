//go:build windows
// +build windows

package cpu

import (
	"context"
	"math"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func (p *Probe) collect(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	if sampleDuration <= 0 {
		sampleDuration = 300 * time.Millisecond
	}

	model := readCPUModel()
	logicalCores := runtime.NumCPU()
	physicalCores := readPhysicalCores(logicalCores)

	// Measure CPU utilization over sample duration
	idle1, kernel1, user1, err := winapi.ReadSystemTimes()
	if err != nil {
		return &models.CPUMetrics{
			Model:         model,
			PhysicalCores: physicalCores,
			LogicalCores:  logicalCores,
		}, collector.StatusPartial, err
	}

	select {
	case <-time.After(sampleDuration):
	case <-ctx.Done():
		return nil, collector.StatusTimeout, ctx.Err()
	}

	idle2, kernel2, user2, err := winapi.ReadSystemTimes()
	if err != nil {
		return &models.CPUMetrics{
			Model:         model,
			PhysicalCores: physicalCores,
			LogicalCores:  logicalCores,
		}, collector.StatusPartial, err
	}

	deltaIdle := float64(idle2 - idle1)
	deltaKernel := float64(kernel2 - kernel1)
	deltaUser := float64(user2 - user1)
	deltaTotal := deltaKernel + deltaUser

	var utilPercent, userPercent, kernelPercent float64
	if deltaTotal > 0 {
		// In Windows, KernelTime includes IdleTime
		actualKernel := deltaKernel - deltaIdle
		if actualKernel < 0 {
			actualKernel = 0
		}
		totalBusy := deltaTotal - deltaIdle
		if totalBusy < 0 {
			totalBusy = 0
		}

		utilPercent = (totalBusy / deltaTotal) * 100.0
		userPercent = (deltaUser / deltaTotal) * 100.0
		kernelPercent = (actualKernel / deltaTotal) * 100.0
	}

	metrics := &models.CPUMetrics{
		Model:              model,
		PhysicalCores:      physicalCores,
		LogicalCores:       logicalCores,
		UtilizationPercent: math.Round(utilPercent*10) / 10,
		UserPercent:        math.Round(userPercent*10) / 10,
		KernelPercent:      math.Round(kernelPercent*10) / 10,
	}

	return metrics, collector.StatusSuccess, nil
}

func readCPUModel() string {
	var hKey syscall.Handle
	subKey, _ := syscall.UTF16PtrFromString(`HARDWARE\DESCRIPTION\System\CentralProcessor\0`)
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subKey, 0, syscall.KEY_READ, &hKey); err != nil {
		return "Unknown Processor"
	}
	defer syscall.RegCloseKey(hKey)

	valPtr, _ := syscall.UTF16PtrFromString("ProcessorNameString")
	var valType uint32
	var bufSize uint32
	if err := syscall.RegQueryValueEx(hKey, valPtr, nil, &valType, nil, &bufSize); err != nil || bufSize == 0 {
		return "Unknown Processor"
	}

	buf := make([]uint16, bufSize/2+1)
	if err := syscall.RegQueryValueEx(hKey, valPtr, nil, &valType, (*byte)(unsafe.Pointer(&buf[0])), &bufSize); err != nil {
		return "Unknown Processor"
	}

	name := strings.TrimSpace(syscall.UTF16ToString(buf))
	if name == "" {
		return "Generic CPU"
	}
	return name
}

func readPhysicalCores(logical int) int {
	// Approximation if logical processors are known
	if logical <= 1 {
		return 1
	}
	// On many systems with hyperthreading, physical cores = logical / 2
	// But let's check basic system info
	si := winapi.GetSystemNativeInfo()
	if si.NumberOfProcessors > 0 && int(si.NumberOfProcessors) <= logical {
		// Minimum plausible physical count
		if logical >= 2 {
			return logical / 2
		}
		return int(si.NumberOfProcessors)
	}
	return logical
}
