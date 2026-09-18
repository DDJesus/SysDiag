//go:build windows
// +build windows

package system

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "UNKNOWN-HOST"
	}

	uptimeDur := winapi.GetUptime()
	bootTime := time.Now().Add(-uptimeDur).UTC().Truncate(time.Second)

	osName := "Microsoft Windows"
	osBuild := "Unknown"
	osVersion := ""

	if vi, err := winapi.GetOSVersion(); err == nil {
		osBuild = fmt.Sprintf("%d.%d.%d", vi.MajorVersion, vi.MinorVersion, vi.BuildNumber)
		if vi.BuildNumber >= 22000 {
			osName = "Microsoft Windows 11"
		} else if vi.MajorVersion == 10 {
			osName = "Microsoft Windows 10"
		} else if vi.MajorVersion == 6 && vi.MinorVersion == 3 {
			osName = "Microsoft Windows 8.1"
		} else if vi.MajorVersion == 6 && vi.MinorVersion == 1 {
			osName = "Microsoft Windows 7"
		}
	}

	// Read detailed OS Product Name from registry if accessible
	if regProdName, regDisplayVer := readOSRegistry(); regProdName != "" {
		osName = regProdName
		if regDisplayVer != "" {
			osVersion = regDisplayVer
		}
	}

	// Detect hypervisor/virtualization from BIOS registry
	virtInfo := detectVirtualization()

	metrics := &models.SystemMetrics{
		Hostname:       hostname,
		OSName:         osName,
		OSVersion:      osVersion,
		OSBuild:        osBuild,
		Architecture:   runtime.GOARCH,
		UptimeSeconds:  uint64(uptimeDur.Seconds()),
		BootTime:       bootTime,
		Virtualization: virtInfo,
	}

	return metrics, collector.StatusSuccess, nil
}

func readOSRegistry() (productName string, displayVersion string) {
	var hKey syscall.Handle
	subKey, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subKey, 0, syscall.KEY_READ, &hKey); err != nil {
		return "", ""
	}
	defer syscall.RegCloseKey(hKey)

	productName = regQueryString(hKey, "ProductName")
	displayVersion = regQueryString(hKey, "DisplayVersion")
	if displayVersion == "" {
		displayVersion = regQueryString(hKey, "ReleaseId")
	}
	return productName, displayVersion
}

func detectVirtualization() models.VirtualizationInfo {
	var hKey syscall.Handle
	subKey, _ := syscall.UTF16PtrFromString(`HARDWARE\DESCRIPTION\System\BIOS`)
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subKey, 0, syscall.KEY_READ, &hKey); err != nil {
		return models.VirtualizationInfo{IsVirtual: false}
	}
	defer syscall.RegCloseKey(hKey)

	manufacturer := strings.ToLower(regQueryString(hKey, "SystemManufacturer"))
	product := strings.ToLower(regQueryString(hKey, "SystemProductName"))
	biosVendor := strings.ToLower(regQueryString(hKey, "BIOSVendor"))

	combined := manufacturer + " " + product + " " + biosVendor

	if strings.Contains(combined, "vmware") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "VMware"}
	}
	if strings.Contains(combined, "hyper-v") || strings.Contains(combined, "microsoft corporation") && strings.Contains(product, "virtual") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "Hyper-V"}
	}
	if strings.Contains(combined, "qemu") || strings.Contains(combined, "kvm") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "KVM/QEMU"}
	}
	if strings.Contains(combined, "virtualbox") || strings.Contains(combined, "innotek") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "VirtualBox"}
	}
	if strings.Contains(combined, "xen") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "Xen"}
	}
	if strings.Contains(combined, "amazon ec2") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "AWS Nitro/Xen"}
	}

	return models.VirtualizationInfo{IsVirtual: false}
}

func regQueryString(hKey syscall.Handle, valueName string) string {
	valPtr, _ := syscall.UTF16PtrFromString(valueName)
	var valType uint32
	var bufSize uint32
	if err := syscall.RegQueryValueEx(hKey, valPtr, nil, &valType, nil, &bufSize); err != nil || bufSize == 0 {
		return ""
	}

	buf := make([]uint16, bufSize/2+1)
	if err := syscall.RegQueryValueEx(hKey, valPtr, nil, &valType, (*byte)(unsafe.Pointer(&buf[0])), &bufSize); err != nil {
		return ""
	}

	return syscall.UTF16ToString(buf)
}
