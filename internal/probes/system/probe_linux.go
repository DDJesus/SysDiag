//go:build linux
// +build linux

package system

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "UNKNOWN-HOST"
	}

	uptimeSec, bootTime := readLinuxUptime()
	osName, osVersion, osBuild := readLinuxOSInfo()
	virtInfo := detectLinuxVirtualization()

	metrics := &models.SystemMetrics{
		Hostname:       hostname,
		OSName:         osName,
		OSVersion:      osVersion,
		OSBuild:        osBuild,
		Architecture:   runtime.GOARCH,
		UptimeSeconds:  uptimeSec,
		BootTime:       bootTime,
		Virtualization: virtInfo,
	}

	return metrics, collector.StatusSuccess, nil
}

func readLinuxUptime() (uint64, time.Time) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, time.Now().UTC()
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, time.Now().UTC()
	}

	uptimeFloat, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, time.Now().UTC()
	}

	uptimeSec := uint64(uptimeFloat)
	bootTime := time.Now().Add(-time.Duration(uptimeFloat * float64(time.Second))).UTC().Truncate(time.Second)
	return uptimeSec, bootTime
}

func readLinuxOSInfo() (osName, osVersion, osBuild string) {
	osName = "Linux"
	osBuild = "Unknown"

	// Read kernel release for osBuild
	if krel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		osBuild = strings.TrimSpace(string(krel))
	}

	// Read /etc/os-release or /usr/lib/os-release
	paths := []string{"/etc/os-release", "/usr/lib/os-release"}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		props := make(map[string]string)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				props[key] = val
			}
		}

		if pretty, ok := props["PRETTY_NAME"]; ok && pretty != "" {
			osName = pretty
		} else if name, ok := props["NAME"]; ok && name != "" {
			osName = name
		}

		if verID, ok := props["VERSION_ID"]; ok && verID != "" {
			osVersion = verID
		} else if ver, ok := props["VERSION"]; ok && ver != "" {
			osVersion = ver
		}

		break
	}

	return osName, osVersion, osBuild
}

func detectLinuxVirtualization() models.VirtualizationInfo {
	// 1. Container checks
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "Docker"}
	}
	if _, err := os.Stat("/run/systemd/container"); err == nil {
		if ctype, err := os.ReadFile("/run/systemd/container"); err == nil {
			return models.VirtualizationInfo{IsVirtual: true, Hypervisor: strings.TrimSpace(string(ctype))}
		}
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "Container"}
	}

	// 2. DMI System Vendor & Product checks
	sysVendor, _ := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	prodName, _ := os.ReadFile("/sys/class/dmi/id/product_name")
	biosVendor, _ := os.ReadFile("/sys/class/dmi/id/bios_vendor")

	combined := strings.ToLower(string(sysVendor) + " " + string(prodName) + " " + string(biosVendor))

	if strings.Contains(combined, "qemu") || strings.Contains(combined, "kvm") || strings.Contains(combined, "bochs") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "KVM/QEMU"}
	}
	if strings.Contains(combined, "vmware") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "VMware"}
	}
	if strings.Contains(combined, "microsoft") && strings.Contains(combined, "virtual") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "Hyper-V"}
	}
	if strings.Contains(combined, "innotek") || strings.Contains(combined, "virtualbox") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "VirtualBox"}
	}
	if strings.Contains(combined, "xen") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "Xen"}
	}
	if strings.Contains(combined, "amazon ec2") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "AWS Nitro/Xen"}
	}
	if strings.Contains(combined, "google") {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: "Google Compute Engine"}
	}

	// 3. /sys/hypervisor/type check
	if hypType, err := os.ReadFile("/sys/hypervisor/type"); err == nil && len(hypType) > 0 {
		return models.VirtualizationInfo{IsVirtual: true, Hypervisor: strings.TrimSpace(string(hypType))}
	}

	return models.VirtualizationInfo{IsVirtual: false}
}
