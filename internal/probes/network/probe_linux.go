//go:build linux
// +build linux

package network

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, collector.StatusFailed, err
	}

	gateways := readLinuxDefaultGateways()
	dnsServers := readLinuxDNSServers()

	var adapterMetrics []models.NetworkAdapterMetrics

	for _, iface := range ifaces {
		status := "Down"
		if iface.Flags&net.FlagUp != 0 {
			status = "Up"
		}

		ifType := "Ethernet"
		if iface.Flags&net.FlagLoopback != 0 {
			ifType = "Loopback"
		} else if isWireless(iface.Name) {
			ifType = "Wi-Fi"
		}

		var ipv4List, ipv6List []string
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				ipv4List = append(ipv4List, ip.String())
			} else {
				ipv6List = append(ipv6List, ip.String())
			}
		}

		stats := readLinuxInterfaceStats(iface.Name)
		var speedPtr *uint64
		if speed := readLinuxInterfaceSpeed(iface.Name); speed > 0 {
			speedPtr = &speed
		}

		var ifGateways []string
		if gw, ok := gateways[iface.Name]; ok && gw != "" {
			ifGateways = append(ifGateways, gw)
		}

		adapterMetrics = append(adapterMetrics, models.NetworkAdapterMetrics{
			ID:            iface.Name,
			Name:          iface.Name,
			Description:   fmt.Sprintf("%s (%s)", iface.Name, ifType),
			MACAddress:    iface.HardwareAddr.String(),
			Status:        status,
			IfType:        ifType,
			SpeedMbps:     speedPtr,
			IPv4Addresses: ipv4List,
			IPv6Addresses: ipv6List,
			Gateways:      ifGateways,
			DNSServers:    dnsServers,
			InOctets:      stats.rxBytes,
			OutOctets:     stats.txBytes,
			InErrors:      stats.rxErrors,
			OutErrors:     stats.txErrors,
			InDiscards:    stats.rxDropped,
			OutDiscards:   stats.txDropped,
		})
	}

	dnsTest := runDNSTest(ctx)

	metrics := &models.NetworkMetrics{
		Adapters: adapterMetrics,
		DNSTest:  dnsTest,
	}

	return metrics, collector.StatusSuccess, nil
}

type ifaceStats struct {
	rxBytes   uint64
	txBytes   uint64
	rxErrors  uint64
	txErrors  uint64
	rxDropped uint64
	txDropped uint64
}

func readLinuxInterfaceStats(ifaceName string) ifaceStats {
	var stats ifaceStats
	statDir := filepath.Join("/sys/class/net", ifaceName, "statistics")

	stats.rxBytes = readUint64File(filepath.Join(statDir, "rx_bytes"))
	stats.txBytes = readUint64File(filepath.Join(statDir, "tx_bytes"))
	stats.rxErrors = readUint64File(filepath.Join(statDir, "rx_errors"))
	stats.txErrors = readUint64File(filepath.Join(statDir, "tx_errors"))
	stats.rxDropped = readUint64File(filepath.Join(statDir, "rx_dropped"))
	stats.txDropped = readUint64File(filepath.Join(statDir, "tx_dropped"))

	return stats
}

func readLinuxInterfaceSpeed(ifaceName string) uint64 {
	speedPath := filepath.Join("/sys/class/net", ifaceName, "speed")
	speedVal := readUint64File(speedPath)
	return speedVal
}

func isWireless(ifaceName string) bool {
	if strings.HasPrefix(ifaceName, "wl") {
		return true
	}
	wirelessDir := filepath.Join("/sys/class/net", ifaceName, "wireless")
	if _, err := os.Stat(wirelessDir); err == nil {
		return true
	}
	return false
}

func readUint64File(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return val
}

func readLinuxDefaultGateways() map[string]string {
	gwMap := make(map[string]string)
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return gwMap
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			iface := fields[0]
			dest := fields[1]
			gwHex := fields[2]

			// Default route has destination 00000000
			if dest == "00000000" && gwHex != "00000000" && len(gwHex) == 8 {
				if ipBytes, err := hex.DecodeString(gwHex); err == nil && len(ipBytes) == 4 {
					// Little-endian IPv4 in /proc/net/route
					gwIP := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]).String()
					gwMap[iface] = gwIP
				}
			}
		}
	}

	return gwMap
}

func readLinuxDNSServers() []string {
	var dnsList []string
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return dnsList
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				dnsList = append(dnsList, fields[1])
			}
		}
	}

	return dnsList
}

func runDNSTest(parentCtx context.Context) *models.DNSResolutionTest {
	target := "localhost"
	if h, err := os.Hostname(); err == nil && h != "" {
		target = h
	}

	dnsCtx, cancel := context.WithTimeout(parentCtx, 1500*time.Millisecond)
	defer cancel()

	start := time.Now()
	ips, err := net.DefaultResolver.LookupIPAddr(dnsCtx, target)
	duration := float64(time.Since(start).Microseconds()) / 1000.0

	testResult := &models.DNSResolutionTest{
		QueryTarget: target,
		DurationMS:  duration,
	}

	if err != nil {
		testResult.Success = false
		testResult.Error = err.Error()
	} else {
		testResult.Success = true
		for _, ip := range ips {
			testResult.ResolvedIPs = append(testResult.ResolvedIPs, ip.String())
		}
	}

	return testResult
}
