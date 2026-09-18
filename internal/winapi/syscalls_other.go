//go:build !windows
// +build !windows

package winapi

import (
	"context"
	"errors"
	"time"

	"github.com/systemdiag/sysdiag/internal/models"
)

type MemoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type OSVersionInfoExW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CSDVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       byte
	Reserved          byte
}

type SystemInfo struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

func GetUptime() time.Duration {
	return 0
}

func GetMemoryStatus() (*MemoryStatusEx, error) {
	return nil, errors.New("winapi: not supported on this platform")
}

func GetOSVersion() (*OSVersionInfoExW, error) {
	return nil, errors.New("winapi: not supported on this platform")
}

func ReadSystemTimes() (idle, kernel, user uint64, err error) {
	return 0, 0, 0, errors.New("winapi: not supported on this platform")
}

func GetSystemNativeInfo() SystemInfo {
	return SystemInfo{}
}

func IsProcessElevated() (bool, error) {
	return false, nil
}

type VolumeInfo struct {
	MountPoint   string
	VolumeName   string
	FileSystem   string
	DriveType    string
	TotalBytes   uint64
	FreeBytes    uint64
	UsedBytes    uint64
	UsedPercent  float64
	SerialNumber uint32
}

type PhysicalDiskInfo struct {
	DeviceID     string
	Model        string
	MediaType    string
	BusType      string
	SizeBytes    uint64
	SerialNumber string
}

func GetVolumes() ([]VolumeInfo, error) {
	return nil, errors.New("winapi: not supported on this platform")
}

func GetPhysicalDisks() ([]PhysicalDiskInfo, error) {
	return nil, errors.New("winapi: not supported on this platform")
}

type AdapterInfo struct {
	ID            string
	Name          string
	Description   string
	MACAddress    string
	Status        string
	IfType        string
	SpeedMbps     *uint64
	IPv4Addresses []string
	IPv6Addresses []string
	Gateways      []string
	DNSServers    []string
	DHCPEnabled   bool
	InOctets      uint64
	OutOctets     uint64
	InErrors      uint64
	OutErrors     uint64
	InDiscards    uint64
	OutDiscards   uint64
}

func GetNetworkAdapters() ([]AdapterInfo, error) {
	return nil, errors.New("winapi: not supported on this platform")
}

type ProcessDetail struct {
	PID             uint32
	PPID            uint32
	Name            string
	ExecutablePath  string
	ThreadCount     uint32
	WorkingSetBytes uint64
	PrivateBytes    uint64
	CPUTimeSeconds  float64
	CreationTime    time.Time
}

func GetProcesses() ([]ProcessDetail, error) {
	return nil, errors.New("winapi: not supported on this platform")
}

func GetServices() ([]models.ServiceInfo, error) {
	return nil, errors.New("winapi: not supported on this platform")
}

func GetReliabilityEvents(ctx context.Context, timeWindowHours int, maxRecords int) (*models.ReliabilityMetrics, error) {
	return nil, errors.New("winapi: not supported on this platform")
}

func GetSoftwareInventory() (*models.SoftwareMetrics, error) {
	return nil, errors.New("winapi: not supported on this platform")
}

func IsLaunchedFromExplorer() bool {
	return false
}
