//go:build windows
// +build windows

package winapi

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/systemdiag/sysdiag/internal/models"
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modNtdll    = syscall.NewLazyDLL("ntdll.dll")
	modAdvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modIphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	modWevtapi  = syscall.NewLazyDLL("wevtapi.dll")

	procGetTickCount64             = modKernel32.NewProc("GetTickCount64")
	procGetSystemTimes             = modKernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx       = modKernel32.NewProc("GlobalMemoryStatusEx")
	procGetNativeSystemInfo        = modKernel32.NewProc("GetNativeSystemInfo")
	procGetLogicalDriveStringsW    = modKernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW              = modKernel32.NewProc("GetDriveTypeW")
	procGetVolumeInformationW      = modKernel32.NewProc("GetVolumeInformationW")
	procGetDiskFreeSpaceExW        = modKernel32.NewProc("GetDiskFreeSpaceExW")
	procCreateFileW                = modKernel32.NewProc("CreateFileW")
	procDeviceIoControl            = modKernel32.NewProc("DeviceIoControl")
	procCreateToolhelp32Snapshot   = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW            = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW             = modKernel32.NewProc("Process32NextW")
	procOpenProcess                = modKernel32.NewProc("OpenProcess")
	procGetProcessTimes            = modKernel32.NewProc("GetProcessTimes")
	procK32GetProcessMemoryInfo    = modKernel32.NewProc("K32GetProcessMemoryInfo")
	procQueryFullProcessImageNameW = modKernel32.NewProc("QueryFullProcessImageNameW")
	procRtlGetVersion              = modNtdll.NewProc("RtlGetVersion")
	procOpenProcessToken           = modAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation        = modAdvapi32.NewProc("GetTokenInformation")
	procGetAdaptersAddresses       = modIphlpapi.NewProc("GetAdaptersAddresses")
	procGetIfEntry2                = modIphlpapi.NewProc("GetIfEntry2")

	procOpenSCManagerW        = modAdvapi32.NewProc("OpenSCManagerW")
	procEnumServicesStatusExW = modAdvapi32.NewProc("EnumServicesStatusExW")
	procCloseServiceHandle    = modAdvapi32.NewProc("CloseServiceHandle")
	procRegEnumKeyExW         = modAdvapi32.NewProc("RegEnumKeyExW")

	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
)

// MemoryStatusEx corresponds to Win32 MEMORYSTATUSEX.
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

// OSVersionInfoExW corresponds to Win32 OSVERSIONINFOEXW.
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

// SystemTimes contains raw system idle, kernel, and user file times.
type SystemTimes struct {
	IdleTime   syscall.Filetime
	KernelTime syscall.Filetime
	UserTime   syscall.Filetime
}

// SystemInfo corresponds to Win32 SYSTEM_INFO.
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

// GetUptime returns the system uptime duration based on GetTickCount64.
func GetUptime() time.Duration {
	ret, _, _ := procGetTickCount64.Call()
	return time.Duration(ret) * time.Millisecond
}

// GetMemoryStatus calls GlobalMemoryStatusEx to get physical and commit metrics.
func GetMemoryStatus() (*MemoryStatusEx, error) {
	var status MemoryStatusEx
	status.Length = uint32(unsafe.Sizeof(status))
	ret, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if ret == 0 {
		return nil, fmt.Errorf("GlobalMemoryStatusEx failed: %w", err)
	}
	return &status, nil
}

// GetOSVersion calls RtlGetVersion to bypass application manifest version lie.
func GetOSVersion() (*OSVersionInfoExW, error) {
	var vi OSVersionInfoExW
	vi.OSVersionInfoSize = uint32(unsafe.Sizeof(vi))
	ret, _, err := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&vi)))
	if ret != 0 {
		return nil, fmt.Errorf("RtlGetVersion failed with NTSTATUS: 0x%X (%v)", ret, err)
	}
	return &vi, nil
}

// ReadSystemTimes retrieves current system idle, kernel, and user times.
func ReadSystemTimes() (idle, kernel, user uint64, err error) {
	var st SystemTimes
	ret, _, callErr := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&st.IdleTime)),
		uintptr(unsafe.Pointer(&st.KernelTime)),
		uintptr(unsafe.Pointer(&st.UserTime)),
	)
	if ret == 0 {
		return 0, 0, 0, fmt.Errorf("GetSystemTimes failed: %w", callErr)
	}
	idle = (uint64(st.IdleTime.HighDateTime) << 32) | uint64(st.IdleTime.LowDateTime)
	kernel = (uint64(st.KernelTime.HighDateTime) << 32) | uint64(st.KernelTime.LowDateTime)
	user = (uint64(st.UserTime.HighDateTime) << 32) | uint64(st.UserTime.LowDateTime)
	return idle, kernel, user, nil
}

// GetSystemNativeInfo returns processor count and architecture details.
func GetSystemNativeInfo() SystemInfo {
	var si SystemInfo
	procGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(&si)))
	return si
}

// IsProcessElevated checks whether current process has Administrator token elevation.
func IsProcessElevated() (bool, error) {
	var token syscall.Token
	currentProcess, err := syscall.GetCurrentProcess()
	if err != nil {
		return false, err
	}

	const TOKEN_QUERY = 0x0008
	ret, _, err := procOpenProcessToken.Call(
		uintptr(currentProcess),
		uintptr(TOKEN_QUERY),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return false, fmt.Errorf("OpenProcessToken failed: %w", err)
	}
	defer token.Close()

	type tokenElevation struct {
		TokenIsElevated uint32
	}
	var elev tokenElevation
	var returnLength uint32
	const TokenElevationClass = 20

	ret, _, err = procGetTokenInformation.Call(
		uintptr(token),
		uintptr(TokenElevationClass),
		uintptr(unsafe.Pointer(&elev)),
		uintptr(unsafe.Sizeof(elev)),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	if ret == 0 {
		return false, fmt.Errorf("GetTokenInformation failed: %w", err)
	}

	return elev.TokenIsElevated != 0, nil
}

// DriveType constants
const (
	DriveUnknown     = 0
	DriveNoRootDir   = 1
	DriveRemovable   = 2
	DriveFixed       = 3
	DriveRemote      = 4
	DriveCDROM       = 5
	DriveRAMDisk     = 6
)

// VolumeInfo describes logical storage volume metrics.
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

// PhysicalDiskInfo describes physical storage drive properties.
type PhysicalDiskInfo struct {
	DeviceID     string
	Model        string
	MediaType    string
	BusType      string
	SizeBytes    uint64
	SerialNumber string
}

// GetVolumes enumerates all logical drives and their capacity metrics.
func GetVolumes() ([]VolumeInfo, error) {
	buf := make([]uint16, 512)
	ret, _, err := procGetLogicalDriveStringsW.Call(uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	if ret == 0 {
		return nil, fmt.Errorf("GetLogicalDriveStringsW failed: %w", err)
	}

	var volumes []VolumeInfo
	start := 0
	for i := 0; i < int(ret); i++ {
		if buf[i] == 0 {
			if i > start {
				drive := syscall.UTF16ToString(buf[start:i])
				vol, ok := queryVolume(drive)
				if ok {
					volumes = append(volumes, vol)
				}
			}
			start = i + 1
		}
	}
	return volumes, nil
}

func queryVolume(drive string) (VolumeInfo, bool) {
	drivePtr, err := syscall.UTF16PtrFromString(drive)
	if err != nil {
		return VolumeInfo{}, false
	}

	dtRet, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(drivePtr)))
	dt := uint32(dtRet)
	if dt == DriveNoRootDir {
		return VolumeInfo{}, false
	}

	driveTypeStr := "Unknown"
	switch dt {
	case DriveRemovable:
		driveTypeStr = "Removable"
	case DriveFixed:
		driveTypeStr = "Fixed"
	case DriveRemote:
		driveTypeStr = "Network"
	case DriveCDROM:
		driveTypeStr = "CD-ROM"
	case DriveRAMDisk:
		driveTypeStr = "RAMDisk"
	}

	volNameBuf := make([]uint16, 260)
	fsNameBuf := make([]uint16, 260)
	var serialNum, maxCompLen, fsFlags uint32

	procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(drivePtr)),
		uintptr(unsafe.Pointer(&volNameBuf[0])),
		uintptr(len(volNameBuf)),
		uintptr(unsafe.Pointer(&serialNum)),
		uintptr(unsafe.Pointer(&maxCompLen)),
		uintptr(unsafe.Pointer(&fsFlags)),
		uintptr(unsafe.Pointer(&fsNameBuf[0])),
		uintptr(len(fsNameBuf)),
	)

	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	ret, _, _ := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(drivePtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)

	if ret == 0 && dt == DriveCDROM {
		// CD-ROM without media inserted
		return VolumeInfo{
			MountPoint: drive,
			DriveType:  driveTypeStr,
		}, true
	}

	usedBytes := uint64(0)
	usedPercent := 0.0
	if totalBytes > 0 {
		if totalBytes >= totalFreeBytes {
			usedBytes = totalBytes - totalFreeBytes
		}
		usedPercent = float64(usedBytes) / float64(totalBytes) * 100.0
	}

	return VolumeInfo{
		MountPoint:   drive,
		VolumeName:   syscall.UTF16ToString(volNameBuf),
		FileSystem:   syscall.UTF16ToString(fsNameBuf),
		DriveType:    driveTypeStr,
		TotalBytes:   totalBytes,
		FreeBytes:    totalFreeBytes,
		UsedBytes:    usedBytes,
		UsedPercent:  usedPercent,
		SerialNumber: serialNum,
	}, true
}

// Storage property query structures
const (
	IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
	StorageDeviceProperty        = 0
	PropertyStandardQuery        = 0
	FILE_SHARE_READ              = 0x00000001
	FILE_SHARE_WRITE             = 0x00000002
	OPEN_EXISTING                = 3
)

type StoragePropertyQuery struct {
	PropertyID           uint32
	QueryType            uint32
	AdditionalParameters [1]byte
}

type StorageDeviceDescriptor struct {
	Version               uint32
	Size                  uint32
	DeviceType            byte
	DeviceTypeModifier    byte
	RemovableMedia        byte
	CommandQueueing       byte
	VendorIDOffset        uint32
	ProductIDOffset       uint32
	ProductRevisionOffset uint32
	SerialNumberOffset    uint32
	BusType               uint32
	RawPropertiesLength   uint32
	RawDeviceProperties   [512]byte
}

// GetPhysicalDisks queries attached physical drives (PhysicalDrive0..N).
func GetPhysicalDisks() ([]PhysicalDiskInfo, error) {
	var disks []PhysicalDiskInfo

	for i := 0; i < 16; i++ {
		devPath := fmt.Sprintf(`\\.\PhysicalDrive%d`, i)
		pathPtr, err := syscall.UTF16PtrFromString(devPath)
		if err != nil {
			continue
		}

		handle, _, _ := procCreateFileW.Call(
			uintptr(unsafe.Pointer(pathPtr)),
			0, // query access without read/write
			FILE_SHARE_READ|FILE_SHARE_WRITE,
			0,
			OPEN_EXISTING,
			0,
			0,
		)

		if syscall.Handle(handle) == syscall.InvalidHandle {
			continue
		}

		disk := queryPhysicalDisk(syscall.Handle(handle), devPath)
		syscall.CloseHandle(syscall.Handle(handle))
		disks = append(disks, disk)
	}

	return disks, nil
}

func queryPhysicalDisk(h syscall.Handle, devID string) PhysicalDiskInfo {
	query := StoragePropertyQuery{
		PropertyID: StorageDeviceProperty,
		QueryType:  PropertyStandardQuery,
	}

	var desc StorageDeviceDescriptor
	var bytesReturned uint32

	ret, _, _ := procDeviceIoControl.Call(
		uintptr(h),
		IOCTL_STORAGE_QUERY_PROPERTY,
		uintptr(unsafe.Pointer(&query)),
		uintptr(unsafe.Sizeof(query)),
		uintptr(unsafe.Pointer(&desc)),
		uintptr(unsafe.Sizeof(desc)),
		uintptr(unsafe.Pointer(&bytesReturned)),
		0,
	)

	info := PhysicalDiskInfo{
		DeviceID: devID,
	}

	if ret != 0 {
		raw := (*[1024]byte)(unsafe.Pointer(&desc))
		if desc.ProductIDOffset > 0 && desc.ProductIDOffset < bytesReturned {
			info.Model = readNullString(raw[desc.ProductIDOffset:bytesReturned])
		}
		if desc.VendorIDOffset > 0 && desc.VendorIDOffset < bytesReturned {
			vendor := readNullString(raw[desc.VendorIDOffset:bytesReturned])
			if vendor != "" {
				info.Model = fmt.Sprintf("%s %s", vendor, info.Model)
			}
		}
		if desc.SerialNumberOffset > 0 && desc.SerialNumberOffset < bytesReturned {
			info.SerialNumber = readNullString(raw[desc.SerialNumberOffset:bytesReturned])
		}

		info.BusType = mapBusType(desc.BusType)
		if desc.RemovableMedia != 0 {
			info.MediaType = "Removable"
		} else {
			info.MediaType = "Fixed Disk"
		}
	}

	return info
}

func readNullString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func mapBusType(bt uint32) string {
	switch bt {
	case 1:
		return "SCSI"
	case 2:
		return "ATAPI"
	case 3:
		return "ATA"
	case 4:
		return "1394"
	case 5:
		return "SSA"
	case 6:
		return "Fibre"
	case 7:
		return "USB"
	case 8:
		return "RAID"
	case 9:
		return "iSCSI"
	case 10:
		return "SAS"
	case 11:
		return "SATA"
	case 12:
		return "SD"
	case 13:
		return "MMC"
	case 17:
		return "NVMe"
	default:
		return "Unknown"
	}
}

// Network structs & API bindings
type IPAdapterAddresses struct {
	Length                uint32
	IfIndex               uint32
	Next                  *IPAdapterAddresses
	AdapterName           *byte
	FirstUnicastAddress   *IPAdapterUnicastAddress
	FirstAnycastAddress   uintptr
	FirstMulticastAddress uintptr
	FirstDnsServerAddress *IPAdapterDnsServerAddress
	DnsSuffix             *uint16
	Description           *uint16
	FriendlyName          *uint16
	PhysicalAddress       [8]byte
	PhysicalAddressLength uint32
	Flags                 uint32
	Mtu                   uint32
	IfType                uint32
	OperStatus            uint32
	Ipv6IfIndex           uint32
	ZoneIndices           [16]uint32
	FirstPrefix           uintptr
	TransmitLinkSpeed     uint64
	ReceiveLinkSpeed      uint64
	FirstWinsServerAddress uintptr
	FirstGatewayAddress   *IPAdapterGatewayAddress
	Ipv4Metric            uint32
	Ipv6Metric            uint32
	Luid                  uint64
}

type IPAdapterUnicastAddress struct {
	Length             uint32
	Flags              uint32
	Next               *IPAdapterUnicastAddress
	Address            SocketAddress
	PrefixOrigin       uint32
	SuffixOrigin       uint32
	DadState           uint32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	LeaseLifetime      uint32
	OnLinkPrefixLength uint8
}

type IPAdapterGatewayAddress struct {
	Length   uint32
	Reserved uint32
	Next     *IPAdapterGatewayAddress
	Address  SocketAddress
}

type IPAdapterDnsServerAddress struct {
	Length   uint32
	Reserved uint32
	Next     *IPAdapterDnsServerAddress
	Address  SocketAddress
}

type SocketAddress struct {
	Sockaddr       *syscall.RawSockaddrAny
	SockaddrLength int32
}

type MIB_IF_ROW2 struct {
	InterfaceLuid               uint64
	InterfaceIndex              uint32
	InterfaceGuid               syscall.GUID
	Alias                       [257]uint16
	Description                 [257]uint16
	PhysicalAddressLength       uint32
	PhysicalAddress             [32]byte
	PermanentPhysicalAddress    [32]byte
	Mtu                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags byte
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGuid                 syscall.GUID
	ConnectionType              uint32
	TransmitLinkSpeed           uint64
	ReceiveLinkSpeed            uint64
	InOctets                    uint64
	InUcastPkts                 uint64
	InNUcastPkts                uint64
	InDiscards                  uint64
	InErrors                    uint64
	InUnknownProtos             uint64
	InUcastOctets               uint64
	InMulticastOctets           uint64
	InBroadcastOctets           uint64
	OutOctets                   uint64
	OutUcastPkts                uint64
	OutNUcastPkts               uint64
	OutDiscards                 uint64
	OutErrors                   uint64
	OutUcastOctets              uint64
	OutMulticastOctets          uint64
	OutBroadcastOctets          uint64
	OutQLen                     uint64
}

// AdapterInfo encapsulates normalized network interface data.
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

// GetNetworkAdapters returns the list of active/configured network adapters.
func GetNetworkAdapters() ([]AdapterInfo, error) {
	const (
		AF_UNSPEC                 = 0
		GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
		GAA_FLAG_INCLUDE_PREFIXES = 0x0010
	)

	bufSize := uint32(15000)
	buf := make([]byte, bufSize)

	for attempts := 0; attempts < 3; attempts++ {
		ret, _, _ := procGetAdaptersAddresses.Call(
			uintptr(AF_UNSPEC),
			uintptr(GAA_FLAG_INCLUDE_GATEWAYS|GAA_FLAG_INCLUDE_PREFIXES),
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufSize)),
		)
		if ret == 0 { // ERROR_SUCCESS
			break
		}
		if ret == 111 { // ERROR_BUFFER_OVERFLOW
			buf = make([]byte, bufSize)
			continue
		}
		return nil, fmt.Errorf("GetAdaptersAddresses failed with code: %d", ret)
	}

	var adapters []AdapterInfo
	curr := (*IPAdapterAddresses)(unsafe.Pointer(&buf[0]))

	for curr != nil {
		info := AdapterInfo{}
		if curr.FriendlyName != nil {
			info.Name = syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(curr.FriendlyName))[:])
		}
		if curr.Description != nil {
			info.Description = syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(curr.Description))[:])
		}
		if curr.AdapterName != nil {
			info.ID = readNullString((*[256]byte)(unsafe.Pointer(curr.AdapterName))[:])
		}

		if curr.PhysicalAddressLength > 0 && curr.PhysicalAddressLength <= 8 {
			var macParts []string
			for i := 0; i < int(curr.PhysicalAddressLength); i++ {
				macParts = append(macParts, fmt.Sprintf("%02X", curr.PhysicalAddress[i]))
			}
			info.MACAddress = stringsJoin(macParts, ":")
		}

		// OperStatus: 1 = IfOperStatusUp, 2 = IfOperStatusDown
		switch curr.OperStatus {
		case 1:
			info.Status = "Up"
		case 2:
			info.Status = "Down"
		case 3:
			info.Status = "Testing"
		default:
			info.Status = "Unknown"
		}

		info.IfType = mapIfType(curr.IfType)
		info.SpeedMbps = parseLinkSpeed(curr.TransmitLinkSpeed, curr.OperStatus)

		const IP_ADAPTER_DHCP_ENABLED = 0x0004
		info.DHCPEnabled = (curr.Flags & IP_ADAPTER_DHCP_ENABLED) != 0

		// Extract Unicast addresses (IPv4 & IPv6)
		uAddr := curr.FirstUnicastAddress
		for uAddr != nil {
			ipStr := parseSockaddr(uAddr.Address.Sockaddr)
			if ipStr != "" {
				if isIPv4(ipStr) {
					info.IPv4Addresses = append(info.IPv4Addresses, ipStr)
				} else {
					info.IPv6Addresses = append(info.IPv6Addresses, ipStr)
				}
			}
			uAddr = uAddr.Next
		}

		// Extract Gateways
		gw := curr.FirstGatewayAddress
		for gw != nil {
			ipStr := parseSockaddr(gw.Address.Sockaddr)
			if ipStr != "" {
				info.Gateways = append(info.Gateways, ipStr)
			}
			gw = gw.Next
		}

		// Extract DNS Servers
		dns := curr.FirstDnsServerAddress
		for dns != nil {
			ipStr := parseSockaddr(dns.Address.Sockaddr)
			if ipStr != "" {
				info.DNSServers = append(info.DNSServers, ipStr)
			}
			dns = dns.Next
		}

		// Query Interface Statistics via GetIfEntry2
		var row MIB_IF_ROW2
		row.InterfaceLuid = curr.Luid
		row.InterfaceIndex = curr.IfIndex
		ifRet, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(&row)))
		if ifRet == 0 {
			info.InOctets = sanitizeCounter(row.InOctets)
			info.OutOctets = sanitizeCounter(row.OutOctets)
			info.InErrors = sanitizeCounter(row.InErrors)
			info.OutErrors = sanitizeCounter(row.OutErrors)
			info.InDiscards = sanitizeCounter(row.InDiscards)
			info.OutDiscards = sanitizeCounter(row.OutDiscards)

			// If link speed was missing or 0 from IP_ADAPTER_ADDRESSES, check MIB_IF_ROW2
			if info.SpeedMbps == nil {
				info.SpeedMbps = parseLinkSpeed(row.TransmitLinkSpeed, curr.OperStatus)
			}
		}

		adapters = append(adapters, info)
		curr = curr.Next
	}

	return adapters, nil
}

func mapIfType(t uint32) string {
	switch t {
	case 6:
		return "Ethernet"
	case 71:
		return "Wi-Fi"
	case 24:
		return "Loopback"
	case 23:
		return "PPP"
	case 131:
		return "Tunnel"
	default:
		return "Other"
	}
}

// parseLinkSpeed converts link speed in bits/sec to Mbps, guarding against sentinel / invalid / disconnected values.
func parseLinkSpeed(speedBps uint64, operStatus uint32) *uint64 {
	// If adapter is not Up (operStatus != 1), link speed is unavailable
	if operStatus != 1 {
		return nil
	}
	// NDIS_LINK_SPEED_UNKNOWN ((ULONG64)(-1) = 18446744073709551615), 0, 0xFFFFFFFF,
	// or unfeasibly large sentinel values (> 10 Tbps = 10_000_000_000_000 bps) are invalid sentinels.
	if speedBps == 0 || speedBps == ^uint64(0) || speedBps == 0xFFFFFFFF || speedBps > 10_000_000_000_000 {
		return nil
	}
	mbps := speedBps / 1000000
	return &mbps
}

// sanitizeCounter guards against Windows drivers returning sentinel values (^uint64(0) or 0xFFFFFFFF) for unsupported MIB stats.
func sanitizeCounter(val uint64) uint64 {
	if val == ^uint64(0) || val == 0xFFFFFFFF {
		return 0
	}
	return val
}

func parseSockaddr(sa *syscall.RawSockaddrAny) string {
	if sa == nil {
		return ""
	}
	const AF_INET = 2
	const AF_INET6 = 23

	if sa.Addr.Family == AF_INET {
		sa4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sa))
		return fmt.Sprintf("%d.%d.%d.%d", sa4.Addr[0], sa4.Addr[1], sa4.Addr[2], sa4.Addr[3])
	} else if sa.Addr.Family == AF_INET6 {
		sa6 := (*syscall.RawSockaddrInet6)(unsafe.Pointer(sa))
		// Format IPv6 representation
		var b [16]byte
		for i := 0; i < 16; i++ {
			b[i] = sa6.Addr[i]
		}
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			(uint16(b[0])<<8)|uint16(b[1]), (uint16(b[2])<<8)|uint16(b[3]),
			(uint16(b[4])<<8)|uint16(b[5]), (uint16(b[6])<<8)|uint16(b[7]),
			(uint16(b[8])<<8)|uint16(b[9]), (uint16(b[10])<<8)|uint16(b[11]),
			(uint16(b[12])<<8)|uint16(b[13]), (uint16(b[14])<<8)|uint16(b[15]))
	}
	return ""
}

func isIPv4(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

func stringsJoin(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	res := parts[0]
	for i := 1; i < len(parts); i++ {
		res += sep + parts[i]
	}
	return res
}

// Process enumeration structures
const (
	TH32CS_SNAPPROCESS               = 0x00000002
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
)

type ProcessEntry32W struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type ProcessMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

// ProcessDetail captures runtime resource telemetry of a process.
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

// GetProcesses enumerates running processes and samples CPU / memory telemetry.
func GetProcesses() ([]ProcessDetail, error) {
	snap, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if syscall.Handle(snap) == syscall.InvalidHandle {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var pe ProcessEntry32W
	pe.Size = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return nil, fmt.Errorf("Process32FirstW failed")
	}

	var procs []ProcessDetail
	for {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		detail := ProcessDetail{
			PID:         pe.ProcessID,
			PPID:        pe.ParentProcessID,
			Name:        name,
			ThreadCount: pe.Threads,
		}

		if pe.ProcessID > 0 {
			hProc, _, _ := procOpenProcess.Call(
				PROCESS_QUERY_LIMITED_INFORMATION,
				0,
				uintptr(pe.ProcessID),
			)

			if syscall.Handle(hProc) != syscall.InvalidHandle {
				var pmc ProcessMemoryCountersEx
				pmc.CB = uint32(unsafe.Sizeof(pmc))
				pmcRet, _, _ := procK32GetProcessMemoryInfo.Call(
					hProc,
					uintptr(unsafe.Pointer(&pmc)),
					uintptr(pmc.CB),
				)
				if pmcRet != 0 {
					detail.WorkingSetBytes = uint64(pmc.WorkingSetSize)
					detail.PrivateBytes = uint64(pmc.PrivateUsage)
				}

				var createTime, exitTime, kernelTime, userTime syscall.Filetime
				ptRet, _, _ := procGetProcessTimes.Call(
					hProc,
					uintptr(unsafe.Pointer(&createTime)),
					uintptr(unsafe.Pointer(&exitTime)),
					uintptr(unsafe.Pointer(&kernelTime)),
					uintptr(unsafe.Pointer(&userTime)),
				)
				if ptRet != 0 {
					kNs := (uint64(kernelTime.HighDateTime) << 32) | uint64(kernelTime.LowDateTime)
					uNs := (uint64(userTime.HighDateTime) << 32) | uint64(userTime.LowDateTime)
					detail.CPUTimeSeconds = float64(kNs+uNs) / 10000000.0 // 100-nanosecond intervals to seconds
					cNs := (int64(createTime.HighDateTime) << 32) | int64(createTime.LowDateTime)
					if cNs > 0 {
						detail.CreationTime = time.Unix(0, (cNs-116444736000000000)*100)
					}
				}

				pathBuf := make([]uint16, 1024)
				pathSize := uint32(len(pathBuf))
				procQueryFullProcessImageNameW.Call(
					hProc,
					0,
					uintptr(unsafe.Pointer(&pathBuf[0])),
					uintptr(unsafe.Pointer(&pathSize)),
				)
				if pathSize > 0 {
					detail.ExecutablePath = syscall.UTF16ToString(pathBuf[:pathSize])
				}

				syscall.CloseHandle(syscall.Handle(hProc))
			}
		}

		procs = append(procs, detail)

		nextRet, _, _ := procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if nextRet == 0 {
			break
		}
	}

	return procs, nil
}

const (
	SC_MANAGER_ENUMERATE_SERVICE = 0x0004
	SC_ENUM_PROCESS_INFO         = 0
	SERVICE_WIN32                = 0x00000030
	SERVICE_STATE_ALL            = 0x00000003

	EvtQueryChannelPath      = 0x1
	EvtQueryReverseDirection = 0x200
	EvtRenderEventXml        = 1
)

type ENUM_SERVICE_STATUS_PROCESS struct {
	lpServiceName        *uint16
	lpDisplayName        *uint16
	ServiceStatusProcess SERVICE_STATUS_PROCESS
}

type SERVICE_STATUS_PROCESS struct {
	dwServiceType             uint32
	dwCurrentState            uint32
	dwControlsAccepted        uint32
	dwWin32ExitCode           uint32
	dwServiceSpecificExitCode uint32
	dwCheckPoint              uint32
	dwWaitHint                uint32
	dwProcessId               uint32
	dwServiceFlags            uint32
}

// GetServices enumerates all system services from the Service Control Manager and registry.
func GetServices() ([]models.ServiceInfo, error) {
	hSCM, _, err := procOpenSCManagerW.Call(0, 0, SC_MANAGER_ENUMERATE_SERVICE)
	if hSCM == 0 {
		return nil, fmt.Errorf("OpenSCManager failed: %w", err)
	}
	defer procCloseServiceHandle.Call(hSCM)

	var bytesNeeded uint32
	var servicesReturned uint32
	var resumeHandle uint32

	procEnumServicesStatusExW.Call(
		hSCM,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		0,
		0,
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)),
		uintptr(unsafe.Pointer(&resumeHandle)),
		0,
	)

	if bytesNeeded == 0 {
		return nil, fmt.Errorf("EnumServicesStatusEx returned 0 bytes needed")
	}

	buf := make([]byte, bytesNeeded)
	ret, _, err := procEnumServicesStatusExW.Call(
		hSCM,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)),
		uintptr(unsafe.Pointer(&resumeHandle)),
		0,
	)
	if ret == 0 {
		return nil, fmt.Errorf("EnumServicesStatusEx failed: %w", err)
	}

	elemSize := int(unsafe.Sizeof(ENUM_SERVICE_STATUS_PROCESS{}))
	var result []models.ServiceInfo

	var hServicesKey syscall.Handle
	servicesPathPtr, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Services`)
	regErr := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, servicesPathPtr, 0, syscall.KEY_READ, &hServicesKey)
	if regErr == nil {
		defer syscall.RegCloseKey(hServicesKey)
	}

	for i := 0; i < int(servicesReturned); i++ {
		item := (*ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[i*elemSize]))
		name := ""
		if item.lpServiceName != nil {
			name = syscall.UTF16ToString((*[512]uint16)(unsafe.Pointer(item.lpServiceName))[:])
		}
		displayName := ""
		if item.lpDisplayName != nil {
			displayName = syscall.UTF16ToString((*[512]uint16)(unsafe.Pointer(item.lpDisplayName))[:])
		}

		status := mapServiceState(item.ServiceStatusProcess.dwCurrentState)
		var pid *uint32
		if item.ServiceStatusProcess.dwProcessId > 0 {
			p := item.ServiceStatusProcess.dwProcessId
			pid = &p
		}

		startType := "Unknown"
		binaryPath := ""
		account := ""

		if regErr == nil && name != "" {
			namePtr, err := syscall.UTF16PtrFromString(name)
			if err == nil {
				var hSubKey syscall.Handle
				if syscall.RegOpenKeyEx(hServicesKey, namePtr, 0, syscall.KEY_READ, &hSubKey) == nil {
					if startVal, err := readRegDWORD(hSubKey, "Start"); err == nil {
						startType = mapServiceStartType(startVal)
						if startVal == 2 {
							if delayed, err := readRegDWORD(hSubKey, "DelayedAutoStart"); err == nil && delayed == 1 {
								startType = "Auto (Delayed)"
							}
						}
					}
					if imgPath, err := readRegString(hSubKey, "ImagePath"); err == nil {
						binaryPath = imgPath
					}
					if objName, err := readRegString(hSubKey, "ObjectName"); err == nil {
						account = objName
					}
					syscall.RegCloseKey(hSubKey)
				}
			}
		}

		result = append(result, models.ServiceInfo{
			Name:        name,
			DisplayName: displayName,
			Status:      status,
			StartType:   startType,
			PID:         pid,
			BinaryPath:  binaryPath,
			Account:     account,
			ExitCode:    item.ServiceStatusProcess.dwWin32ExitCode,
		})
	}

	return result, nil
}

func readRegDWORD(hKey syscall.Handle, valueName string) (uint32, error) {
	valPtr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return 0, err
	}
	var valType uint32
	var val uint32
	valSize := uint32(unsafe.Sizeof(val))
	err = syscall.RegQueryValueEx(hKey, valPtr, nil, &valType, (*byte)(unsafe.Pointer(&val)), &valSize)
	if err != nil {
		return 0, err
	}
	return val, nil
}

func readRegString(hKey syscall.Handle, valueName string) (string, error) {
	valPtr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return "", err
	}
	var valType uint32
	var valSize uint32
	err = syscall.RegQueryValueEx(hKey, valPtr, nil, &valType, nil, &valSize)
	if err != nil {
		return "", err
	}
	if valSize == 0 {
		return "", nil
	}
	buf := make([]uint16, valSize/2+1)
	err = syscall.RegQueryValueEx(hKey, valPtr, nil, &valType, (*byte)(unsafe.Pointer(&buf[0])), &valSize)
	if err != nil {
		return "", err
	}
	return syscall.UTF16ToString(buf), nil
}

func mapServiceState(state uint32) string {
	switch state {
	case 1:
		return "Stopped"
	case 2:
		return "StartPending"
	case 3:
		return "StopPending"
	case 4:
		return "Running"
	case 5:
		return "ContinuePending"
	case 6:
		return "PausePending"
	case 7:
		return "Paused"
	default:
		return "Unknown"
	}
}

func mapServiceStartType(start uint32) string {
	switch start {
	case 0:
		return "Boot"
	case 1:
		return "System"
	case 2:
		return "Auto"
	case 3:
		return "Manual"
	case 4:
		return "Disabled"
	default:
		return "Unknown"
	}
}

type rawEvent struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int    `xml:"EventID"`
		Level       int    `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// GetReliabilityEvents queries Windows Event Log (System and Application channels) for critical reliability issues.
func GetReliabilityEvents(ctx context.Context, timeWindowHours int, maxRecords int) (*models.ReliabilityMetrics, error) {
	metrics := &models.ReliabilityMetrics{
		TimeWindowHours:   timeWindowHours,
		AppCrashes:        make([]models.AppCrashEvent, 0),
		SystemErrors:      make([]models.SystemErrorEvent, 0),
		KernelPowerEvents: make([]models.KernelPowerEvent, 0),
		BugChecks:         make([]models.BugCheckEvent, 0),
	}

	windowMs := int64(timeWindowHours) * 3600 * 1000
	if windowMs <= 0 {
		windowMs = 86400000 // default 24h
	}

	systemQuery := fmt.Sprintf(`*[System[(Level=1 or Level=2 or Level=3 or EventID=41 or EventID=1001 or EventID=7000 or EventID=7001 or EventID=7023 or EventID=7034) and TimeCreated[timediff(@SystemTime) <= %d]]]`, windowMs)
	appQuery := fmt.Sprintf(`*[System[(Level=1 or Level=2 or EventID=1000 or EventID=1001 or EventID=1002) and TimeCreated[timediff(@SystemTime) <= %d]]]`, windowMs)

	sysEvents, _ := queryEventChannel("System", systemQuery, maxRecords/2)
	appEvents, _ := queryEventChannel("Application", appQuery, maxRecords/2)

	allEvents := append(sysEvents, appEvents...)
	metrics.TotalErrorsLogged = len(allEvents)

	for _, ev := range allEvents {
		t, err := time.Parse(time.RFC3339Nano, ev.System.TimeCreated.SystemTime)
		if err != nil {
			t, _ = time.Parse("2006-01-02T15:04:05.999999999Z", ev.System.TimeCreated.SystemTime)
		}

		levelStr := "Info"
		switch ev.System.Level {
		case 1:
			levelStr = "Critical"
		case 2:
			levelStr = "Error"
		case 3:
			levelStr = "Warning"
		}

		// Check for Kernel-Power Event 41
		if ev.System.EventID == 41 && strings.Contains(strings.ToLower(ev.System.Provider.Name), "kernel-power") {
			bugcheck := getDataParam(ev, "BugcheckCode")
			metrics.KernelPowerEvents = append(metrics.KernelPowerEvents, models.KernelPowerEvent{
				Timestamp:    t,
				EventID:      41,
				BugCheckCode: bugcheck,
				Message:      fmt.Sprintf("System has rebooted without cleanly shutting down first (BugcheckCode: %s).", bugcheck),
			})
			continue
		}

		// Check for BugCheck Event 1001
		if ev.System.EventID == 1001 && ev.System.Channel == "System" {
			metrics.BugChecks = append(metrics.BugChecks, models.BugCheckEvent{
				Timestamp:      t,
				BugCheckString: getDataParam(ev, "param1"),
				BugCheckCode:   getDataParam(ev, "param2"),
				DumpFile:       getDataParam(ev, "param3"),
				Message:        "Computer has rebooted from a bugcheck.",
			})
			continue
		}

		// Check for App Crash / Hang
		if (ev.System.EventID == 1000 || ev.System.EventID == 1002) && ev.System.Channel == "Application" {
			appName := getDataParam(ev, "AppName")
			if appName == "" && len(ev.EventData.Data) > 0 {
				appName = ev.EventData.Data[0].Value
			}
			faultMod := getDataParam(ev, "ModuleName")
			if faultMod == "" && len(ev.EventData.Data) > 1 {
				faultMod = ev.EventData.Data[1].Value
			}
			excCode := getDataParam(ev, "ExceptionCode")
			if excCode == "" && len(ev.EventData.Data) > 6 {
				excCode = ev.EventData.Data[6].Value
			}

			metrics.AppCrashes = append(metrics.AppCrashes, models.AppCrashEvent{
				Timestamp:     t,
				Application:   appName,
				FaultModule:   faultMod,
				ExceptionCode: excCode,
				EventID:       ev.System.EventID,
				Message:       fmt.Sprintf("Faulting application: %s, faulting module: %s, exception code: %s", appName, faultMod, excCode),
			})
			continue
		}

		// General System / Application error
		msg := formatEventData(ev)
		metrics.SystemErrors = append(metrics.SystemErrors, models.SystemErrorEvent{
			Timestamp: t,
			Provider:  ev.System.Provider.Name,
			EventID:   ev.System.EventID,
			Level:     levelStr,
			Channel:   ev.System.Channel,
			Message:   msg,
		})
	}

	return metrics, nil
}

func queryEventChannel(channel string, query string, maxRecords int) ([]rawEvent, error) {
	chanPtr, _ := syscall.UTF16PtrFromString(channel)
	queryPtr, _ := syscall.UTF16PtrFromString(query)

	hQuery, _, err := procEvtQuery.Call(
		0,
		uintptr(unsafe.Pointer(chanPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		EvtQueryChannelPath|EvtQueryReverseDirection,
	)
	if hQuery == 0 {
		return nil, fmt.Errorf("EvtQuery on %s failed: %w", channel, err)
	}
	defer procEvtClose.Call(hQuery)

	var events []rawEvent
	batchSize := 20
	hEvents := make([]syscall.Handle, batchSize)

	for len(events) < maxRecords {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			hQuery,
			uintptr(batchSize),
			uintptr(unsafe.Pointer(&hEvents[0])),
			500,
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 || returned == 0 {
			break
		}

		for i := 0; i < int(returned); i++ {
			hEv := hEvents[i]
			var bufferUsed uint32
			var propCount uint32

			procEvtRender.Call(
				0,
				uintptr(hEv),
				EvtRenderEventXml,
				0,
				0,
				uintptr(unsafe.Pointer(&bufferUsed)),
				uintptr(unsafe.Pointer(&propCount)),
			)

			if bufferUsed > 0 {
				buf := make([]uint16, bufferUsed/2+1)
				rRet, _, _ := procEvtRender.Call(
					0,
					uintptr(hEv),
					EvtRenderEventXml,
					uintptr(bufferUsed),
					uintptr(unsafe.Pointer(&buf[0])),
					uintptr(unsafe.Pointer(&bufferUsed)),
					uintptr(unsafe.Pointer(&propCount)),
				)
				if rRet != 0 {
					xmlStr := syscall.UTF16ToString(buf)
					var ev rawEvent
					if xml.Unmarshal([]byte(xmlStr), &ev) == nil {
						events = append(events, ev)
					}
				}
			}
			procEvtClose.Call(uintptr(hEv))
		}
	}

	return events, nil
}

func getDataParam(ev rawEvent, name string) string {
	nameLower := strings.ToLower(name)
	for _, d := range ev.EventData.Data {
		if strings.ToLower(d.Name) == nameLower {
			return strings.TrimSpace(d.Value)
		}
	}
	return ""
}

func formatEventData(ev rawEvent) string {
	var parts []string
	for _, d := range ev.EventData.Data {
		val := strings.TrimSpace(d.Value)
		if val != "" {
			if d.Name != "" {
				parts = append(parts, fmt.Sprintf("%s=%s", d.Name, val))
			} else {
				parts = append(parts, val)
			}
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("Event %d from %s", ev.System.EventID, ev.System.Provider.Name)
	}
	return strings.Join(parts, "; ")
}

// GetSoftwareInventory inspects the Windows registry for installed software, hotfixes, and runtime frameworks.
func GetSoftwareInventory() (*models.SoftwareMetrics, error) {
	metrics := &models.SoftwareMetrics{
		Applications: make([]models.InstalledApp, 0),
		HotFixes:     make([]models.HotFixInfo, 0),
		Runtimes:     make([]models.RuntimeInfo, 0),
	}

	seenApps := make(map[string]bool)

	// Scan HKLM 64-bit
	scanUninstallKey(syscall.HKEY_LOCAL_MACHINE, syscall.KEY_READ|syscall.KEY_WOW64_64KEY, "System", metrics, seenApps)
	// Scan HKLM 32-bit
	scanUninstallKey(syscall.HKEY_LOCAL_MACHINE, syscall.KEY_READ|syscall.KEY_WOW64_32KEY, "System", metrics, seenApps)
	// Scan HKCU User
	scanUninstallKey(syscall.HKEY_CURRENT_USER, syscall.KEY_READ, "User", metrics, seenApps)

	metrics.TotalInstalledApps = len(metrics.Applications)
	metrics.Runtimes = discoverRuntimes()

	return metrics, nil
}

func scanUninstallKey(root syscall.Handle, access uint32, scope string, metrics *models.SoftwareMetrics, seen map[string]bool) {
	pathPtr, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`)
	var hKey syscall.Handle
	if syscall.RegOpenKeyEx(root, pathPtr, 0, access, &hKey) != nil {
		return
	}
	defer syscall.RegCloseKey(hKey)

	var subkeyIndex uint32
	for {
		var nameBuf [256]uint16
		var nameLen uint32 = uint32(len(nameBuf))
		ret, _, _ := procRegEnumKeyExW.Call(
			uintptr(hKey),
			uintptr(subkeyIndex),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(unsafe.Pointer(&nameLen)),
			0, 0, 0, 0,
		)
		if ret != 0 {
			break
		}
		subkeyIndex++

		subName := syscall.UTF16ToString(nameBuf[:nameLen])
		subPathPtr, err := syscall.UTF16PtrFromString(subName)
		if err != nil {
			continue
		}

		var hSubKey syscall.Handle
		if syscall.RegOpenKeyEx(hKey, subPathPtr, 0, access, &hSubKey) == nil {
			dispName, _ := readRegString(hSubKey, "DisplayName")
			dispVer, _ := readRegString(hSubKey, "DisplayVersion")
			pub, _ := readRegString(hSubKey, "Publisher")
			instDate, _ := readRegString(hSubKey, "InstallDate")
			sysComp, _ := readRegDWORD(hSubKey, "SystemComponent")
			parentKey, _ := readRegString(hSubKey, "ParentKeyName")

			syscall.RegCloseKey(hSubKey)

			if dispName == "" || sysComp == 1 || parentKey != "" {
				continue
			}

			if strings.HasPrefix(strings.ToUpper(dispName), "KB") || strings.Contains(strings.ToUpper(dispName), "HOTFIX") || strings.HasPrefix(strings.ToUpper(subName), "KB") {
				kbID := subName
				if strings.HasPrefix(strings.ToUpper(dispName), "KB") {
					kbID = strings.Fields(dispName)[0]
				}
				metrics.HotFixes = append(metrics.HotFixes, models.HotFixInfo{
					HotFixID:    kbID,
					Description: dispName,
					InstalledOn: instDate,
				})
				continue
			}

			key := fmt.Sprintf("%s|%s", strings.ToLower(dispName), strings.ToLower(dispVer))
			if !seen[key] {
				seen[key] = true
				metrics.Applications = append(metrics.Applications, models.InstalledApp{
					Name:        dispName,
					Version:     dispVer,
					Publisher:   pub,
					InstallDate: instDate,
					Scope:       scope,
				})
			}
		}
	}
}

func discoverRuntimes() []models.RuntimeInfo {
	var runtimes []models.RuntimeInfo

	// 1. .NET Framework
	var hNetKey syscall.Handle
	netPathPtr, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full`)
	if syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, netPathPtr, 0, syscall.KEY_READ, &hNetKey) == nil {
		if ver, err := readRegString(hNetKey, "Version"); err == nil && ver != "" {
			runtimes = append(runtimes, models.RuntimeInfo{
				Name:    ".NET Framework",
				Version: ver,
			})
		}
		syscall.RegCloseKey(hNetKey)
	}

	// 2. .NET Core / .NET Runtimes
	dotnetPath := `C:\Program Files\dotnet\shared\Microsoft.NETCore.App`
	if entries, err := os.ReadDir(dotnetPath); err == nil {
		var versions []string
		for _, e := range entries {
			if e.IsDir() {
				versions = append(versions, e.Name())
			}
		}
		if len(versions) > 0 {
			sort.Strings(versions)
			runtimes = append(runtimes, models.RuntimeInfo{
				Name:    ".NET Core / .NET Runtime",
				Version: strings.Join(versions, ", "),
				Path:    dotnetPath,
			})
		}
	}

	// 3. Go
	goRoot := os.Getenv("GOROOT")
	if goRoot == "" {
		if _, err := os.Stat(`C:\Program Files\Go`); err == nil {
			goRoot = `C:\Program Files\Go`
		} else if _, err := os.Stat(`C:\Go`); err == nil {
			goRoot = `C:\Go`
		}
	}
	if goRoot != "" {
		runtimes = append(runtimes, models.RuntimeInfo{
			Name: "Go",
			Path: goRoot,
		})
	}

	// 4. Python
	var hPyKey syscall.Handle
	pyPathPtr, _ := syscall.UTF16PtrFromString(`SOFTWARE\Python\PythonCore`)
	if syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, pyPathPtr, 0, syscall.KEY_READ, &hPyKey) == nil {
		var pyIndex uint32
		for {
			var nameBuf [64]uint16
			var nameLen uint32 = uint32(len(nameBuf))
			ret, _, _ := procRegEnumKeyExW.Call(uintptr(hPyKey), uintptr(pyIndex), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)), 0, 0, 0, 0)
			if ret != 0 {
				break
			}
			pyIndex++
			ver := syscall.UTF16ToString(nameBuf[:nameLen])
			if ver != "" {
				runtimes = append(runtimes, models.RuntimeInfo{
					Name:    "Python (System)",
					Version: ver,
				})
			}
		}
		syscall.RegCloseKey(hPyKey)
	}

	return runtimes
}

// IsLaunchedFromExplorer checks if the current process was launched directly from Windows Explorer (e.g. double-clicked).
func IsLaunchedFromExplorer() bool {
	ppid := os.Getppid()
	if ppid <= 0 {
		return false
	}
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(snapshot)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := syscall.Process32First(snapshot, &entry); err != nil {
		return false
	}

	for {
		if entry.ProcessID == uint32(ppid) {
			name := syscall.UTF16ToString(entry.ExeFile[:])
			return strings.EqualFold(name, "explorer.exe")
		}
		if err := syscall.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return false
}
