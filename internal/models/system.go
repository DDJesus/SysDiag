package models

import "time"

// VirtualizationInfo details hypervisor presence and virtualization state.
type VirtualizationInfo struct {
	IsVirtual  bool   `json:"is_virtual"`
	Hypervisor string `json:"hypervisor,omitempty"`
}

// SystemMetrics encapsulates host OS, uptime, and identity telemetry.
type SystemMetrics struct {
	Hostname       string             `json:"hostname"`
	OSName         string             `json:"os_name"`
	OSVersion      string             `json:"os_version,omitempty"`
	OSBuild        string             `json:"os_build"`
	Architecture   string             `json:"architecture"`
	UptimeSeconds  uint64             `json:"uptime_seconds"`
	BootTime       time.Time          `json:"boot_time"`
	Virtualization VirtualizationInfo `json:"virtualization"`
}

// CPUMetrics encapsulates processor topology and utilization measurements.
type CPUMetrics struct {
	Model              string  `json:"model"`
	PhysicalCores      int     `json:"physical_cores"`
	LogicalCores       int     `json:"logical_cores"`
	UtilizationPercent float64 `json:"utilization_percent"`
	UserPercent        float64 `json:"user_percent"`
	KernelPercent      float64 `json:"kernel_percent"`
}

// MemoryMetrics encapsulates physical and virtual memory usage telemetry.
type MemoryMetrics struct {
	TotalBytes       uint64  `json:"total_bytes"`
	AvailableBytes   uint64  `json:"available_bytes"`
	UsedBytes        uint64  `json:"used_bytes"`
	UsedPercent      float64 `json:"used_percent"`
	CommitLimitBytes uint64  `json:"commit_limit_bytes"`
	CommitTotalBytes uint64  `json:"commit_total_bytes"`
	CommitPercent    float64 `json:"commit_percent"`
}

// DiagnosticData aggregates normalized subsystem models.
type DiagnosticData struct {
	System      *SystemMetrics      `json:"system,omitempty"`
	CPU         *CPUMetrics         `json:"cpu,omitempty"`
	Memory      *MemoryMetrics      `json:"memory,omitempty"`
	Storage     *StorageMetrics     `json:"storage,omitempty"`
	Network     *NetworkMetrics     `json:"network,omitempty"`
	Processes   *ProcessMetrics     `json:"processes,omitempty"`
	Services    *ServicesMetrics    `json:"services,omitempty"`
	Reliability *ReliabilityMetrics `json:"reliability,omitempty"`
	Software    *SoftwareMetrics    `json:"software,omitempty"`
}
