package models

// VolumeMetrics represents a logical volume or mount point.
type VolumeMetrics struct {
	MountPoint  string  `json:"mount_point"`
	VolumeName  string  `json:"volume_name,omitempty"`
	FileSystem  string  `json:"filesystem,omitempty"`
	DriveType   string  `json:"drive_type,omitempty"`
	TotalBytes  uint64  `json:"total_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`
	IsReadOnly  bool    `json:"is_read_only,omitempty"`
}

// PhysicalDiskMetrics represents a physical storage device.
type PhysicalDiskMetrics struct {
	DeviceID     string `json:"device_id"`
	Model        string `json:"model,omitempty"`
	MediaType    string `json:"media_type,omitempty"`
	BusType      string `json:"bus_type,omitempty"`
	SizeBytes    uint64 `json:"size_bytes,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
}

// StorageIOMetrics captures real-time I/O throughput and queue telemetry.
type StorageIOMetrics struct {
	ReadBytesPerSec  uint64  `json:"read_bytes_per_sec,omitempty"`
	WriteBytesPerSec uint64  `json:"write_bytes_per_sec,omitempty"`
	AvgQueueDepth    float64 `json:"avg_queue_depth,omitempty"`
	AvgLatencyMs     float64 `json:"avg_latency_ms,omitempty"`
}

// StorageMetrics encapsulates all storage subsystem telemetry.
type StorageMetrics struct {
	Volumes       []VolumeMetrics       `json:"volumes"`
	PhysicalDisks []PhysicalDiskMetrics `json:"physical_disks,omitempty"`
	IOMetrics     *StorageIOMetrics     `json:"io_metrics,omitempty"`
}
