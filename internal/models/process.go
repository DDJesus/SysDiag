package models

import "time"

// ProcessSummary captures resource metrics and metadata of an individual process.
type ProcessSummary struct {
	PID             uint32     `json:"pid"`
	PPID            uint32     `json:"ppid"`
	Name            string     `json:"name"`
	ExecutablePath  string     `json:"executable_path,omitempty"`
	ThreadCount     uint32     `json:"thread_count"`
	WorkingSetBytes uint64     `json:"working_set_bytes"`
	PrivateBytes    uint64     `json:"private_bytes,omitempty"`
	CPUTimeSeconds  float64    `json:"cpu_time_seconds,omitempty"`
	CPUPercent      float64    `json:"cpu_percent,omitempty"`
	StartTime       *time.Time `json:"start_time,omitempty"`
}

// ProcessMetrics encapsulates system-wide process statistics and top consumers.
type ProcessMetrics struct {
	TotalProcesses int              `json:"total_processes"`
	TotalThreads   int              `json:"total_threads"`
	TopCPU         []ProcessSummary `json:"top_cpu"`
	TopMemory      []ProcessSummary `json:"top_memory"`
}
