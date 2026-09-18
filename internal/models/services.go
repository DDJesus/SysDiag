package models

// ServiceInfo encapsulates state and configuration of an OS service or daemon.
type ServiceInfo struct {
	Name        string  `json:"name"`
	DisplayName string  `json:"display_name"`
	Status      string  `json:"status"`               // "Running", "Stopped", "Paused", "StartPending", "StopPending"
	StartType   string  `json:"start_type"`           // "Auto", "Auto (Delayed)", "Manual", "Disabled", "Boot", "System", "Unknown"
	PID         *uint32 `json:"pid,omitempty"`        // Process ID if currently running
	BinaryPath  string  `json:"binary_path,omitempty"`
	Account     string  `json:"account,omitempty"`    // Service execution account (e.g. LocalSystem, NetworkService)
	ExitCode    uint32  `json:"exit_code,omitempty"`
}

// ServicesMetrics summarizes all discovered system services and highlights failures.
type ServicesMetrics struct {
	TotalCount           int           `json:"total_count"`
	RunningCount         int           `json:"running_count"`
	StoppedCount         int           `json:"stopped_count"`
	FailedAutoStartCount int           `json:"failed_auto_start_count"`
	FailedAutoStart      []ServiceInfo `json:"failed_auto_start"`
	Services             []ServiceInfo `json:"services,omitempty"` // Included in deep profile
}
