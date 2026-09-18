package models

import "time"

// AppCrashEvent records an application failure or unhandled exception event.
type AppCrashEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	Application   string    `json:"application"`
	FaultModule   string    `json:"fault_module,omitempty"`
	ExceptionCode string    `json:"exception_code,omitempty"`
	EventID       int       `json:"event_id"`
	Message       string    `json:"message,omitempty"`
}

// SystemErrorEvent captures critical or error-level OS log records.
type SystemErrorEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Provider  string    `json:"provider"`
	EventID   int       `json:"event_id"`
	Level     string    `json:"level"` // "Critical", "Error", "Warning"
	Channel   string    `json:"channel"`
	Message   string    `json:"message"`
}

// KernelPowerEvent records dirty shutdowns, sudden loss of power, or sleep transitions.
type KernelPowerEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	EventID      int       `json:"event_id"` // 41
	BugCheckCode string    `json:"bugcheck_code,omitempty"`
	Message      string    `json:"message"`
}

// BugCheckEvent records a system blue-screen crash dump event (Event ID 1001).
type BugCheckEvent struct {
	Timestamp      time.Time `json:"timestamp"`
	BugCheckString string    `json:"bugcheck_string,omitempty"`
	BugCheckCode   string    `json:"bugcheck_code,omitempty"`
	DumpFile       string    `json:"dump_file,omitempty"`
	Message        string    `json:"message"`
}

// ReliabilityMetrics aggregates crash, blue-screen, and system error events.
type ReliabilityMetrics struct {
	TimeWindowHours   int                `json:"time_window_hours"`
	TotalErrorsLogged int                `json:"total_errors_logged"`
	AppCrashes        []AppCrashEvent    `json:"app_crashes"`
	SystemErrors      []SystemErrorEvent `json:"system_errors"`
	KernelPowerEvents []KernelPowerEvent `json:"kernel_power_events"`
	BugChecks         []BugCheckEvent    `json:"bugchecks"`
}
