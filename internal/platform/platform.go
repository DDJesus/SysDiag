package platform

import (
	"runtime"
	"time"
)

// Platform identifies the target operating system family.
type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
	PlatformDarwin  Platform = "darwin"
	PlatformUnknown Platform = "unknown"
)

// CurrentPlatform returns the runtime operating system platform.
func CurrentPlatform() Platform {
	switch runtime.GOOS {
	case "windows":
		return PlatformWindows
	case "linux":
		return PlatformLinux
	case "darwin":
		return PlatformDarwin
	default:
		return PlatformUnknown
	}
}

// HostInfo summarizes basic platform and host runtime attributes.
type HostInfo struct {
	Platform     Platform
	OSName       string
	OSVersion    string
	OSBuild      string
	Architecture string
	Hostname     string
	Uptime       time.Duration
	BootTime     time.Time
	IsElevated   bool
	Privilege    string
}
