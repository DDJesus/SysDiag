//go:build windows
// +build windows

package platform

import (
	"github.com/systemdiag/sysdiag/internal/winapi"
)

// IsProcessElevated checks whether the current process has administrative / elevated privileges on Windows.
func IsProcessElevated() (bool, error) {
	return winapi.IsProcessElevated()
}

// IsLaunchedFromExplorer checks whether the process was spawned by Windows Explorer (double-clicked).
func IsLaunchedFromExplorer() bool {
	return winapi.IsLaunchedFromExplorer()
}
