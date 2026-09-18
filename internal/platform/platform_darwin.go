//go:build darwin
// +build darwin

package platform

import (
	"os"
)

// IsProcessElevated checks whether the current process is running as root (euid 0) on macOS.
func IsProcessElevated() (bool, error) {
	return os.Geteuid() == 0, nil
}

// IsLaunchedFromExplorer returns false on macOS.
func IsLaunchedFromExplorer() bool {
	return false
}
