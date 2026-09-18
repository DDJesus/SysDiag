//go:build linux
// +build linux

package platform

import (
	"os"
)

// IsProcessElevated checks whether the current process is running as root (euid 0) on Linux.
func IsProcessElevated() (bool, error) {
	return os.Geteuid() == 0, nil
}

// IsLaunchedFromExplorer returns false on Linux.
func IsLaunchedFromExplorer() bool {
	return false
}
