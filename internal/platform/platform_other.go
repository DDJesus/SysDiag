//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package platform

// IsProcessElevated returns false on unsupported generic platforms.
func IsProcessElevated() (bool, error) {
	return false, nil
}

// IsLaunchedFromExplorer returns false on unsupported generic platforms.
func IsLaunchedFromExplorer() bool {
	return false
}
