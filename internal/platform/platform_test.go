package platform_test

import (
	"runtime"
	"testing"

	"github.com/systemdiag/sysdiag/internal/platform"
)

func TestCurrentPlatform(t *testing.T) {
	current := platform.CurrentPlatform()
	switch runtime.GOOS {
	case "windows":
		if current != platform.PlatformWindows {
			t.Fatalf("expected PlatformWindows, got %s", current)
		}
	case "linux":
		if current != platform.PlatformLinux {
			t.Fatalf("expected PlatformLinux, got %s", current)
		}
	case "darwin":
		if current != platform.PlatformDarwin {
			t.Fatalf("expected PlatformDarwin, got %s", current)
		}
	default:
		if current != platform.PlatformUnknown {
			t.Fatalf("expected PlatformUnknown, got %s", current)
		}
	}
}

func TestIsProcessElevated(t *testing.T) {
	elevated, err := platform.IsProcessElevated()
	if err != nil {
		t.Logf("IsProcessElevated returned error (expected in some mock environments): %v", err)
	}
	t.Logf("Process elevation state: %v", elevated)
}

func TestIsLaunchedFromExplorer(t *testing.T) {
	// Should return boolean without panic
	isDoubleClicked := platform.IsLaunchedFromExplorer()
	t.Logf("Launched from GUI/Explorer: %v", isDoubleClicked)
}
