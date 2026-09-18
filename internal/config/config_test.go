package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/systemdiag/sysdiag/internal/config"
)

func TestProfileConfig(t *testing.T) {
	quick := config.GetProfileConfig(config.ProfileQuick)
	if quick.Name != config.ProfileQuick {
		t.Errorf("Expected profile quick, got %s", quick.Name)
	}
	if quick.SampleDuration != 300*time.Millisecond {
		t.Errorf("Expected 300ms sample duration, got %v", quick.SampleDuration)
	}
	if quick.ProbeTimeout != 5*time.Second {
		t.Errorf("Expected 5s probe timeout, got %v", quick.ProbeTimeout)
	}

	deep := config.GetProfileConfig(config.ProfileDeep)
	if deep.Name != config.ProfileDeep {
		t.Errorf("Expected profile deep, got %s", deep.Name)
	}
	if deep.SampleDuration != 2*time.Second {
		t.Errorf("Expected 2s sample duration, got %v", deep.SampleDuration)
	}
	if deep.ProbeTimeout != 15*time.Second {
		t.Errorf("Expected 15s probe timeout, got %v", deep.ProbeTimeout)
	}

	def := config.GetProfileConfig("unknown_custom")
	if def.Name != config.ProfileQuick {
		t.Errorf("Expected default to quick profile, got %s", def.Name)
	}
}

func TestResolveOutputDir_WritableDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "sysdiag_test_out_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	resolved, fellBack, err := config.ResolveOutputDir(tempDir)
	if err != nil {
		t.Fatalf("Expected ResolveOutputDir to succeed, got %v", err)
	}
	if fellBack {
		t.Errorf("Expected fellBack to be false for writable directory")
	}

	absExpected, _ := filepath.Abs(tempDir)
	if resolved != absExpected {
		t.Errorf("Expected resolved path %s, got %s", absExpected, resolved)
	}
}

func TestResolveOutputDir_EmptyRequestedDir(t *testing.T) {
	resolved, fellBack, err := config.ResolveOutputDir("")
	if err != nil {
		t.Fatalf("Expected ResolveOutputDir to succeed for empty string (current dir), got %v", err)
	}
	if fellBack {
		t.Errorf("Expected fellBack false when running in project directory")
	}
	if resolved == "" {
		t.Errorf("Expected non-empty resolved path")
	}
}
