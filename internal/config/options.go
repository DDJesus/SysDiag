package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Options encapsulates CLI flags and runtime parameters.
type Options struct {
	Profile        string
	OutputDir      string
	JSONOnly       bool
	NoHTML         bool
	Sanitize       bool
	SampleDuration time.Duration
	ProbeTimeout   time.Duration
}

// ResolveOutputDir validates directory writability and falls back to temp directory if read-only.
func ResolveOutputDir(requestedDir string) (resolvedPath string, fellBack bool, err error) {
	target := requestedDir
	if target == "" {
		target = "."
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		absTarget = target
	}

	// Ensure directory exists or create it
	if err := os.MkdirAll(absTarget, 0755); err != nil {
		return fallbackTempDir()
	}

	// Test writability with a temporary canary file
	testFile := filepath.Join(absTarget, fmt.Sprintf(".sysdiag_write_test_%d", time.Now().UnixNano()))
	f, err := os.OpenFile(testFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fallbackTempDir()
	}
	f.Close()
	os.Remove(testFile)

	return absTarget, false, nil
}

func fallbackTempDir() (string, bool, error) {
	tempBase := os.TempDir()
	fallbackDir := filepath.Join(tempBase, "sysdiag_output")
	if err := os.MkdirAll(fallbackDir, 0755); err != nil {
		return "", false, fmt.Errorf("failed to create fallback temp output directory: %w", err)
	}
	return fallbackDir, true, nil
}
