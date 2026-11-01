package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/reporter"
)

type stubProbe struct {
	id       string
	category collector.ProbeCategory
	profiles []string
	data     interface{}
}

func (p stubProbe) ID() string                                  { return p.id }
func (p stubProbe) Name() string                                { return p.id }
func (p stubProbe) Category() collector.ProbeCategory           { return p.category }
func (p stubProbe) RequiredPrivilege() collector.PrivilegeLevel { return collector.PrivilegeUser }
func (p stubProbe) SupportedProfiles() []string                 { return p.profiles }
func (p stubProbe) Run(context.Context, time.Duration) (interface{}, collector.ProbeStatus, error) {
	return p.data, collector.StatusSuccess, nil
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("writer failed") }

func testDependencies() dependencies {
	deps := defaultDependencies()
	deps.isElevated = func() (bool, error) { return false, nil }
	deps.executable = func() (string, error) { return "sysdiag-test", nil }
	deps.hostname = func() (string, error) { return "TEST-HOST", nil }
	deps.resolveOutputDir = func(string) (string, bool, error) { return "test-output", false, nil }
	deps.probes = func() []collector.Probe {
		return []collector.Probe{
			stubProbe{
				id: "system", category: collector.CategorySystem, profiles: []string{"quick", "deep"},
				data: &models.SystemMetrics{Hostname: "TEST-HOST", OSName: "Test OS"},
			},
		}
	}
	deps.createFile = func(string) (io.WriteCloser, error) { return nil, errors.New("unexpected file creation") }
	deps.isLaunchedFromExplorer = func() bool { return false }
	return deps
}

func TestRunCommand_SuccessAndInvalidProfileFallback(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), []string{"--json-only", "--profile", "not-a-profile"}, nil, &stdout, &stderr, testDependencies())
	if code != 0 {
		t.Fatalf("runCommand exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	report, err := models.FromJSON(stdout.Bytes())
	if err != nil {
		t.Fatalf("stdout is not a report JSON document: %v", err)
	}
	if report.Metadata.Profile != "quick" {
		t.Errorf("invalid profile resolved to %q, want quick", report.Metadata.Profile)
	}
	if report.Metadata.Hostname != "TEST-HOST" || report.CollectionStatus.Successful != 1 {
		t.Errorf("unexpected collected report metadata/status: hostname=%q successful=%d", report.Metadata.Hostname, report.CollectionStatus.Successful)
	}
	if report.Data.System == nil || report.Data.System.OSName != "Test OS" {
		t.Errorf("system probe data was not normalized: %#v", report.Data.System)
	}
	if stderr.Len() != 0 {
		t.Errorf("unexpected stderr: %s", stderr.String())
	}
}

func TestRunCommand_InvalidOption(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommand(context.Background(), []string{"--not-a-real-option"}, nil, &stdout, &stderr, dependencies{})
	if code != 2 {
		t.Errorf("invalid option exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "not defined") {
		t.Errorf("expected flag parse error, got %q", stderr.String())
	}
}

func TestRunCommand_JSONOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommand(context.Background(), []string{"--json-only"}, nil, failingWriter{}, &stderr, testDependencies())
	if code != 1 {
		t.Errorf("JSON output failure exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "Error exporting JSON: writer failed") {
		t.Errorf("expected JSON export error, got %q", stderr.String())
	}
}

func TestRun_ReportsOutputAndReporterDependencyErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := testDependencies()
	deps.newHTMLReporter = func() (reporter.Reporter, error) { return nil, errors.New("renderer unavailable") }
	code := run(context.Background(), commandOptions{profile: "quick"}, strings.NewReader(""), &stdout, &stderr, deps)
	if code != 0 {
		t.Errorf("optional file/reporter failures changed exit code to %d, want existing best-effort code 0", code)
	}
	for _, want := range []string{"failed to save JSON report", "failed to initialize HTML reporter: renderer unavailable"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr %q does not contain %q", stderr.String(), want)
		}
	}
}

func TestSelectProbes_ProfileAndCategoryFilters(t *testing.T) {
	registry := collector.NewRegistry()
	registry.Register(stubProbe{id: "system", category: collector.CategorySystem, profiles: []string{"quick"}})
	registry.Register(stubProbe{id: "storage", category: collector.CategoryStorage, profiles: []string{"deep"}})
	registry.Register(stubProbe{id: "network", category: collector.CategoryNetwork, profiles: []string{"all"}})

	quick := selectProbes(registry, "quick", commandOptions{})
	if len(quick) != 2 {
		t.Errorf("quick profile selected %d probes, want 2", len(quick))
	}
	filtered := selectProbes(registry, "quick", commandOptions{storage: true, perf: true})
	if len(filtered) != 1 || filtered[0].ID() != "storage" {
		t.Errorf("storage+performance filter selected %#v, want storage only", filtered)
	}
}
