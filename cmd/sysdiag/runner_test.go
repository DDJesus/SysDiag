package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/reporter"
	jsonReporter "github.com/systemdiag/sysdiag/internal/reporter/json"
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

type memoryWriteCloser struct{ bytes.Buffer }

func (*memoryWriteCloser) Close() error { return nil }

type closeFailWriteCloser struct{ bytes.Buffer }

func (*closeFailWriteCloser) Close() error { return errors.New("close failed") }

type failingReporter struct{ err error }

func (f failingReporter) Name() string { return "failing" }
func (f failingReporter) Generate(*models.DiagnosticReport, io.Writer) error {
	return f.err
}

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
	deps.createFile = func(string) (io.WriteCloser, error) { return &memoryWriteCloser{}, nil }
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
	if code != 1 {
		t.Errorf("artifact failures exit code = %d, want 1", code)
	}
	for _, want := range []string{"failed to initialize HTML reporter: renderer unavailable"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr %q does not contain %q", stderr.String(), want)
		}
	}
}

func TestRun_HTMLCreationFailureDoesNotAdvertisePath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := testDependencies()
	deps.createFile = func(path string) (io.WriteCloser, error) {
		if strings.HasSuffix(path, ".html") {
			return nil, errors.New("disk full")
		}
		return &memoryWriteCloser{}, nil
	}

	code := run(context.Background(), commandOptions{profile: "quick"}, strings.NewReader(""), &stdout, &stderr, deps)
	if code != 1 {
		t.Errorf("HTML creation failure exit code = %d, want 1", code)
	}
	if strings.Contains(stdout.String(), "WHAT TO SEND") || strings.Contains(stdout.String(), ".html") {
		t.Errorf("handoff advertised an HTML report after creation failure: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "failed to save HTML report: disk full") {
		t.Errorf("expected HTML creation warning, got %q", stderr.String())
	}
}

func TestRun_HTMLGenerationFailureDoesNotAdvertisePath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := testDependencies()
	deps.createFile = func(string) (io.WriteCloser, error) { return &memoryWriteCloser{}, nil }
	deps.newHTMLReporter = func() (reporter.Reporter, error) {
		return failingReporter{err: errors.New("template write failed")}, nil
	}

	code := run(context.Background(), commandOptions{profile: "quick"}, strings.NewReader(""), &stdout, &stderr, deps)
	if code != 1 {
		t.Errorf("HTML generation failure exit code = %d, want 1", code)
	}
	if strings.Contains(stdout.String(), "WHAT TO SEND") || strings.Contains(stdout.String(), ".html") {
		t.Errorf("handoff advertised an HTML report after generation failure: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "failed to write HTML report: template write failed") {
		t.Errorf("expected HTML generation warning, got %q", stderr.String())
	}
}

func TestWriteReportFile_CloseFailureReturnsError(t *testing.T) {
	err := writeReportFile("report.html", "HTML", failingReporter{}, models.NewDiagnosticReport(), func(string) (io.WriteCloser, error) {
		return &closeFailWriteCloser{}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "failed to close HTML report: close failed") {
		t.Errorf("writeReportFile error = %v, want a close failure", err)
	}
}

func TestWriteReportFileFailureMatrix(t *testing.T) {
	for _, tc := range []struct {
		name   string
		create func(string) (io.WriteCloser, error)
		rep    reporter.Reporter
		want   string
	}{
		{"create", func(string) (io.WriteCloser, error) { return nil, errors.New("create") }, failingReporter{}, "failed to save"},
		{"render", func(string) (io.WriteCloser, error) { return &memoryWriteCloser{}, nil }, failingReporter{errors.New("render")}, "failed to write"},
		{"write", func(string) (io.WriteCloser, error) { return &writerFailCloser{}, nil }, jsonReporter.NewReporter(), "failed to write"},
		{"close", func(string) (io.WriteCloser, error) { return &closeFailWriteCloser{}, nil }, jsonReporter.NewReporter(), "failed to close"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := writeReportFile(filepath.Join(t.TempDir(), "report"), "JSON", tc.rep, models.NewDiagnosticReport(), tc.create)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want %q", err, tc.want)
			}
		})
	}
}

func TestWriteReportFileCleanupOwnership(t *testing.T) {
	t.Run("failed artifact removed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "report")
		create := func(p string) (io.WriteCloser, error) { return os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) }
		if err := writeReportFile(path, "HTML", failingReporter{errors.New("render")}, models.NewDiagnosticReport(), create); err == nil {
			t.Fatal("expected error")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("incomplete artifact still exists: %v", err)
		}
	})
	t.Run("collision preserved", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "report")
		original := []byte("pre-existing")
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		create := func(p string) (io.WriteCloser, error) { return os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) }
		if err := writeReportFile(path, "JSON", jsonReporter.NewReporter(), models.NewDiagnosticReport(), create); err == nil {
			t.Fatal("expected collision")
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatalf("pre-existing file changed: %q %v", got, err)
		}
	})
}

func TestRunArtifactOutcomeMatrix(t *testing.T) {
	for _, tc := range []struct {
		name               string
		opts               commandOptions
		jsonFail, htmlFail bool
		wantCode           int
		wantJSON, wantHTML bool
	}{
		{"both succeed", commandOptions{profile: "quick"}, false, false, 0, true, true},
		{"json fails html succeeds", commandOptions{profile: "quick"}, true, false, 1, false, true},
		{"html fails json succeeds", commandOptions{profile: "quick"}, false, true, 1, true, false},
		{"both fail", commandOptions{profile: "quick"}, true, true, 1, false, false},
		{"no html success", commandOptions{profile: "quick", noHTML: true}, false, false, 0, true, false},
		{"no html json failure", commandOptions{profile: "quick", noHTML: true}, true, false, 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			deps := testDependencies()
			if tc.jsonFail {
				deps.jsonReporter = failingReporter{errors.New("json render")}
			}
			if tc.htmlFail {
				deps.newHTMLReporter = func() (reporter.Reporter, error) { return nil, errors.New("html init") }
			}
			code := run(context.Background(), tc.opts, strings.NewReader(""), &stdout, &stderr, deps)
			if code != tc.wantCode {
				t.Errorf("exit=%d want %d", code, tc.wantCode)
			}
			if strings.Contains(stdout.String(), "[SUCCESS]") != (tc.wantCode == 0) {
				t.Errorf("unexpected final status: %s", stdout.String())
			}
			if strings.Contains(stdout.String(), ".json") != tc.wantJSON {
				t.Errorf("json path presence mismatch: %s", stdout.String())
			}
			if strings.Contains(stdout.String(), ".html") != tc.wantHTML {
				t.Errorf("html path presence mismatch: %s", stdout.String())
			}
			if (tc.jsonFail || tc.htmlFail) && !strings.Contains(stderr.String(), "Error:") {
				t.Errorf("missing artifact error: %s", stderr.String())
			}
		})
	}
}

type writerFailCloser struct{}

func (writerFailCloser) Write([]byte) (int, error) { return 0, errors.New("write") }
func (writerFailCloser) Close() error              { return nil }

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
