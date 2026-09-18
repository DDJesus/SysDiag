package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/systemdiag/sysdiag/internal/analyzer"
	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/config"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/probes/cpu"
	"github.com/systemdiag/sysdiag/internal/probes/memory"
	"github.com/systemdiag/sysdiag/internal/probes/network"
	"github.com/systemdiag/sysdiag/internal/probes/process"
	"github.com/systemdiag/sysdiag/internal/probes/reliability"
	"github.com/systemdiag/sysdiag/internal/probes/services"
	"github.com/systemdiag/sysdiag/internal/probes/software"
	"github.com/systemdiag/sysdiag/internal/probes/storage"
	"github.com/systemdiag/sysdiag/internal/probes/system"
	htmlReporter "github.com/systemdiag/sysdiag/internal/reporter/html"
	jsonReporter "github.com/systemdiag/sysdiag/internal/reporter/json"
	termReporter "github.com/systemdiag/sysdiag/internal/reporter/terminal"
)

func TestEndToEnd_VerticalSlicePipeline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "sysdiag_e2e_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	resolvedDir, fellBack, err := config.ResolveOutputDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to resolve output dir: %v", err)
	}
	if fellBack {
		t.Errorf("Did not expect fallback for writable temp dir")
	}

	report := models.NewDiagnosticReport()
	report.Metadata = models.ExecutionMetadata{
		ToolVersion:     "1.0.0",
		ScanTimestamp:   time.Now().UTC(),
		Profile:         "quick",
		Hostname:        "TEST-E2E-HOST",
		OS:              "windows",
		OSVersion:       "Microsoft Windows",
		Architecture:    "amd64",
		PrivilegeLevel:  "User",
		IsElevated:      false,
		ExecutionPath:   filepath.Join(tmpDir, "sysdiag.exe"),
		OutputDirectory: resolvedDir,
	}

	registry := collector.NewRegistry()
	registry.Register(system.NewProbe())
	registry.Register(cpu.NewProbe())
	registry.Register(memory.NewProbe())
	registry.Register(storage.NewProbe())
	registry.Register(network.NewProbe())
	registry.Register(process.NewProbe())
	registry.Register(services.NewProbe())
	registry.Register(reliability.NewProbe())
	registry.Register(software.NewProbe())

	probes := registry.ForProfile("quick")
	if len(probes) != 9 {
		t.Fatalf("Expected 9 registered probes for quick profile, got %d", len(probes))
	}

	engine := collector.NewEngine(
		collector.WithMaxConcurrency(4),
		collector.WithProbeTimeout(5*time.Second),
	)

	start := time.Now()
	results := engine.Execute(ctx, probes, 300*time.Millisecond)
	engine.Normalize(results, report)
	report.Metadata.ScanDurationMS = time.Since(start).Milliseconds()

	if report.CollectionStatus.Successful < 1 {
		t.Errorf("Expected at least 1 successful probe, got %d", report.CollectionStatus.Successful)
	}

	// Rule Engine Evaluation
	ruleEngine := analyzer.NewDefaultEngine()
	findings := ruleEngine.EvaluateAll(ctx, report)
	t.Logf("Evaluated %d findings against collected system state", len(findings))

	// Verify JSON export
	jsonFile := filepath.Join(resolvedDir, "report.json")
	jf, err := os.Create(jsonFile)
	if err != nil {
		t.Fatalf("Failed to create json report file: %v", err)
	}
	jsonRep := jsonReporter.NewReporter()
	if err := jsonRep.Generate(report, jf); err != nil {
		t.Fatalf("Failed to export JSON: %v", err)
	}
	jf.Close()

	jsonBytes, err := os.ReadFile(jsonFile)
	if err != nil {
		t.Fatalf("Failed to read back JSON file: %v", err)
	}
	restored, err := models.FromJSON(jsonBytes)
	if err != nil {
		t.Fatalf("Failed to parse saved JSON: %v", err)
	}
	if restored.SchemaVersion != "1.0.0" {
		t.Errorf("Expected SchemaVersion 1.0.0, got %s", restored.SchemaVersion)
	}

	// Verify HTML export
	htmlFile := filepath.Join(resolvedDir, "report.html")
	hf, err := os.Create(htmlFile)
	if err != nil {
		t.Fatalf("Failed to create html report file: %v", err)
	}
	htmlRep, err := htmlReporter.NewReporter()
	if err != nil {
		t.Fatalf("Failed to init HTML reporter: %v", err)
	}
	if err := htmlRep.Generate(report, hf); err != nil {
		t.Fatalf("Failed to export HTML: %v", err)
	}
	hf.Close()

	htmlBytes, err := os.ReadFile(htmlFile)
	if err != nil || len(htmlBytes) == 0 {
		t.Fatalf("HTML report file is empty or missing")
	}

	// Verify Terminal export
	termRep := termReporter.NewReporter()
	var termBuf filepath.WalkFunc // dummy
	_ = termBuf
	var outputBuffer = &models.DiagnosticReport{}
	_ = outputBuffer
	err = termRep.Generate(report, os.Stdout)
	if err != nil {
		t.Errorf("Terminal reporter failed: %v", err)
	}
}
