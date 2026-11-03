package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/systemdiag/sysdiag/internal/analyzer"
	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/config"
	"github.com/systemdiag/sysdiag/internal/models"
	"github.com/systemdiag/sysdiag/internal/platform"
	"github.com/systemdiag/sysdiag/internal/probes/cpu"
	"github.com/systemdiag/sysdiag/internal/probes/memory"
	"github.com/systemdiag/sysdiag/internal/probes/network"
	"github.com/systemdiag/sysdiag/internal/probes/process"
	"github.com/systemdiag/sysdiag/internal/probes/reliability"
	"github.com/systemdiag/sysdiag/internal/probes/services"
	"github.com/systemdiag/sysdiag/internal/probes/software"
	"github.com/systemdiag/sysdiag/internal/probes/storage"
	"github.com/systemdiag/sysdiag/internal/probes/system"
	"github.com/systemdiag/sysdiag/internal/reporter"
	htmlReporter "github.com/systemdiag/sysdiag/internal/reporter/html"
	jsonReporter "github.com/systemdiag/sysdiag/internal/reporter/json"
	termReporter "github.com/systemdiag/sysdiag/internal/reporter/terminal"
	"github.com/systemdiag/sysdiag/internal/sanitizer"
)

const ToolVersion = "1.0.0"

type commandOptions struct {
	profile, outputDir                string
	jsonOnly, noHTML, sanitize, pause bool
	version                           bool
	storage, network, perf, services  bool
	inventory                         bool
}

type probeEngine interface {
	Execute(context.Context, []collector.Probe, time.Duration) []collector.ProbeResult
	Normalize([]collector.ProbeResult, *models.DiagnosticReport)
}

type ruleEvaluator interface {
	EvaluateAll(context.Context, *models.DiagnosticReport) []models.Finding
}

type dependencies struct {
	isElevated             func() (bool, error)
	executable             func() (string, error)
	hostname               func() (string, error)
	resolveOutputDir       func(string) (string, bool, error)
	probes                 func() []collector.Probe
	newProbeEngine         func(time.Duration) probeEngine
	newRuleEvaluator       func() ruleEvaluator
	sanitizeReport         func(*models.DiagnosticReport)
	jsonReporter           reporter.Reporter
	terminalReporter       reporter.Reporter
	newHTMLReporter        func() (reporter.Reporter, error)
	createFile             func(string) (io.WriteCloser, error)
	isLaunchedFromExplorer func() bool
}

func defaultDependencies() dependencies {
	return dependencies{
		isElevated:       platform.IsProcessElevated,
		executable:       os.Executable,
		hostname:         os.Hostname,
		resolveOutputDir: config.ResolveOutputDir,
		probes: func() []collector.Probe {
			return []collector.Probe{
				system.NewProbe(), cpu.NewProbe(), memory.NewProbe(), storage.NewProbe(),
				network.NewProbe(), process.NewProbe(), services.NewProbe(),
				reliability.NewProbe(), software.NewProbe(),
			}
		},
		newProbeEngine: func(timeout time.Duration) probeEngine {
			return collector.NewEngine(collector.WithMaxConcurrency(4), collector.WithProbeTimeout(timeout))
		},
		newRuleEvaluator: func() ruleEvaluator { return analyzer.NewDefaultEngine() },
		sanitizeReport:   sanitizer.SanitizeReport,
		jsonReporter:     jsonReporter.NewReporter(),
		terminalReporter: termReporter.NewReporter(),
		newHTMLReporter: func() (reporter.Reporter, error) {
			return htmlReporter.NewReporter()
		},
		createFile: func(path string) (io.WriteCloser, error) {
			return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		},
		isLaunchedFromExplorer: platform.IsLaunchedFromExplorer,
	}
}

func runCommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, deps dependencies) int {
	opts := commandOptions{}
	flags := flag.NewFlagSet("sysdiag", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.profile, "profile", "quick", "Diagnostic profile ('quick', 'deep')")
	flags.StringVar(&opts.outputDir, "output-dir", "", "Directory to save diagnostic reports (default: current directory)")
	flags.StringVar(&opts.outputDir, "o", "", "Alias for --output-dir")
	flags.BoolVar(&opts.jsonOnly, "json-only", false, "Output canonical JSON only to stdout and suppress terminal dashboard")
	flags.BoolVar(&opts.noHTML, "no-html", false, "Disable generation of standalone HTML report")
	flags.BoolVar(&opts.sanitize, "sanitize", false, "Sanitize sensitive identifiers (hostnames, usernames) in output")
	flags.BoolVar(&opts.pause, "pause", false, "Wait for Enter key before closing the terminal window")
	flags.BoolVar(&opts.version, "version", false, "Show tool version")
	flags.BoolVar(&opts.version, "v", false, "Alias for --version")
	flags.BoolVar(&opts.storage, "storage", false, "Execute storage & volume diagnostic probes only")
	flags.BoolVar(&opts.network, "network", false, "Execute network & DNS diagnostic probes only")
	flags.BoolVar(&opts.perf, "perf", false, "Execute performance & resource diagnostic probes (CPU, Memory, Process, Storage)")
	flags.BoolVar(&opts.services, "services", false, "Execute service diagnostic probes only")
	flags.BoolVar(&opts.inventory, "inventory", false, "Execute system & software inventory probes only")
	flags.Usage = func() {
		fmt.Fprintf(stderr, "Portable System Diagnostic Toolkit (sysdiag) v%s\n", ToolVersion)
		fmt.Fprintln(stderr, "Read-Only Observational Diagnostic Utility for System Triage")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Usage: sysdiag [flags]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Flags:")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if opts.version {
		fmt.Fprintf(stdout, "sysdiag version %s (%s/%s)\n", ToolVersion, runtime.GOOS, runtime.GOARCH)
		return 0
	}
	return run(ctx, opts, stdin, stdout, stderr, deps)
}

func run(ctx context.Context, opts commandOptions, stdin io.Reader, stdout, stderr io.Writer, deps dependencies) int {
	profile := strings.ToLower(strings.TrimSpace(opts.profile))
	if profile != config.ProfileQuick && profile != config.ProfileDeep {
		profile = config.ProfileQuick
	}
	profileConfig := config.GetProfileConfig(profile)
	scanStartTime := time.Now()

	isElevated, _ := deps.isElevated()
	privLevel := "User"
	if isElevated {
		if runtime.GOOS == "windows" {
			privLevel = "Administrator"
		} else {
			privLevel = "Root"
		}
	}

	execPath, err := deps.executable()
	if err != nil {
		execPath = os.Args[0]
	}
	resolvedOutDir, fellBack, err := deps.resolveOutputDir(opts.outputDir)
	if err != nil {
		fmt.Fprintf(stderr, "Warning: unable to resolve output directory: %v\n", err)
	}
	hostname, _ := deps.hostname()
	if hostname == "" {
		hostname = "UNKNOWN-HOST"
	}

	report := models.NewDiagnosticReport()
	report.Metadata = models.ExecutionMetadata{
		ToolVersion: ToolVersion, ScanTimestamp: scanStartTime.UTC(), Profile: profile,
		Hostname: hostname, OS: runtime.GOOS, OSVersion: runtime.GOOS,
		Architecture: runtime.GOARCH, PrivilegeLevel: privLevel, IsElevated: isElevated,
		ExecutionPath: execPath, OutputDirectory: resolvedOutDir,
	}
	if fellBack && !opts.jsonOnly {
		fmt.Fprintf(stderr, "\n[Notice] Target output directory is read-only or inaccessible. Redirected output to: %s\n\n", resolvedOutDir)
	}

	registry := collector.NewRegistry()
	for _, probe := range deps.probes() {
		registry.Register(probe)
	}
	probesToRun := selectProbes(registry, profile, opts)
	if !opts.jsonOnly {
		fmt.Fprintf(stdout, "Executing sysdiag [Profile: %s, Probes: %d, Privilege: %s]...\n",
			strings.ToUpper(profile), len(probesToRun), privLevel)
	}

	engine := deps.newProbeEngine(profileConfig.ProbeTimeout)
	results := engine.Execute(ctx, probesToRun, profileConfig.SampleDuration)
	engine.Normalize(results, report)
	scanCanceled := report.CollectionStatus.Canceled > 0 || report.CollectionStatus.Skipped > 0
	if report.Data.System != nil {
		report.Metadata.OSVersion = report.Data.System.OSName
		report.Metadata.Hostname = report.Data.System.Hostname
	}
	deps.newRuleEvaluator().EvaluateAll(ctx, report)
	if opts.sanitize {
		deps.sanitizeReport(report)
	}
	report.Metadata.ScanDurationMS = time.Since(scanStartTime).Milliseconds()

	if opts.jsonOnly {
		if err := deps.jsonReporter.Generate(report, stdout); err != nil {
			fmt.Fprintf(stderr, "Error exporting JSON: %v\n", err)
			return 1
		}
		if scanCanceled {
			return 1
		}
		return 0
	}
	if err := deps.terminalReporter.Generate(report, stdout); err != nil {
		fmt.Fprintf(stderr, "Warning: failed to render terminal summary: %v\n", err)
	}

	timestamp := scanStartTime.Format("20060102_150405")
	cleanHost := strings.ReplaceAll(report.Metadata.Hostname, " ", "_")
	jsonPath := filepath.Join(resolvedOutDir, fmt.Sprintf("sysdiag_report_%s_%s.json", cleanHost, timestamp))
	jsonErr := writeReportFile(jsonPath, "JSON", deps.jsonReporter, report, deps.createFile)
	if jsonErr != nil {
		fmt.Fprintf(stderr, "Error: %v\n", jsonErr)
	}

	var htmlFilename string
	var htmlErr error
	if !opts.noHTML {
		htmlFilename = filepath.Join(resolvedOutDir, fmt.Sprintf("sysdiag_report_%s_%s.html", cleanHost, timestamp))
		htmlRep, err := deps.newHTMLReporter()
		if err != nil {
			htmlErr = fmt.Errorf("failed to initialize HTML reporter: %w", err)
			fmt.Fprintf(stderr, "Error: %v\n", htmlErr)
			htmlFilename = ""
		} else {
			if err := writeReportFile(htmlFilename, "HTML", htmlRep, report, deps.createFile); err != nil {
				htmlErr = err
				fmt.Fprintf(stderr, "Error: %v\n", err)
				htmlFilename = ""
			}
		}
	}

	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "================================================================================")
	if scanCanceled {
		fmt.Fprintf(stdout, " [INCOMPLETE] Diagnostic collection canceled after %d ms. Partial results were saved.\n", report.Metadata.ScanDurationMS)
		fmt.Fprintf(stdout, " Canceled probes: %d; not started: %d.\n", report.CollectionStatus.Canceled, report.CollectionStatus.Skipped)
	} else if jsonErr != nil || htmlErr != nil {
		fmt.Fprintln(stdout, " [INCOMPLETE] Diagnostic collection completed, but required report artifact generation failed; partial results were retained.")
	} else {
		fmt.Fprintf(stdout, " [SUCCESS] Diagnostic collection completed safely in %d ms.\n", report.Metadata.ScanDurationMS)
	}
	fmt.Fprintln(stdout, " Zero changes, modifications, or optimizations were performed on this machine.")
	fmt.Fprintln(stdout, "--------------------------------------------------------------------------------")
	if htmlFilename != "" {
		fmt.Fprintln(stdout, " [!] WHAT TO SEND:")
		fmt.Fprintln(stdout, "     Please send this interactive HTML report to your technician or support team:")
		fmt.Fprintf(stdout, "     --> %s\n\n", htmlFilename)
	}
	if jsonErr == nil {
		fmt.Fprintln(stdout, " [*] Raw Machine Data (Canonical JSON):")
		fmt.Fprintf(stdout, "     --> %s\n", jsonPath)
	}
	fmt.Fprintln(stdout, "================================================================================")
	if opts.pause || deps.isLaunchedFromExplorer() {
		fmt.Fprintln(stdout, "\nPress Enter to exit...")
		_, _ = bufio.NewReader(stdin).ReadString('\n')
	}
	if scanCanceled {
		return 1
	}
	if jsonErr != nil || htmlErr != nil {
		return 1
	}
	return 0
}

func selectProbes(registry *collector.Registry, profile string, opts commandOptions) []collector.Probe {
	var categories []collector.ProbeCategory
	if opts.storage {
		categories = append(categories, collector.CategoryStorage)
	}
	if opts.network {
		categories = append(categories, collector.CategoryNetwork)
	}
	if opts.perf {
		categories = append(categories, collector.CategoryCPU, collector.CategoryMemory, collector.CategoryProcesses, collector.CategoryStorage)
	}
	if opts.services {
		categories = append(categories, collector.CategoryServices)
	}
	if opts.inventory {
		categories = append(categories, collector.CategorySystem, collector.CategorySoftware)
	}
	if len(categories) > 0 {
		return registry.ForCategories(categories...)
	}
	return registry.ForProfile(profile)
}

func writeReportFile(path, format string, rep reporter.Reporter, report *models.DiagnosticReport, createFile func(string) (io.WriteCloser, error)) error {
	f, err := createFile(path)
	if err != nil {
		return fmt.Errorf("failed to save %s report: %w", format, err)
	}
	var createdInfo os.FileInfo
	if owned, ok := f.(*os.File); ok {
		createdInfo, _ = owned.Stat()
	}
	generateErr := rep.Generate(report, f)
	closeErr := f.Close()
	if generateErr != nil {
		generateErr = fmt.Errorf("failed to write %s report: %w", format, generateErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("failed to close %s report: %w", format, closeErr)
	}
	combined := errors.Join(generateErr, closeErr)
	if combined != nil {
		if createdInfo != nil {
			if current, pathErr := os.Stat(path); pathErr == nil && os.SameFile(createdInfo, current) {
				_ = os.Remove(path)
			}
		}
	}
	return combined
}
