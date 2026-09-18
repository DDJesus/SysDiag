package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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
	"github.com/systemdiag/sysdiag/internal/platform"
	htmlReporter "github.com/systemdiag/sysdiag/internal/reporter/html"
	jsonReporter "github.com/systemdiag/sysdiag/internal/reporter/json"
	termReporter "github.com/systemdiag/sysdiag/internal/reporter/terminal"
	"github.com/systemdiag/sysdiag/internal/sanitizer"
)

const (
	ToolVersion = "1.0.0"
)

func main() {
	profileFlag := flag.String("profile", "quick", "Diagnostic profile ('quick', 'deep')")
	outputDirFlag := flag.String("output-dir", "", "Directory to save diagnostic reports (default: current directory)")
	flag.StringVar(outputDirFlag, "o", "", "Alias for --output-dir")
	jsonOnlyFlag := flag.Bool("json-only", false, "Output canonical JSON only to stdout and suppress terminal dashboard")
	noHTMLFlag := flag.Bool("no-html", false, "Disable generation of standalone HTML report")
	sanitizeFlag := flag.Bool("sanitize", false, "Sanitize sensitive identifiers (hostnames, usernames) in output")
	pauseFlag := flag.Bool("pause", false, "Wait for Enter key before closing the terminal window")
	versionFlag := flag.Bool("version", false, "Show tool version")
	flag.BoolVar(versionFlag, "v", false, "Alias for --version")

	// Domain-specific probe filter flags
	storageFilter := flag.Bool("storage", false, "Execute storage & volume diagnostic probes only")
	networkFilter := flag.Bool("network", false, "Execute network & DNS diagnostic probes only")
	perfFilter := flag.Bool("perf", false, "Execute performance & resource diagnostic probes (CPU, Memory, Process, Storage)")
	servicesFilter := flag.Bool("services", false, "Execute service diagnostic probes only")
	inventoryFilter := flag.Bool("inventory", false, "Execute system & software inventory probes only")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Portable System Diagnostic Toolkit (sysdiag) v%s\n", ToolVersion)
		fmt.Fprintf(os.Stderr, "Read-Only Observational Diagnostic Utility for System Triage\n\n")
		fmt.Fprintf(os.Stderr, "Usage: sysdiag [flags]\n\nFlags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("sysdiag version %s (%s/%s)\n", ToolVersion, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	profile := strings.ToLower(strings.TrimSpace(*profileFlag))
	if profile != config.ProfileQuick && profile != config.ProfileDeep {
		profile = config.ProfileQuick
	}
	profCfg := config.GetProfileConfig(profile)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	scanStartTime := time.Now()

	// Privilege inspection
	isElevated, _ := platform.IsProcessElevated()
	privLevel := "User"
	if isElevated {
		if runtime.GOOS == "windows" {
			privLevel = "Administrator"
		} else {
			privLevel = "Root"
		}
	}

	execPath, err := os.Executable()
	if err != nil {
		execPath = os.Args[0]
	}

	// Resolve output directory with fallback
	resolvedOutDir, fellBack, err := config.ResolveOutputDir(*outputDirFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: unable to resolve output directory: %v\n", err)
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "UNKNOWN-HOST"
	}

	report := models.NewDiagnosticReport()
	report.Metadata = models.ExecutionMetadata{
		ToolVersion:     ToolVersion,
		ScanTimestamp:   scanStartTime.UTC(),
		Profile:         profile,
		Hostname:        hostname,
		OS:              runtime.GOOS,
		OSVersion:       runtime.GOOS,
		Architecture:    runtime.GOARCH,
		PrivilegeLevel:  privLevel,
		IsElevated:      isElevated,
		ExecutionPath:   execPath,
		OutputDirectory: resolvedOutDir,
	}

	if fellBack && !*jsonOnlyFlag {
		fmt.Fprintf(os.Stderr, "\n[Notice] Target output directory is read-only or inaccessible. Redirected output to: %s\n\n", resolvedOutDir)
	}

	// Register diagnostic probes
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

	// Select probes to run based on category flags or profile
	var probesToRun []collector.Probe
	var activeCategories []collector.ProbeCategory

	if *storageFilter {
		activeCategories = append(activeCategories, collector.CategoryStorage)
	}
	if *networkFilter {
		activeCategories = append(activeCategories, collector.CategoryNetwork)
	}
	if *perfFilter {
		activeCategories = append(activeCategories, collector.CategoryCPU, collector.CategoryMemory, collector.CategoryProcesses, collector.CategoryStorage)
	}
	if *servicesFilter {
		activeCategories = append(activeCategories, collector.CategoryServices)
	}
	if *inventoryFilter {
		activeCategories = append(activeCategories, collector.CategorySystem, collector.CategorySoftware)
	}

	if len(activeCategories) > 0 {
		probesToRun = registry.ForCategories(activeCategories...)
	} else {
		probesToRun = registry.ForProfile(profile)
	}

	if !*jsonOnlyFlag {
		fmt.Printf("Executing sysdiag [Profile: %s, Probes: %d, Privilege: %s]...\n",
			strings.ToUpper(profile), len(probesToRun), privLevel)
	}

	// Execute probes concurrently
	engine := collector.NewEngine(
		collector.WithMaxConcurrency(4),
		collector.WithProbeTimeout(profCfg.ProbeTimeout),
	)

	results := engine.Execute(ctx, probesToRun, profCfg.SampleDuration)
	engine.Normalize(results, report)

	// Update OS Version metadata from SystemMetrics if populated
	if report.Data.System != nil {
		report.Metadata.OSVersion = report.Data.System.OSName
		report.Metadata.Hostname = report.Data.System.Hostname
	}

	// Run rule evaluation
	ruleEngine := analyzer.NewDefaultEngine()
	ruleEngine.EvaluateAll(ctx, report)

	if *sanitizeFlag {
		sanitizer.SanitizeReport(report)
	}

	report.Metadata.ScanDurationMS = time.Since(scanStartTime).Milliseconds()

	// Handle JSON-only stdout mode
	if *jsonOnlyFlag {
		jsonRep := jsonReporter.NewReporter()
		if err := jsonRep.Generate(report, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting JSON: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Render Terminal Summary
	termRep := termReporter.NewReporter()
	_ = termRep.Generate(report, os.Stdout)

	// Export canonical JSON file
	timestampStr := scanStartTime.Format("20060102_150405")
	cleanHost := strings.ReplaceAll(report.Metadata.Hostname, " ", "_")
	jsonFilename := filepath.Join(resolvedOutDir, fmt.Sprintf("sysdiag_report_%s_%s.json", cleanHost, timestampStr))
	if f, err := os.Create(jsonFilename); err == nil {
		jsonRep := jsonReporter.NewReporter()
		_ = jsonRep.Generate(report, f)
		f.Close()
	} else {
		fmt.Fprintf(os.Stderr, "Warning: failed to save JSON report file: %v\n", err)
	}

	// Export HTML report
	var htmlFilename string
	if !*noHTMLFlag {
		htmlFilename = filepath.Join(resolvedOutDir, fmt.Sprintf("sysdiag_report_%s_%s.html", cleanHost, timestampStr))
		if htmlRep, err := htmlReporter.NewReporter(); err == nil {
			if f, err := os.Create(htmlFilename); err == nil {
				_ = htmlRep.Generate(report, f)
				f.Close()
			} else {
				fmt.Fprintf(os.Stderr, "Warning: failed to save HTML report file: %v\n", err)
			}
		}
	}

	// Handover guidance banner (Mom Test)
	fmt.Println()
	fmt.Println("================================================================================")
	fmt.Printf(" [SUCCESS] Diagnostic collection completed safely in %d ms.\n", report.Metadata.ScanDurationMS)
	fmt.Println(" Zero changes, modifications, or optimizations were performed on this machine.")
	fmt.Println("--------------------------------------------------------------------------------")
	if htmlFilename != "" {
		fmt.Println(" [!] WHAT TO SEND:")
		fmt.Println("     Please send this interactive HTML report to your technician or support team:")
		fmt.Printf("     --> %s\n\n", htmlFilename)
	}
	fmt.Println(" [*] Raw Machine Data (Canonical JSON):")
	fmt.Printf("     --> %s\n", jsonFilename)
	fmt.Println("================================================================================")

	// Check if we should pause for user acknowledgment (Mom Test double-click support)
	isDoubleClicked := platform.IsLaunchedFromExplorer()
	if *pauseFlag || isDoubleClicked {
		fmt.Println("\nPress Enter to exit...")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
