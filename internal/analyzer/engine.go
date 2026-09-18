package analyzer

import (
	"context"

	"github.com/systemdiag/sysdiag/internal/models"
)

// RuleEngine coordinates and executes diagnostic rules against the normalized model.
type RuleEngine struct {
	rules []Rule
}

// NewRuleEngine instantiates an empty rule engine.
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules: make([]Rule, 0),
	}
}

// NewDefaultEngine creates a rule engine pre-populated with default diagnostic rules across all domains.
func NewDefaultEngine() *RuleEngine {
	engine := NewRuleEngine()
	// System / CPU / Memory
	engine.Register(&CPUHighUtilizationRule{})
	engine.Register(&MemoryCommitExhaustionRule{})

	// Storage
	engine.Register(&StorageVolumeCapacityRule{})
	engine.Register(&StorageDiskQueueDepthRule{})

	// Network
	engine.Register(&NetworkInterfaceErrorsRule{})
	engine.Register(&NetworkDNSLatencyRule{})

	// Services
	engine.Register(&ServiceFailedAutoStartRule{})

	// Reliability & Event Logs
	engine.Register(&ReliabilityBugCheckRule{})
	engine.Register(&ReliabilityKernelPowerRule{})
	engine.Register(&ReliabilityAppCrashRule{})
	engine.Register(&ReliabilityDiskErrorsRule{})

	// Processes
	engine.Register(&ProcessHighResourceRule{})

	return engine
}

// Register registers a diagnostic rule.
func (e *RuleEngine) Register(r Rule) {
	e.rules = append(e.rules, r)
}

// EvaluateAll executes all registered rules against the report and populates Findings.
func (e *RuleEngine) EvaluateAll(ctx context.Context, report *models.DiagnosticReport) []models.Finding {
	allFindings := make([]models.Finding, 0)

	for _, r := range e.rules {
		findings, err := r.Evaluate(ctx, report)
		if err == nil && len(findings) > 0 {
			allFindings = append(allFindings, findings...)
		}
	}

	report.Findings = allFindings
	return allFindings
}
