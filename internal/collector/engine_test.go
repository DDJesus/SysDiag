package collector_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

type cancellationProbe struct {
	id      string
	started chan<- string
	calls   *atomic.Int32
}

type controlledProbe struct {
	id      string
	started chan<- string
	release <-chan struct{}
	active  *atomic.Int32
	peak    *atomic.Int32
}

type completionProbe struct {
	id       string
	started  chan<- string
	release  <-chan struct{}
	returned chan<- struct{}
}

func (p *controlledProbe) ID() string                        { return p.id }
func (p *controlledProbe) Name() string                      { return p.id }
func (p *controlledProbe) Category() collector.ProbeCategory { return collector.CategorySystem }
func (p *controlledProbe) RequiredPrivilege() collector.PrivilegeLevel {
	return collector.PrivilegeUser
}
func (p *controlledProbe) SupportedProfiles() []string { return []string{"all"} }
func (p *controlledProbe) Run(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	active := p.active.Add(1)
	defer p.active.Add(-1)
	for previous := p.peak.Load(); active > previous && !p.peak.CompareAndSwap(previous, active); previous = p.peak.Load() {
	}
	p.started <- p.id
	select {
	case <-p.release:
		return p.id, collector.StatusSuccess, nil
	case <-ctx.Done():
		return nil, collector.StatusFailed, ctx.Err()
	}
}

func (p *completionProbe) ID() string                        { return p.id }
func (p *completionProbe) Name() string                      { return p.id }
func (p *completionProbe) Category() collector.ProbeCategory { return collector.CategorySystem }
func (p *completionProbe) RequiredPrivilege() collector.PrivilegeLevel {
	return collector.PrivilegeUser
}
func (p *completionProbe) SupportedProfiles() []string { return []string{"all"} }
func (p *completionProbe) Run(context.Context, time.Duration) (interface{}, collector.ProbeStatus, error) {
	p.started <- p.id
	<-p.release
	p.returned <- struct{}{}
	return p.id, collector.StatusSuccess, nil
}

func (p *cancellationProbe) ID() string                        { return p.id }
func (p *cancellationProbe) Name() string                      { return p.id }
func (p *cancellationProbe) Category() collector.ProbeCategory { return collector.CategorySystem }
func (p *cancellationProbe) RequiredPrivilege() collector.PrivilegeLevel {
	return collector.PrivilegeUser
}
func (p *cancellationProbe) SupportedProfiles() []string { return []string{"all"} }
func (p *cancellationProbe) Run(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	p.calls.Add(1)
	p.started <- p.id
	<-ctx.Done()
	return nil, collector.StatusFailed, ctx.Err()
}

func TestEngine_CanceledBeforeExecutionSkipsProbes(t *testing.T) {
	var calls atomic.Int32
	started := make(chan string, 2)
	probes := []collector.Probe{
		&cancellationProbe{id: "first", started: started, calls: &calls},
		&cancellationProbe{id: "second", started: started, calls: &calls},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results := collector.NewEngine().Execute(ctx, probes, 0)
	if got := calls.Load(); got != 0 {
		t.Errorf("canceled execution started %d probes, want 0", got)
	}
	if len(results) != len(probes) {
		t.Fatalf("got %d results, want %d", len(results), len(probes))
	}
	for i, wantID := range []string{"first", "second"} {
		if results[i].ProbeID != wantID {
			t.Errorf("result %d is for %q, want %q", i, results[i].ProbeID, wantID)
		}
		if results[i].Status != collector.StatusSkipped {
			t.Errorf("result %d status is %q, want Skipped", i, results[i].Status)
		}
	}
}

func TestEngine_CancellationStopsQueuedProbes(t *testing.T) {
	var calls atomic.Int32
	started := make(chan string, 3)
	probes := []collector.Probe{
		&cancellationProbe{id: "first", started: started, calls: &calls},
		&cancellationProbe{id: "second", started: started, calls: &calls},
		&cancellationProbe{id: "third", started: started, calls: &calls},
	}
	ctx, cancel := context.WithCancel(context.Background())
	engine := collector.NewEngine(collector.WithMaxConcurrency(1))
	done := make(chan []collector.ProbeResult, 1)
	go func() { done <- engine.Execute(ctx, probes, 0) }()

	<-started // One probe is active; the remaining probes are queued behind the sole slot.
	cancel()
	results := <-done

	if got := calls.Load(); got != 1 {
		t.Errorf("cancellation started %d probes, want only the active probe", got)
	}
	if len(results) != len(probes) {
		t.Fatalf("got %d results, want %d", len(results), len(probes))
	}
	canceled, skipped := 0, 0
	for i, wantID := range []string{"first", "second", "third"} {
		if results[i].ProbeID != wantID {
			t.Errorf("result %d is for %q, want %q", i, results[i].ProbeID, wantID)
		}
		switch results[i].Status {
		case collector.StatusCanceled:
			canceled++
		case collector.StatusSkipped:
			skipped++
		default:
			t.Errorf("result %q has status %q, want Canceled or Skipped", wantID, results[i].Status)
		}
	}
	if canceled != 1 || skipped != 2 {
		t.Errorf("got %d canceled and %d skipped results, want 1 and 2", canceled, skipped)
	}

	report := models.NewDiagnosticReport()
	engine.Normalize(results, report)
	if report.CollectionStatus.Canceled != 1 || report.CollectionStatus.Skipped != 2 {
		t.Errorf("normalized cancellation counts are canceled=%d skipped=%d, want 1 and 2", report.CollectionStatus.Canceled, report.CollectionStatus.Skipped)
	}
	if report.CollectionStatus.Failed != 0 {
		t.Errorf("cancellation was counted as %d ordinary failures, want 0", report.CollectionStatus.Failed)
	}
}

func TestEngine_CancellationPreservesCompletedProbe(t *testing.T) {
	started := make(chan string, 2)
	releaseCompleted := make(chan struct{})
	returned := make(chan struct{}, 1)
	var calls atomic.Int32
	probes := []collector.Probe{
		&completionProbe{id: "completed", started: started, release: releaseCompleted, returned: returned},
		&cancellationProbe{id: "active", started: started, calls: &calls},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := collector.NewEngine(collector.WithMaxConcurrency(2))
	done := make(chan []collector.ProbeResult, 1)
	go func() { done <- engine.Execute(ctx, probes, 0) }()

	<-started
	<-started
	close(releaseCompleted)
	<-returned
	cancel()
	results := <-done
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].ProbeID != "completed" || results[0].Status != collector.StatusSuccess {
		t.Errorf("completed probe result = (%q, %q), want (completed, Success)", results[0].ProbeID, results[0].Status)
	}
	if results[1].ProbeID != "active" || results[1].Status != collector.StatusCanceled {
		t.Errorf("active probe result = (%q, %q), want (active, Canceled)", results[1].ProbeID, results[1].Status)
	}
}

func TestEngine_SuccessConcurrencyAndDeterministicResults(t *testing.T) {
	const concurrency = 2
	var active, peak atomic.Int32
	started := make(chan string, 6)
	release := make(chan struct{})
	probes := make([]collector.Probe, 6)
	for i := range probes {
		id := fmt.Sprintf("probe-%d", i)
		probes[i] = &controlledProbe{id: id, started: started, release: release, active: &active, peak: &peak}
	}

	done := make(chan []collector.ProbeResult, 1)
	engine := collector.NewEngine(collector.WithMaxConcurrency(concurrency))
	go func() { done <- engine.Execute(context.Background(), probes, 0) }()
	<-started
	<-started
	if got := active.Load(); got != concurrency {
		t.Fatalf("active probes after two starts = %d, want %d", got, concurrency)
	}
	close(release)
	results := <-done

	if got := peak.Load(); got > concurrency {
		t.Errorf("peak concurrency = %d, exceeds configured limit %d", got, concurrency)
	}
	if len(results) != len(probes) {
		t.Fatalf("got %d results, want %d", len(results), len(probes))
	}
	for i, result := range results {
		wantID := fmt.Sprintf("probe-%d", i)
		if result.ProbeID != wantID {
			t.Errorf("result %d is for %q, want %q", i, result.ProbeID, wantID)
		}
		if result.Status != collector.StatusSuccess {
			t.Errorf("result %q status is %q, want Success", wantID, result.Status)
		}
	}
}

func TestEngine_CooperativeProbeTimeout(t *testing.T) {
	started := make(chan string, 1)
	var calls atomic.Int32
	probe := &cancellationProbe{id: "timeout", started: started, calls: &calls}
	engine := collector.NewEngine(collector.WithProbeTimeout(20 * time.Millisecond))
	results := engine.Execute(context.Background(), []collector.Probe{probe}, 0)
	if calls.Load() != 1 {
		t.Fatalf("probe called %d times, want 1", calls.Load())
	}
	if len(results) != 1 || results[0].Status != collector.StatusTimeout {
		t.Fatalf("got results %#v, want one Timeout result", results)
	}
}

type mockProbe struct {
	id          string
	name        string
	category    collector.ProbeCategory
	privilege   collector.PrivilegeLevel
	profiles    []string
	delay       time.Duration
	data        interface{}
	status      collector.ProbeStatus
	err         error
	shouldPanic bool
}

func (m *mockProbe) ID() string                                  { return m.id }
func (m *mockProbe) Name() string                                { return m.name }
func (m *mockProbe) Category() collector.ProbeCategory           { return m.category }
func (m *mockProbe) RequiredPrivilege() collector.PrivilegeLevel { return m.privilege }
func (m *mockProbe) SupportedProfiles() []string                 { return m.profiles }
func (m *mockProbe) Run(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	if m.shouldPanic {
		panic("simulated critical probe panic")
	}
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, collector.StatusTimeout, ctx.Err()
		}
	}
	return m.data, m.status, m.err
}

func TestEngine_ConcurrencyAndTimeouts(t *testing.T) {
	probes := []collector.Probe{
		&mockProbe{
			id:        "probe_fast",
			name:      "Fast Probe",
			category:  collector.CategorySystem,
			privilege: collector.PrivilegeUser,
			status:    collector.StatusSuccess,
			data: &models.SystemMetrics{
				Hostname: "FAST-NODE",
			},
		},
		&mockProbe{
			id:        "probe_slow",
			name:      "Slow Probe",
			category:  collector.CategoryCPU,
			privilege: collector.PrivilegeUser,
			delay:     500 * time.Millisecond,
			status:    collector.StatusSuccess,
		},
		&mockProbe{
			id:          "probe_panic",
			name:        "Panicking Probe",
			category:    collector.CategoryMemory,
			privilege:   collector.PrivilegeUser,
			shouldPanic: true,
		},
		&mockProbe{
			id:        "probe_admin",
			name:      "Admin Only Probe",
			category:  collector.CategoryStorage,
			privilege: collector.PrivilegeAdmin,
			status:    collector.StatusRequiresAdmin,
			err:       errors.New("access denied"),
		},
	}

	// Engine configured with 100ms probe timeout (slow probe should timeout)
	engine := collector.NewEngine(
		collector.WithMaxConcurrency(2),
		collector.WithProbeTimeout(100*time.Millisecond),
	)

	report := models.NewDiagnosticReport()
	results := engine.Execute(context.Background(), probes, 50*time.Millisecond)

	if len(results) != 4 {
		t.Fatalf("Expected 4 results, got %d", len(results))
	}

	engine.Normalize(results, report)

	if report.CollectionStatus.TotalProbes != 4 {
		t.Errorf("Expected 4 total probes in status, got %d", report.CollectionStatus.TotalProbes)
	}
	if report.CollectionStatus.Successful != 1 {
		t.Errorf("Expected 1 successful probe, got %d", report.CollectionStatus.Successful)
	}
	if report.CollectionStatus.Timeout != 1 {
		t.Errorf("Expected 1 timed out probe, got %d", report.CollectionStatus.Timeout)
	}
	if report.CollectionStatus.Failed != 1 {
		t.Errorf("Expected 1 failed probe (panic), got %d", report.CollectionStatus.Failed)
	}
	if report.CollectionStatus.RequiresAdmin != 1 {
		t.Errorf("Expected 1 requires admin probe, got %d", report.CollectionStatus.RequiresAdmin)
	}

	if report.Data.System == nil || report.Data.System.Hostname != "FAST-NODE" {
		t.Errorf("Expected normalized system hostname FAST-NODE, got %v", report.Data.System)
	}
}

func TestEngine_EmptyProbes(t *testing.T) {
	engine := collector.NewEngine()
	results := engine.Execute(context.Background(), nil, 10*time.Millisecond)
	if results != nil {
		t.Errorf("Expected nil results for empty probes, got %v", results)
	}
}

func TestEngine_NormalizationStatuses(t *testing.T) {
	engine := collector.NewEngine()
	report := models.NewDiagnosticReport()

	results := []collector.ProbeResult{
		{
			ProbeID:  "p_success",
			Category: collector.CategorySystem,
			Status:   collector.StatusSuccess,
			Data:     &models.SystemMetrics{Hostname: "HOST-1"},
		},
		{
			ProbeID:  "p_partial",
			Category: collector.CategoryStorage,
			Status:   collector.StatusPartial,
			Data:     &models.StorageMetrics{},
		},
		{
			ProbeID:  "p_unsupported",
			Category: collector.CategoryReliability,
			Status:   collector.StatusUnsupported,
			Err:      errors.New("feature not available on Windows 7"),
		},
		{
			ProbeID:           "p_admin",
			Category:          collector.CategoryServices,
			Status:            collector.StatusRequiresAdmin,
			RequiredPrivilege: collector.PrivilegeAdmin,
			Err:               errors.New("requires admin"),
		},
		{
			ProbeID:  "p_timeout",
			Category: collector.CategoryNetwork,
			Status:   collector.StatusTimeout,
			Err:      errors.New("timed out"),
		},
		{
			ProbeID:  "p_failed",
			Category: collector.CategoryProcesses,
			Status:   collector.StatusFailed,
			Err:      errors.New("failed snapshot"),
		},
	}

	engine.Normalize(results, report)

	if report.CollectionStatus.TotalProbes != 6 {
		t.Errorf("Expected 6 total probes, got %d", report.CollectionStatus.TotalProbes)
	}
	if report.CollectionStatus.Successful != 1 {
		t.Errorf("Expected 1 successful, got %d", report.CollectionStatus.Successful)
	}
	if report.CollectionStatus.Partial != 1 {
		t.Errorf("Expected 1 partial, got %d", report.CollectionStatus.Partial)
	}
	if report.CollectionStatus.Unsupported != 1 {
		t.Errorf("Expected 1 unsupported, got %d", report.CollectionStatus.Unsupported)
	}
	if report.CollectionStatus.RequiresAdmin != 1 {
		t.Errorf("Expected 1 requires admin, got %d", report.CollectionStatus.RequiresAdmin)
	}
	if report.CollectionStatus.Timeout != 1 {
		t.Errorf("Expected 1 timeout, got %d", report.CollectionStatus.Timeout)
	}
	if report.CollectionStatus.Failed != 1 {
		t.Errorf("Expected 1 failed, got %d", report.CollectionStatus.Failed)
	}
	if len(report.Limitations) != 4 {
		t.Errorf("Expected 4 limitations recorded, got %d", len(report.Limitations))
	}
	if len(report.CollectionStatus.Probes) != 6 {
		t.Fatalf("Expected 6 probe records in collection_status.probes, got %d", len(report.CollectionStatus.Probes))
	}
	if report.CollectionStatus.Probes[0].ProbeID != "p_success" || report.CollectionStatus.Probes[0].Status != "Success" {
		t.Errorf("Expected first probe to be p_success / Success, got %v", report.CollectionStatus.Probes[0])
	}
	if report.CollectionStatus.Probes[1].ProbeID != "p_partial" || report.CollectionStatus.Probes[1].Status != "Partial" {
		t.Errorf("Expected second probe to be p_partial / Partial, got %v", report.CollectionStatus.Probes[1])
	}
	if report.CollectionStatus.Probes[3].PrivilegeRequired != "Administrator" {
		t.Errorf("Expected p_admin privilege requirement 'Administrator', got %q", report.CollectionStatus.Probes[3].PrivilegeRequired)
	}
}

func TestRegistry_Operations(t *testing.T) {
	reg := collector.NewRegistry()

	p1 := &mockProbe{
		id:        "p1",
		name:      "Probe 1",
		category:  collector.CategorySystem,
		privilege: collector.PrivilegeUser,
		profiles:  []string{"quick", "deep"},
	}
	p2 := &mockProbe{
		id:        "p2",
		name:      "Probe 2",
		category:  collector.CategoryStorage,
		privilege: collector.PrivilegeAdmin,
		profiles:  []string{"deep"},
	}
	p3 := &mockProbe{
		id:        "p3",
		name:      "Probe 3",
		category:  collector.CategorySoftware,
		privilege: collector.PrivilegeUser,
		profiles:  []string{"all"},
	}

	reg.Register(p1)
	reg.Register(p2)
	reg.Register(p3)

	if retrieved, ok := reg.Get("p1"); !ok || retrieved.ID() != "p1" {
		t.Errorf("Expected to get p1 from registry")
	}
	if _, ok := reg.Get("non_existent"); ok {
		t.Errorf("Expected non_existent probe not to be found")
	}

	all := reg.All()
	if len(all) != 3 {
		t.Errorf("Expected 3 probes in registry, got %d", len(all))
	}

	quickProbes := reg.ForProfile("quick")
	// quick should match p1 (quick) and p3 (all)
	if len(quickProbes) != 2 {
		t.Errorf("Expected 2 probes for quick profile, got %d", len(quickProbes))
	}

	deepProbes := reg.ForProfile("deep")
	// deep should match p1 (deep), p2 (deep), and p3 (all)
	if len(deepProbes) != 3 {
		t.Errorf("Expected 3 probes for deep profile, got %d", len(deepProbes))
	}

	// ForCategories test
	storageProbes := reg.ForCategories(collector.CategoryStorage)
	if len(storageProbes) != 1 || storageProbes[0].ID() != "p2" {
		t.Errorf("Expected only p2 for storage category, got %v", storageProbes)
	}

	multiCategory := reg.ForCategories(collector.CategorySystem, collector.CategorySoftware)
	if len(multiCategory) != 2 {
		t.Errorf("Expected 2 probes for system and software categories, got %d", len(multiCategory))
	}
}
