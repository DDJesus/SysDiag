package collector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/systemdiag/sysdiag/internal/models"
)

// EngineOption configures execution parameters of the Collector Engine.
type EngineOption func(*Engine)

// WithMaxConcurrency sets the worker pool ceiling.
func WithMaxConcurrency(n int) EngineOption {
	return func(e *Engine) {
		if n > 0 {
			e.concurrency = n
		}
	}
}

// WithProbeTimeout sets the per-probe execution deadline.
func WithProbeTimeout(d time.Duration) EngineOption {
	return func(e *Engine) {
		if d > 0 {
			e.probeTimeout = d
		}
	}
}

// Engine coordinates concurrent execution of diagnostic probes.
type Engine struct {
	concurrency  int
	probeTimeout time.Duration
}

// NewEngine creates a configured probe execution engine.
func NewEngine(opts ...EngineOption) *Engine {
	e := &Engine{
		concurrency:  4,
		probeTimeout: 10 * time.Second,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Execute runs the given probes and returns collected raw results.
func (e *Engine) Execute(ctx context.Context, probes []Probe, sampleDuration time.Duration) []ProbeResult {
	if len(probes) == 0 {
		return nil
	}

	results := make([]ProbeResult, len(probes))
	sem := make(chan struct{}, e.concurrency)
	var wg sync.WaitGroup

	for i, p := range probes {
		wg.Add(1)
		go func(idx int, target Probe) {
			defer wg.Done()
			res := ProbeResult{
				ProbeID:           target.ID(),
				Name:              target.Name(),
				Category:          target.Category(),
				RequiredPrivilege: target.RequiredPrivilege(),
			}
			if ctx.Err() != nil {
				res.Status = StatusSkipped
				res.Err = context.Canceled
				results[idx] = res
				return
			}

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				res.Status = StatusSkipped
				res.Err = context.Canceled
				results[idx] = res
				return
			}
			defer func() { <-sem }()

			// The semaphore and cancellation cases may become ready together.
			// Recheck before starting so cancellation never starts another probe.
			if ctx.Err() != nil {
				res.Status = StatusSkipped
				res.Err = context.Canceled
				results[idx] = res
				return
			}

			start := time.Now()

			probeCtx, cancel := context.WithTimeout(ctx, e.probeTimeout)
			defer cancel()

			defer func() {
				if r := recover(); r != nil {
					res.Status = StatusFailed
					res.Err = fmt.Errorf("probe panic: %v", r)
					res.Duration = time.Since(start)
					results[idx] = res
				}
			}()

			data, status, err := target.Run(probeCtx, sampleDuration)
			finished := time.Now()
			res.Duration = finished.Sub(start)

			deadline, hasDeadline := probeCtx.Deadline()
			if probeCtx.Err() == context.DeadlineExceeded && hasDeadline && !finished.Before(deadline) {
				res.Status = StatusTimeout
				res.Err = fmt.Errorf("probe timed out after %v", e.probeTimeout)
			} else if status == StatusCanceled || errors.Is(err, context.Canceled) {
				res.Status = StatusCanceled
				res.Data = data
				res.Err = context.Canceled
			} else {
				res.Status = status
				res.Data = data
				res.Err = err
			}

			results[idx] = res
		}(i, p)
	}

	wg.Wait()
	return results
}

// Normalize applies collected probe results onto the normalized DiagnosticReport.
func (e *Engine) Normalize(results []ProbeResult, report *models.DiagnosticReport) {
	report.CollectionStatus.TotalProbes = len(results)
	report.CollectionStatus.Probes = make([]models.ProbeRecord, 0, len(results))

	for _, res := range results {
		rec := models.ProbeRecord{
			ProbeID:    res.ProbeID,
			Category:   string(res.Category),
			Name:       res.Name,
			Status:     string(res.Status),
			DurationMS: res.Duration.Milliseconds(),
		}
		if res.Err != nil {
			rec.Reason = res.Err.Error()
		}
		if res.RequiredPrivilege != "" {
			rec.PrivilegeRequired = string(res.RequiredPrivilege)
		}

		switch res.Status {
		case StatusSuccess:
			report.CollectionStatus.Successful++
		case StatusPartial:
			report.CollectionStatus.Partial++
			if res.Err != nil {
				limitationReason := fmt.Sprintf("Partial collection: %v", res.Err)
				if rec.Reason == "" {
					rec.Reason = limitationReason
				}
				report.Limitations = append(report.Limitations, models.CollectionLimitation{
					ProbeID:  res.ProbeID,
					Category: string(res.Category),
					Reason:   limitationReason,
				})
			}
		case StatusRequiresAdmin:
			report.CollectionStatus.RequiresAdmin++
			limitationReason := "Requires elevated administrator privileges"
			if res.Err != nil {
				limitationReason = fmt.Sprintf("Requires elevated administrator privileges: %v", res.Err)
			}
			if rec.Reason == "" {
				rec.Reason = limitationReason
			}
			report.Limitations = append(report.Limitations, models.CollectionLimitation{
				ProbeID:           res.ProbeID,
				Category:          string(res.Category),
				Reason:            limitationReason,
				PrivilegeRequired: string(res.RequiredPrivilege),
			})
		case StatusUnsupported:
			report.CollectionStatus.Unsupported++
			limitationReason := "Subsystem or platform unsupported"
			if res.Err != nil {
				limitationReason = fmt.Sprintf("Subsystem or platform unsupported: %v", res.Err)
			}
			if rec.Reason == "" {
				rec.Reason = limitationReason
			}
			report.Limitations = append(report.Limitations, models.CollectionLimitation{
				ProbeID:  res.ProbeID,
				Category: string(res.Category),
				Reason:   limitationReason,
			})
		case StatusTimeout:
			report.CollectionStatus.Timeout++
			limitationReason := "Probe execution timed out"
			if res.Err != nil {
				limitationReason = fmt.Sprintf("Probe execution timed out: %v", res.Err)
			}
			if rec.Reason == "" {
				rec.Reason = limitationReason
			}
			report.Limitations = append(report.Limitations, models.CollectionLimitation{
				ProbeID:  res.ProbeID,
				Category: string(res.Category),
				Reason:   limitationReason,
			})
		case StatusCanceled:
			report.CollectionStatus.Canceled++
			limitationReason := "Probe canceled by scan cancellation"
			if res.Err != nil {
				limitationReason = fmt.Sprintf("Probe canceled by scan cancellation: %v", res.Err)
			}
			if rec.Reason == "" {
				rec.Reason = limitationReason
			}
			report.Limitations = append(report.Limitations, models.CollectionLimitation{
				ProbeID: res.ProbeID, Category: string(res.Category), Reason: limitationReason,
			})
		case StatusSkipped:
			report.CollectionStatus.Skipped++
			limitationReason := "Probe not started because scan was canceled"
			if rec.Reason == "" {
				rec.Reason = limitationReason
			}
			report.Limitations = append(report.Limitations, models.CollectionLimitation{
				ProbeID: res.ProbeID, Category: string(res.Category), Reason: limitationReason,
			})
		case StatusFailed:
			fallthrough
		default:
			report.CollectionStatus.Failed++
			limitationReason := "Probe collection failed"
			if res.Err != nil {
				limitationReason = fmt.Sprintf("Probe collection failed: %v", res.Err)
			}
			if rec.Reason == "" {
				rec.Reason = limitationReason
			}
			report.Limitations = append(report.Limitations, models.CollectionLimitation{
				ProbeID:  res.ProbeID,
				Category: string(res.Category),
				Reason:   limitationReason,
			})
		}

		report.CollectionStatus.Probes = append(report.CollectionStatus.Probes, rec)

		// Normalize specific subsystem metrics if data is available
		if res.Data == nil {
			continue
		}

		switch typed := res.Data.(type) {
		case *models.SystemMetrics:
			report.Data.System = typed
		case *models.CPUMetrics:
			report.Data.CPU = typed
		case *models.MemoryMetrics:
			report.Data.Memory = typed
		case *models.StorageMetrics:
			report.Data.Storage = typed
		case *models.NetworkMetrics:
			report.Data.Network = typed
		case *models.ProcessMetrics:
			report.Data.Processes = typed
		case *models.ServicesMetrics:
			report.Data.Services = typed
		case *models.ReliabilityMetrics:
			report.Data.Reliability = typed
		case *models.SoftwareMetrics:
			report.Data.Software = typed
		}
	}
}
