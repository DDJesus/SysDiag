//go:build windows
// +build windows

package reliability

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func (p *Probe) collect(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	timeWindowHours := 24
	maxRecords := 60

	if sampleDuration > 500*time.Millisecond {
		timeWindowHours = 72
		maxRecords = 150
	}

	metrics, err := winapi.GetReliabilityEvents(ctx, timeWindowHours, maxRecords)
	if err != nil {
		return nil, collector.StatusPartial, err
	}

	return metrics, collector.StatusSuccess, nil
}
