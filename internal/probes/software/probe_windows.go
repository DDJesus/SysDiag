//go:build windows
// +build windows

package software

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func (p *Probe) collect(ctx context.Context, sampleDuration time.Duration) (interface{}, collector.ProbeStatus, error) {
	metrics, err := winapi.GetSoftwareInventory()
	if err != nil {
		return nil, collector.StatusFailed, err
	}

	return metrics, collector.StatusSuccess, nil
}
