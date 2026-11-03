//go:build windows
// +build windows

package storage

import (
	"context"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/winapi"
)

func (p *Probe) collect(ctx context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	vols, err := winapi.GetVolumes()
	if err != nil {
		return buildWindowsStorageResult(vols, nil, err, nil)
	}
	disks, diskErr := winapi.GetPhysicalDisks()
	return buildWindowsStorageResult(vols, disks, nil, diskErr)
}
