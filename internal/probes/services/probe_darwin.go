//go:build darwin
// +build darwin

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	return nil, collector.StatusUnsupported, fmt.Errorf("macOS service inventory is not implemented")
}
