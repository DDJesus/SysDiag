//go:build darwin
// +build darwin

package software

import (
	"context"
	"fmt"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
)

func (p *Probe) collect(_ context.Context, _ time.Duration) (interface{}, collector.ProbeStatus, error) {
	return nil, collector.StatusUnsupported, fmt.Errorf("macOS installed software and runtime inventory is not implemented")
}
