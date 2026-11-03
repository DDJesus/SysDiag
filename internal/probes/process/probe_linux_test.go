//go:build linux

package process

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/systemdiag/sysdiag/internal/models"
)

func TestParseLinuxProcessStatNameAndClockConversion(t *testing.T) {
	fields := make([]string, 22)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[1] = "S", "7"
	fields[11], fields[12] = "30", "20"
	fields[17], fields[19], fields[21] = "4", "250", "8"
	stat := "123 (worker (pool) alpha) " + strings.Join(fields, " ")
	got, err := parseLinuxProcessStat(stat)
	if err != nil {
		t.Fatal(err)
	}
	if got.comm != "worker (pool) alpha" {
		t.Fatalf("comm = %q", got.comm)
	}
	if got.utime+got.stime != 50 || got.startTicks != 250 {
		t.Fatalf("unexpected ticks: %#v", got)
	}
	seconds, ok := ticksToSeconds(got.utime+got.stime, 250)
	if !ok || seconds != 0.2 {
		t.Fatalf("converted CPU time = %v, want 0.2 seconds", seconds)
	}
	if _, ok := ticksToSeconds(50, 0); ok {
		t.Fatal("zero clock ticks per second was accepted")
	}
}

func TestBuildProcessMetricsWithoutCPUTime(t *testing.T) {
	metrics := buildProcessMetrics([]models.ProcessSummary{
		{PID: 10, WorkingSetBytes: 100, CPUTimeSeconds: 0},
		{PID: 20, WorkingSetBytes: 300, CPUTimeSeconds: 0},
		{PID: 30, WorkingSetBytes: 200, CPUTimeSeconds: 0},
	}, 6, false)
	if metrics.TotalProcesses != 3 || metrics.TotalThreads != 6 {
		t.Fatalf("counts = (%d processes, %d threads), want (3, 6)", metrics.TotalProcesses, metrics.TotalThreads)
	}
	if len(metrics.TopCPU) != 0 {
		t.Fatalf("TopCPU = %#v, want no CPU ranking when unavailable", metrics.TopCPU)
	}
	if len(metrics.TopMemory) != 3 || metrics.TopMemory[0].PID != 20 || metrics.TopMemory[1].PID != 30 || metrics.TopMemory[2].PID != 10 {
		t.Fatalf("TopMemory order = %#v, want PIDs 20, 30, 10", metrics.TopMemory)
	}
	encoded, err := json.Marshal(metrics)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "cpu_time_seconds") || !strings.Contains(string(encoded), `"top_cpu":[]`) {
		t.Fatalf("unavailable CPU values were not omitted as expected: %s", encoded)
	}
}

func TestParseLinuxProcessStatRejectsMalformedRecords(t *testing.T) {
	for _, stat := range []string{"", "123 no-parens", "123 (truncated) S 1", "123 (bad) S 1 x"} {
		if _, err := parseLinuxProcessStat(stat); err == nil {
			t.Errorf("parseLinuxProcessStat(%q) succeeded, want error", stat)
		}
	}
}

func TestLinuxClockTicksHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := linuxClockTicks(ctx)
	if err == nil {
		t.Fatal("linuxClockTicks succeeded with canceled context")
	}
}
