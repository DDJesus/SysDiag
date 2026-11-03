//go:build linux

package process

import (
	"context"
	"strings"
	"testing"
)

func TestParseLinuxProcessStatNameAndClockConversion(t *testing.T) {
	fields := make([]string, 22)
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
