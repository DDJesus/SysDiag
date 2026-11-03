package network

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/systemdiag/sysdiag/internal/collector"
	"github.com/systemdiag/sysdiag/internal/models"
)

func TestBoundedDNSTestInjectsLookupAndRetainsFailure(t *testing.T) {
	lookupErr := errors.New("synthetic resolver failure")
	result := runBoundedDNSTest(context.Background(), func(ctx context.Context, target string) ([]net.IPAddr, error) {
		if target != "example.com" {
			t.Errorf("query target = %q, want example.com", target)
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("DNS lookup context has no deadline")
		}
		if deadline.Sub(time.Now()) > 1500*time.Millisecond || deadline.Sub(time.Now()) < 0 {
			t.Errorf("DNS lookup deadline is not bounded to 1.5 seconds: %v", deadline)
		}
		return nil, lookupErr
	})
	if result.Success || result.QueryTarget != "example.com" || !strings.Contains(result.Error, lookupErr.Error()) {
		t.Fatalf("DNS result did not preserve the failed lookup: %#v", result)
	}
}

func TestNetworkCollectionFailurePreservesAdaptersAndDNSReason(t *testing.T) {
	metrics := &models.NetworkMetrics{
		Adapters: []models.NetworkAdapterMetrics{{Name: "synthetic-adapter"}},
		DNSTest:  &models.DNSResolutionTest{QueryTarget: "example.com", Error: "synthetic resolver failure"},
	}
	data, status, err := networkCollectionResult(metrics)
	if status != collector.StatusPartial || err == nil || !strings.Contains(err.Error(), "synthetic resolver failure") {
		t.Fatalf("got status %q and error %v; want Partial with DNS details", status, err)
	}
	got := data.(*models.NetworkMetrics)
	if len(got.Adapters) != 1 || got.Adapters[0].Name != "synthetic-adapter" || got.DNSTest.Error == "" {
		t.Fatalf("adapter data or DNS details were lost: %#v", got)
	}
}

func TestSuccessfulDNSObservationIsOnlyDNSCollectionSuccess(t *testing.T) {
	result := runBoundedDNSTest(context.Background(), func(_ context.Context, target string) ([]net.IPAddr, error) {
		if target != "example.com" {
			t.Errorf("query target = %q, want example.com", target)
		}
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
	})
	if !result.Success || result.QueryTarget != "example.com" {
		t.Fatalf("expected successful DNS observation, got %#v", result)
	}
	// The result carries only DNS resolution; it has no internet-connectivity field.
	if strings.Contains(strings.ToLower(result.QueryTarget), "internet") {
		t.Fatal("DNS observation was mislabeled as general internet connectivity")
	}
}
