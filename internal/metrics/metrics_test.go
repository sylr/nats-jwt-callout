package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordAllowed(t *testing.T) {
	m := New()
	m.RecordAllowed(5 * time.Millisecond)
	m.RecordAllowed(5 * time.Millisecond)
	if got := testutil.ToFloat64(m.requests.WithLabelValues("allowed")); got != 2 {
		t.Errorf("allowed = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("denied")); got != 0 {
		t.Errorf("denied = %v, want 0", got)
	}
}

func TestRecordDenied(t *testing.T) {
	m := New()
	m.RecordDenied(ReasonNoToken, time.Millisecond)
	m.RecordDenied(ReasonVerificationFailed, time.Millisecond)
	m.RecordDenied(ReasonNoToken, time.Millisecond)
	if got := testutil.ToFloat64(m.requests.WithLabelValues("denied")); got != 3 {
		t.Errorf("denied total = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.denials.WithLabelValues(ReasonNoToken)); got != 2 {
		t.Errorf("denials[no_token] = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.denials.WithLabelValues(ReasonVerificationFailed)); got != 1 {
		t.Errorf("denials[verification_failed] = %v, want 1", got)
	}
}

func TestNilSafe(t *testing.T) {
	var m *Metrics // nil
	// Must not panic.
	m.RecordAllowed(time.Millisecond)
	m.RecordDenied(ReasonSigningFailed, time.Millisecond)
}

func TestHandlerExposesMetrics(t *testing.T) {
	m := New()
	m.RecordAllowed(time.Millisecond)

	body := scrape(t, m.Handler())
	for _, want := range []string{
		"nats_oidc_callout_authorization_requests_total",
		"nats_oidc_callout_authorization_duration_seconds",
		`nats_oidc_callout_authorization_requests_total{result="allowed"} 1`,
		"go_goroutines", // standard Go collector is registered
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}

func TestServeAndShutdown(t *testing.T) {
	m := New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Serve(ctx, ln, "/metrics", nil) }()

	url := "http://" + ln.Addr().String() + "/metrics"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(b), "nats_oidc_callout_authorization_requests_total") {
		t.Error("scraped body missing the requests metric")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after context cancel")
	}
}

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
