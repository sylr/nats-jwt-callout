package e2e

import (
	"io"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"
)

// TestMetricsRecorded drives an authorized and a denied connection through the
// real callout path and asserts the Prometheus counters move accordingly.
func TestMetricsRecorded(t *testing.T) {
	h := setup(t, appPolicy(testARN), awsRequire)

	// Authorized connect.
	if _, err := h.connectClient(t, h.validToken(t)); err != nil {
		t.Fatalf("authorized connect: %v", err)
	}
	// Denied connect (no token).
	if _, err := h.connectClient(t, ""); err == nil {
		t.Fatal("expected the no-token connect to be rejected")
	}

	body := scrapeMetrics(t, h)

	if v := metricValue(t, body, `nats_oidc_callout_authorization_requests_total{result="allowed"}`); v < 1 {
		t.Errorf("allowed requests = %v, want >= 1\n%s", v, body)
	}
	if v := metricValue(t, body, `nats_oidc_callout_authorization_requests_total{result="denied"}`); v < 1 {
		t.Errorf("denied requests = %v, want >= 1", v)
	}
	if v := metricValue(t, body, `nats_oidc_callout_authorization_denials_total{reason="no_token"}`); v < 1 {
		t.Errorf("no_token denials = %v, want >= 1", v)
	}
}

func scrapeMetrics(t *testing.T, h *harness) string {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	h.metrics.Handler().ServeHTTP(rr, req)
	body, _ := io.ReadAll(rr.Result().Body)
	return string(body)
}

// metricValue extracts the float value of a fully-qualified metric line
// (name plus exact label set) from a Prometheus text exposition.
func metricValue(t *testing.T, body, line string) float64 {
	t.Helper()
	re := regexp.MustCompile("(?m)^" + regexp.QuoteMeta(line) + ` (\S+)$`)
	mm := re.FindStringSubmatch(body)
	if mm == nil {
		t.Fatalf("metric %q not found", line)
	}
	v, err := strconv.ParseFloat(mm[1], 64)
	if err != nil {
		t.Fatalf("parse %q value %q: %v", line, mm[1], err)
	}
	return v
}
