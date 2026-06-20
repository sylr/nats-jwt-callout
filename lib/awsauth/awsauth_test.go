package awsauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/nats-io/nats.go"
)

// fakeSTS is a concurrency-safe in-memory stsAPI. It records the last input,
// honours an already cancelled context (so timeout behaviour is observable),
// and returns either a canned token or a canned error.
type fakeSTS struct {
	mu    sync.Mutex
	in    *sts.GetWebIdentityTokenInput
	token string
	err   error
}

func (f *fakeSTS) GetWebIdentityToken(ctx context.Context, in *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	f.mu.Lock()
	f.in = in
	tok, fakeErr := f.token, f.err
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fakeErr != nil {
		return nil, fakeErr
	}
	return &sts.GetWebIdentityTokenOutput{WebIdentityToken: &tok}, nil
}

func (f *fakeSTS) lastInput() *sts.GetWebIdentityTokenInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.in
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"empty audience", Config{}, true},
		{"audience too long", Config{Audience: strings.Repeat("a", maxAudienceLen+1)}, true},
		{"valid default duration", Config{Audience: "aud"}, false},
		{"valid explicit duration", Config{Audience: "aud", Duration: 300 * time.Second}, false},
		{"duration min boundary", Config{Audience: "aud", Duration: minDuration}, false},
		{"duration max boundary", Config{Audience: "aud", Duration: maxDuration}, false},
		{"duration too small", Config{Audience: "aud", Duration: 30 * time.Second}, true},
		{"duration too large", Config{Audience: "aud", Duration: 2 * time.Hour}, true},
		{"duration negative", Config{Audience: "aud", Duration: -time.Second}, true},
		{"duration sub-second", Config{Audience: "aud", Duration: 1500 * time.Millisecond}, true},
		{"signing alg ES384", Config{Audience: "aud", SigningAlgorithm: "ES384"}, false},
		{"signing alg unsupported", Config{Audience: "aud", SigningAlgorithm: "HS256"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newWithClient(&fakeSTS{}, tc.cfg)
			if tc.wantErr != (err != nil) {
				t.Fatalf("newWithClient err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewValidatesBeforeAWS(t *testing.T) {
	// An empty Audience must fail without attempting to load AWS config.
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Fatal("expected error for empty Audience")
	}
}

func TestTokenDefaults(t *testing.T) {
	f := &fakeSTS{token: "tok"}
	ts, err := newWithClient(f, Config{Audience: "aud"})
	if err != nil {
		t.Fatalf("newWithClient: %v", err)
	}
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	in := f.lastInput()
	if got := in.Audience; len(got) != 1 || got[0] != "aud" {
		t.Errorf("Audience = %v, want [aud]", got)
	}
	if got := derefString(in.SigningAlgorithm); got != DefaultSigningAlgorithm {
		t.Errorf("SigningAlgorithm = %q, want %q", got, DefaultSigningAlgorithm)
	}
	if got := derefInt32(in.DurationSeconds); got != 300 {
		t.Errorf("DurationSeconds = %d, want 300", got)
	}
}

func TestTokenOverrides(t *testing.T) {
	f := &fakeSTS{token: "tok"}
	ts, err := newWithClient(f, Config{Audience: "aud", SigningAlgorithm: "ES384", Duration: 600 * time.Second})
	if err != nil {
		t.Fatalf("newWithClient: %v", err)
	}
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	in := f.lastInput()
	if got := derefString(in.SigningAlgorithm); got != "ES384" {
		t.Errorf("SigningAlgorithm = %q, want ES384", got)
	}
	if got := derefInt32(in.DurationSeconds); got != 600 {
		t.Errorf("DurationSeconds = %d, want 600", got)
	}
}

func TestNewFromAWSConfigRequiresRegion(t *testing.T) {
	if _, err := NewFromAWSConfig(aws.Config{}, Config{Audience: "aud"}); err == nil {
		t.Fatal("expected error when region is empty")
	}
	if _, err := NewFromAWSConfig(aws.Config{Region: "us-east-1"}, Config{Audience: "aud"}); err != nil {
		t.Fatalf("unexpected error with region set: %v", err)
	}
	// Config validation runs before the region check.
	if _, err := NewFromAWSConfig(aws.Config{}, Config{}); err == nil {
		t.Fatal("expected error for empty Audience")
	}
}

func TestNATSOptionConcurrent(t *testing.T) {
	ts := mustSource(t, &fakeSTS{token: "tok"}, Config{Audience: "aud"})
	opt := ts.NATSOption(time.Second)
	var opts nats.Options
	if err := opt(&opts); err != nil {
		t.Fatalf("apply option: %v", err)
	}

	// The token handler is invoked from reconnect goroutines; exercise it
	// concurrently so `go test -race` can catch unsynchronised state.
	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			if got := opts.TokenHandler(); got != "tok" {
				t.Errorf("handler token = %q, want tok", got)
			}
			_ = ts.LastError()
		}()
	}
	wg.Wait()
}

func TestTokenSuccess(t *testing.T) {
	ts := mustSource(t, &fakeSTS{token: "the-token"}, Config{Audience: "aud"})
	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != "the-token" {
		t.Errorf("Token = %q, want the-token", got)
	}
}

func TestTokenWrapsError(t *testing.T) {
	sentinel := errors.New("boom")
	ts := mustSource(t, &fakeSTS{err: sentinel}, Config{Audience: "aud"})
	_, err := ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error %v does not wrap sentinel", err)
	}
}

func TestTokenEmpty(t *testing.T) {
	ts := mustSource(t, &fakeSTS{token: ""}, Config{Audience: "aud"})
	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestNATSOptionSuccessClearsLastError(t *testing.T) {
	ts := mustSource(t, &fakeSTS{token: "tok"}, Config{Audience: "aud"})
	ts.setLastError(errors.New("stale"))

	// NATSOption(0) must default the timeout; with a non-positive timeout the
	// fetch context would be already cancelled and the fake would return "".
	if got := applyTokenHandler(t, ts.NATSOption(0)); got != "tok" {
		t.Fatalf("handler token = %q, want tok", got)
	}
	if err := ts.LastError(); err != nil {
		t.Errorf("LastError = %v, want nil after success", err)
	}
}

func TestNATSOptionRecordsError(t *testing.T) {
	ts := mustSource(t, &fakeSTS{err: errors.New("boom")}, Config{Audience: "aud"})
	if got := applyTokenHandler(t, ts.NATSOption(time.Second)); got != "" {
		t.Fatalf("handler token = %q, want empty on error", got)
	}
	if ts.LastError() == nil {
		t.Error("LastError = nil, want non-nil after failed fetch")
	}
}

func mustSource(t *testing.T, client stsAPI, cfg Config) *TokenSource {
	t.Helper()
	ts, err := newWithClient(client, cfg)
	if err != nil {
		t.Fatalf("newWithClient: %v", err)
	}
	return ts
}

// applyTokenHandler applies a nats.Option to an Options value and invokes the
// resulting token handler.
func applyTokenHandler(t *testing.T, opt nats.Option) string {
	t.Helper()
	var opts nats.Options
	if err := opt(&opts); err != nil {
		t.Fatalf("apply option: %v", err)
	}
	if opts.TokenHandler == nil {
		t.Fatal("TokenHandler not set")
	}
	return opts.TokenHandler()
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}
