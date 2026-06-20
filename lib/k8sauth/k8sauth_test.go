package k8sauth

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nats-io/nats.go"
)

func writeToken(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

func TestNewRequiresTokenPath(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty TokenPath")
	}
	if _, err := New(Config{TokenPath: "/some/path"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTokenReadsAndTrims(t *testing.T) {
	ts := mustSource(t, writeToken(t, "  the-token\n"))
	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != "the-token" {
		t.Errorf("Token = %q, want the-token", got)
	}
}

func TestTokenMissingFile(t *testing.T) {
	ts := mustSource(t, filepath.Join(t.TempDir(), "absent"))
	_, err := ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error %v does not wrap fs.ErrNotExist", err)
	}
}

func TestTokenEmptyFile(t *testing.T) {
	ts := mustSource(t, writeToken(t, "   \n\t"))
	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("expected error for empty/whitespace token file")
	}
}

func TestTokenHonoursContext(t *testing.T) {
	ts := mustSource(t, writeToken(t, "tok"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ts.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Token err = %v, want context.Canceled", err)
	}
}

// TestNATSOptionRefresh proves the handler re-reads the file, so an in-place
// rotation (as the kubelet performs) is picked up on the next (re)connect.
func TestNATSOptionRefresh(t *testing.T) {
	path := writeToken(t, "first")
	ts := mustSource(t, path)
	opts := applyOption(t, ts.NATSOption())

	if got := opts.TokenHandler(); got != "first" {
		t.Fatalf("handler token = %q, want first", got)
	}
	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("rotate token file: %v", err)
	}
	if got := opts.TokenHandler(); got != "second" {
		t.Fatalf("handler token after rotation = %q, want second", got)
	}
	if err := ts.LastError(); err != nil {
		t.Errorf("LastError = %v, want nil", err)
	}
}

func TestNATSOptionRecordsError(t *testing.T) {
	ts := mustSource(t, filepath.Join(t.TempDir(), "absent"))
	if got := applyOption(t, ts.NATSOption()).TokenHandler(); got != "" {
		t.Fatalf("handler token = %q, want empty on read error", got)
	}
	if ts.LastError() == nil {
		t.Error("LastError = nil, want non-nil after failed read")
	}
}

func TestNATSOptionConcurrent(t *testing.T) {
	ts := mustSource(t, writeToken(t, "tok"))
	opts := applyOption(t, ts.NATSOption())

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

func mustSource(t *testing.T, path string) *TokenSource {
	t.Helper()
	ts, err := New(Config{TokenPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ts
}

func applyOption(t *testing.T, opt nats.Option) *nats.Options {
	t.Helper()
	var opts nats.Options
	if err := opt(&opts); err != nil {
		t.Fatalf("apply option: %v", err)
	}
	if opts.TokenHandler == nil {
		t.Fatal("TokenHandler not set")
	}
	return &opts
}
