// Package k8sauth reads Kubernetes projected service-account tokens ready to
// hand to the NATS Go SDK, for authenticating to a NATS server protected by an
// auth-callout service that verifies Kubernetes OIDC tokens.
//
// # How the token is obtained
//
// Unlike a credential minted through an API, a projected service-account token
// is written to a file by the kubelet, which also rotates it in place well
// before expiry. This package therefore just reads that file; there is no API
// call and no Kubernetes client dependency. Point Config.TokenPath at a token
// projected with the audience your callout expects, e.g. a projected volume:
//
//	volumes:
//	- name: nats-token
//	  projected:
//	    sources:
//	    - serviceAccountToken:
//	        path: token
//	        audience: nats://callout
//	        expirationSeconds: 600
//
// mounted at, say, /var/run/secrets/nats/token. Do not use the default
// service-account token at DefaultServiceAccountTokenPath unless your callout
// is configured to accept its audience (the API server), which is usually not
// what you want — hence TokenPath is required.
//
// # Token lifetime and refresh
//
// NATS auth callout runs only at CONNECT; there is no in-band token refresh.
// The projected token is a one-shot connect credential the callout verifies and
// discards. The NATS user JWT the callout issues governs the live connection,
// and its expiry is capped to the token's own expiry. When that user JWT
// expires, the server closes the connection and the NATS client reconnects — and
// on every (re)connect the client re-invokes its token handler, which re-reads
// the file and so picks up the token the kubelet has since rotated in.
//
// For this reason [TokenSource.NATSOption] uses nats.TokenHandler (the file is
// re-read per connect), never a captured string. Callers must keep reconnection
// enabled (the nats.go default) for long-lived connections. Do not combine
// NATSOption with nats.Token or a token in the URL: nats.go returns
// ErrTokenAlreadySet if both are set.
//
// # Versioning
//
// This is a nested Go module. External consumers import it as
// github.com/sylr/nats-oidc-callout/lib/k8sauth and version it with
// subdirectory-prefixed tags (e.g. lib/k8sauth/vX.Y.Z), independent of the
// repository's root tags.
package k8sauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/nats-io/nats.go"
)

// DefaultServiceAccountTokenPath is the path of the default projected
// service-account token the kubelet mounts into every pod. Its audience is the
// API server, so it is typically NOT suitable for an auth-callout audience;
// project a token with the callout's audience and point Config.TokenPath there.
const DefaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// Config configures a TokenSource.
type Config struct {
	// TokenPath is the path to the projected service-account token file to read.
	// Required: there is no safe default, because the callout needs a token
	// projected with its own audience (see the package documentation).
	TokenPath string
}

// TokenSource reads Kubernetes projected service-account tokens from disk.
type TokenSource struct {
	path string

	mu      sync.Mutex
	lastErr error
}

// New builds a TokenSource that reads cfg.TokenPath. The file is not read or
// stat'd here — only on Token/NATSOption — so construction succeeds before the
// projected volume is necessarily populated.
func New(cfg Config) (*TokenSource, error) {
	if cfg.TokenPath == "" {
		return nil, errors.New("k8sauth: TokenPath is required")
	}
	return &TokenSource{path: cfg.TokenPath}, nil
}

// Token reads and returns the current token, trimming surrounding whitespace.
func (ts *TokenSource) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b, err := os.ReadFile(ts.path)
	if err != nil {
		return "", fmt.Errorf("k8sauth: read token file %q: %w", ts.path, err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("k8sauth: token file %q is empty", ts.path)
	}
	return tok, nil
}

// NATSOption returns a nats.Option that re-reads the token file on every
// (re)connect, picking up the kubelet's in-place rotation.
//
// nats.AuthTokenHandler is func() string — it cannot return an error — so a read
// failure yields an empty token (which fails the connect) and is recorded for
// retrieval via LastError; a successful read clears LastError. See the package
// documentation for the refresh model and the reconnect requirement.
func (ts *TokenSource) NATSOption() nats.Option {
	return nats.TokenHandler(func() string {
		tok, err := ts.Token(context.Background())
		ts.setLastError(err)
		if err != nil {
			return ""
		}
		return tok
	})
}

// LastError returns the most recent error from a NATSOption token read, or nil
// if the last read succeeded (or none has run yet).
func (ts *TokenSource) LastError() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.lastErr
}

func (ts *TokenSource) setLastError(err error) {
	ts.mu.Lock()
	ts.lastErr = err
	ts.mu.Unlock()
}
