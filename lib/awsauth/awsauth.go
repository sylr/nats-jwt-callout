// Package awsauth mints AWS web identity tokens (via the STS GetWebIdentityToken
// API) ready to hand to the NATS Go SDK, for authenticating to a NATS server
// protected by an auth-callout service that verifies AWS OIDC tokens.
//
// # Token lifetime and refresh
//
// NATS auth callout runs only at CONNECT; there is no in-band token refresh.
// The AWS web identity token is a one-shot connect credential: the callout
// verifies it once and discards it. The NATS user JWT the callout issues back
// governs the live connection, and its expiry is capped to the AWS token's own
// expiry (typically a few minutes). When that user JWT expires, the server
// closes the connection with an authentication-expired error and the NATS
// client reconnects — and on every (re)connect the client re-invokes its token
// handler to obtain a fresh token.
//
// For this reason [TokenSource.NATSOption] uses nats.TokenHandler (a token is
// minted per connect), never a captured string. A static nats.Token would
// resend the same, now-expired token on reconnect; after two identical auth
// failures on the same server the client gives up reconnecting. Callers must
// therefore keep reconnection enabled (the nats.go default) for long-lived
// connections. Relevant nats.go knobs for resilience: nats.IgnoreAuthErrorAbort
// (keep retrying across auth errors, e.g. transient STS outages that yield an
// empty token), the usual reconnect settings, and nats.RetryOnFailedConnect for
// initial-connect resilience. Do not combine NATSOption with nats.Token or a
// token in the URL: nats.go returns ErrTokenAlreadySet if both are set.
//
// # Versioning
//
// This is a nested Go module. External consumers import it as
// github.com/sylr/nats-jwt-callout/lib/awsauth and version it with
// subdirectory-prefixed tags (e.g. lib/awsauth/vX.Y.Z), independent of the
// repository's root tags.
package awsauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/nats-io/nats.go"
)

// Defaults applied when the corresponding Config field is left zero.
const (
	// DefaultSigningAlgorithm is the JWT signing algorithm requested from STS.
	DefaultSigningAlgorithm = "RS256"
	// DefaultDuration is the requested token lifetime.
	DefaultDuration = 5 * time.Minute
	// DefaultFetchTimeout bounds a single token fetch performed by the
	// nats.Option when NATSOption is called with a non-positive timeout.
	DefaultFetchTimeout = 10 * time.Second
)

// STS GetWebIdentityToken accepts a requested lifetime in the 60s..3600s window.
// Validate against it so bad values fail locally instead of as a surprise 400.
const (
	minDuration = 60 * time.Second
	maxDuration = 3600 * time.Second

	// maxAudienceLen is the STS-documented maximum length of an audience value.
	maxAudienceLen = 1000
)

// supportedSigningAlgorithms are the JWT signing algorithms STS accepts for
// GetWebIdentityToken; an empty Config.SigningAlgorithm defaults to RS256.
var supportedSigningAlgorithms = map[string]struct{}{
	"RS256": {},
	"ES384": {},
}

// stsAPI is the subset of the STS client used here; an interface so tests can
// inject a fake without touching the network.
type stsAPI interface {
	GetWebIdentityToken(context.Context, *sts.GetWebIdentityTokenInput, ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

// Config configures a TokenSource.
type Config struct {
	// Audience is the token audience requested from STS. It must match an
	// audience the callout service allows. Required.
	Audience string
	// SigningAlgorithm is the JWT signing algorithm requested from STS.
	// Defaults to DefaultSigningAlgorithm ("RS256") when empty; when set it must
	// be one STS supports ("RS256" or "ES384").
	SigningAlgorithm string
	// Duration is the requested token lifetime, sent as DurationSeconds.
	// Defaults to DefaultDuration (5m) when zero. When set it must be a whole
	// number of seconds within the STS-allowed window (60s..3600s).
	Duration time.Duration
}

func (cfg Config) validate() error {
	if cfg.Audience == "" {
		return errors.New("awsauth: Audience is required")
	}
	if len(cfg.Audience) > maxAudienceLen {
		return fmt.Errorf("awsauth: Audience must be at most %d characters, got %d", maxAudienceLen, len(cfg.Audience))
	}
	if cfg.SigningAlgorithm != "" {
		if _, ok := supportedSigningAlgorithms[cfg.SigningAlgorithm]; !ok {
			return fmt.Errorf("awsauth: unsupported SigningAlgorithm %q (want RS256 or ES384)", cfg.SigningAlgorithm)
		}
	}
	if cfg.Duration != 0 {
		if cfg.Duration < minDuration || cfg.Duration > maxDuration {
			return fmt.Errorf("awsauth: Duration must be between %s and %s, got %s", minDuration, maxDuration, cfg.Duration)
		}
		if cfg.Duration%time.Second != 0 {
			return fmt.Errorf("awsauth: Duration must be a whole number of seconds, got %s", cfg.Duration)
		}
	}
	return nil
}

// TokenSource mints AWS web identity tokens.
type TokenSource struct {
	client           stsAPI
	audience         string
	signingAlgorithm string
	duration         time.Duration

	mu      sync.Mutex
	lastErr error
}

// New loads the default AWS config and builds an STS-backed TokenSource.
//
// Config is validated before any AWS work. A region must resolve from the
// environment or shared config: GetWebIdentityToken is not served on the global
// STS endpoint.
func New(ctx context.Context, cfg Config) (*TokenSource, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("awsauth: load AWS config: %w", err)
	}
	return NewFromAWSConfig(awsCfg, cfg)
}

// NewFromAWSConfig builds a TokenSource from a caller-supplied aws.Config, for
// callers that already have one (custom region, profile, credentials, endpoint
// resolver, ...). The same validation and region check as New apply.
func NewFromAWSConfig(awsCfg aws.Config, cfg Config) (*TokenSource, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if awsCfg.Region == "" {
		return nil, errors.New("awsauth: AWS region must be set; GetWebIdentityToken is not served on the global STS endpoint")
	}
	return newWithClient(sts.NewFromConfig(awsCfg), cfg)
}

// newWithClient validates cfg, applies defaults, and builds the TokenSource.
// It is the single seam tests use to inject a fake stsAPI.
func newWithClient(client stsAPI, cfg Config) (*TokenSource, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	alg := cfg.SigningAlgorithm
	if alg == "" {
		alg = DefaultSigningAlgorithm
	}
	dur := cfg.Duration
	if dur == 0 {
		dur = DefaultDuration
	}
	return &TokenSource{
		client:           client,
		audience:         cfg.Audience,
		signingAlgorithm: alg,
		duration:         dur,
	}, nil
}

// Token mints a fresh web identity token.
func (ts *TokenSource) Token(ctx context.Context) (string, error) {
	alg := ts.signingAlgorithm
	secs := int32(ts.duration / time.Second)
	out, err := ts.client.GetWebIdentityToken(ctx, &sts.GetWebIdentityTokenInput{
		Audience:         []string{ts.audience},
		SigningAlgorithm: &alg,
		DurationSeconds:  &secs,
	})
	if err != nil {
		return "", fmt.Errorf("awsauth: GetWebIdentityToken: %w", err)
	}
	if out == nil || out.WebIdentityToken == nil || *out.WebIdentityToken == "" {
		return "", errors.New("awsauth: STS returned an empty web identity token")
	}
	return *out.WebIdentityToken, nil
}

// NATSOption returns a nats.Option that mints a fresh token on every
// (re)connect, each fetch bounded by timeout (a non-positive timeout uses
// DefaultFetchTimeout).
//
// nats.AuthTokenHandler is func() string — it cannot return an error — so a
// fetch failure yields an empty token (which fails the connect) and is recorded
// for retrieval via LastError; a successful fetch clears LastError. See the
// package documentation for the refresh model and the reconnect requirement.
func (ts *TokenSource) NATSOption(timeout time.Duration) nats.Option {
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	return nats.TokenHandler(func() string {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		tok, err := ts.Token(ctx)
		ts.setLastError(err)
		if err != nil {
			return ""
		}
		return tok
	})
}

// LastError returns the most recent error from a NATSOption token fetch, or nil
// if the last fetch succeeded (or none has run yet).
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
