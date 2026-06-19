// Command nats-jwt-callout is a NATS auth callout service that authenticates
// clients using AWS Web Identity Tokens (from the STS GetWebIdentityToken API).
//
// The client passes its AWS web identity token as the NATS connection token. The
// server delegates authentication to this service, which verifies the token as
// an OIDC token, maps the AWS identity to a NATS account and permissions via a
// policy file, and returns a signed user JWT.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	callout "github.com/synadia-io/callout.go"

	authzcallout "github.com/sylr/nats-jwt-callout/internal/callout"
	"github.com/sylr/nats-jwt-callout/internal/config"
	"github.com/sylr/nats-jwt-callout/internal/verifier"
)

// Build metadata, injected by goreleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	configPath := flag.String("config", "", "path to the service config YAML (required)")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nats-jwt-callout %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	logger := newLogger(*logLevel)

	if *configPath == "" {
		logger.Error("missing required -config flag")
		os.Exit(2)
	}

	if err := run(logger, *configPath); err != nil {
		logger.Error("service exited with error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	signKey, err := nkeys.FromSeed([]byte(cfg.IssuerAccountSeed))
	if err != nil {
		return fmt.Errorf("load issuer account seed: %w", err)
	}

	var xkey nkeys.KeyPair
	if cfg.XKeySeed != "" {
		xkey, err = nkeys.FromSeed([]byte(cfg.XKeySeed))
		if err != nil {
			return fmt.Errorf("load xkey seed: %w", err)
		}
	}

	// Build the verifier (performs OIDC discovery) before connecting, so a bad
	// issuer config fails fast.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	issuers := make([]verifier.IssuerOption, 0, len(cfg.Issuers))
	for _, iss := range cfg.Issuers {
		issuers = append(issuers, verifier.IssuerOption{
			URL:           iss.URL,
			RequireClaims: iss.RequireClaims,
		})
	}
	v, err := verifier.New(ctx, verifier.Options{
		Issuers:     issuers,
		Audiences:   cfg.Audiences,
		SigningAlgs: cfg.SigningAlgs,
		HTTPTimeout: cfg.HTTPTimeout,
	})
	if err != nil {
		return err
	}

	nc, err := connectNATS(cfg.NATS)
	if err != nil {
		return fmt.Errorf("connect to NATS: %w", err)
	}
	defer nc.Close()
	logger.Info("connected to NATS", "url", nc.ConnectedUrl())

	authorizer := authzcallout.New(v, &cfg.Policy, signKey, logger)

	opts := []callout.Option{
		callout.Authorizer(authorizer.Authorize),
		callout.ResponseSignerKey(signKey),
	}
	if xkey != nil {
		opts = append(opts, callout.EncryptionKey(xkey))
	}

	svc, err := callout.NewAuthorizationService(nc, opts...)
	if err != nil {
		return fmt.Errorf("start callout service: %w", err)
	}
	defer func() { _ = svc.Stop() }()

	logger.Info("auth callout service started; waiting for requests")
	<-ctx.Done()
	logger.Info("shutting down")
	return nil
}

func connectNATS(cfg config.NATSConfig) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name("nats-jwt-callout"),
	}
	switch {
	case cfg.Credentials != "":
		opts = append(opts, nats.UserCredentials(cfg.Credentials))
	case cfg.Username != "":
		opts = append(opts, nats.UserInfo(cfg.Username, cfg.Password))
	}

	tlsCfg, err := tlsConfig(cfg)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		opts = append(opts, nats.Secure(tlsCfg))
	}

	return nats.Connect(cfg.URL, opts...)
}

func tlsConfig(cfg config.NATSConfig) (*tls.Config, error) {
	if cfg.ClientCert == "" && cfg.ClientKey == "" && cfg.CACert == "" {
		return nil, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		if cfg.ClientCert == "" || cfg.ClientKey == "" {
			return nil, errors.New("both client_cert and client_key are required for mTLS")
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		pem, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in CA cert %q", cfg.CACert)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
