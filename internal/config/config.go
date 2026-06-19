// Package config loads and validates the callout service configuration and the
// authorization policy file.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sylr/nats-jwt-callout/internal/authz"
)

// Config is the top-level service configuration, loaded from a YAML file and
// optionally overridden by flags/env in cmd.
type Config struct {
	// NATS connection settings for the callout service itself.
	NATS NATSConfig `yaml:"nats"`

	// IssuerAccountSeed is the account nkey seed (SA…) used to sign response
	// user JWTs. Its public key must equal the server's auth_callout.issuer.
	IssuerAccountSeed string `yaml:"issuer_account_seed"`
	// XKeySeed is the curve seed (SX…) used to decrypt auth requests and
	// encrypt responses. Required when the server configures auth_callout.xkey.
	XKeySeed string `yaml:"xkey_seed"`

	// Audiences is the allowlist of acceptable token "aud" values. A token is
	// accepted only if at least one of its audiences is in this list.
	Audiences []string `yaml:"audiences"`

	// SigningAlgs is the allowlist of acceptable JWT signing algorithms
	// (e.g. RS256, ES384). Tokens signed with any other alg are rejected.
	SigningAlgs []string `yaml:"signing_algs"`

	// Issuers is the set of trusted OIDC issuers. A token's "iss" must match
	// one of these exactly; we never perform discovery against an unlisted
	// issuer.
	Issuers []IssuerConfig `yaml:"issuers"`

	// HTTPTimeout bounds OIDC discovery and JWKS fetches.
	HTTPTimeout time.Duration `yaml:"http_timeout"`

	// Policy is the authorization policy (loaded from PolicyFile if set,
	// otherwise inline).
	Policy     authz.Policy `yaml:"policy"`
	PolicyFile string       `yaml:"policy_file"`
}

// NATSConfig holds the callout service's own connection to NATS.
type NATSConfig struct {
	URL         string `yaml:"url"`
	Credentials string `yaml:"credentials"` // path to a .creds file
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	// TLS enables and configures TLS for the service connection. The AWS token
	// is a bearer credential, so TLS is strongly recommended.
	CACert     string `yaml:"ca_cert"`
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
}

// IssuerConfig binds a trusted issuer URL to required claim values.
type IssuerConfig struct {
	// URL is the exact OIDC issuer URL (matches the token "iss" and the
	// discovery document's issuer).
	URL string `yaml:"url"`
	// RequireClaims binds the issuer to specific claim values: every key must
	// equal the given value in the verified token (keys use the flattened
	// namespace, e.g. "aws.aws_account" or "repository_owner"). For GitHub,
	// owner-level binding alone is not sufficient — pin the repository in the
	// policy as well.
	RequireClaims map[string]string `yaml:"require_claims"`
}

// DefaultHTTPTimeout is used when HTTPTimeout is unset.
const DefaultHTTPTimeout = 10 * time.Second

// Load reads and validates the configuration from a YAML file. If PolicyFile is
// set, the policy is loaded from there and replaces any inline policy.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	if cfg.PolicyFile != "" {
		pol, err := authz.LoadPolicy(cfg.PolicyFile)
		if err != nil {
			return nil, err
		}
		cfg.Policy = *pol
	}

	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = DefaultHTTPTimeout
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks that the configuration is internally consistent and complete
// enough to start the service. It fails fast so a bad config never reaches the
// hot path.
func (c *Config) Validate() error {
	if c.NATS.URL == "" {
		return fmt.Errorf("nats.url is required")
	}
	if c.IssuerAccountSeed == "" {
		return fmt.Errorf("issuer_account_seed is required")
	}
	if len(c.Audiences) == 0 {
		return fmt.Errorf("at least one audience is required")
	}
	if len(c.SigningAlgs) == 0 {
		return fmt.Errorf("at least one signing_alg is required")
	}
	if len(c.Issuers) == 0 {
		return fmt.Errorf("at least one issuer is required")
	}
	for i, iss := range c.Issuers {
		if iss.URL == "" {
			return fmt.Errorf("issuers[%d].url is required", i)
		}
	}
	if err := c.Policy.Validate(); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	return nil
}
