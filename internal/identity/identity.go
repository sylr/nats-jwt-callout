// Package identity models a verified OIDC identity in a provider-neutral way.
//
// After the verifier authenticates a token, its claim set is flattened into a
// string map that the authorization policy matches against. The model supports
// any OIDC provider (AWS STS web identity tokens, GitHub Actions, …) without
// provider-specific code on the hot path.
//
// Flattening rules (see Parse):
//   - Standard registered claims (iss/sub/aud/exp/nbf/iat) are EXCLUDED from the
//     generic claim map; they are matched only via verifier-validated fields, so
//     a policy can never match an unvalidated copy of, say, the subject.
//   - Numeric claims are decoded as json.Number and stringified exactly (no
//     float64 precision loss on IDs such as repository_id).
//   - The AWS namespace object ("https://sts.amazonaws.com/") is flattened under
//     the "aws." prefix (e.g. aws.aws_account, aws.principal_tags.env) so its
//     keys cannot collide with a top-level claim of the same bare name emitted by
//     a different trusted issuer.
package identity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Namespace is the JWT claim under which AWS nests its identity-specific claims.
const Namespace = "https://sts.amazonaws.com/"

// awsPrefix is the flattened-claim prefix for AWS-namespaced claims.
const awsPrefix = "aws"

// reserved registered claims are matched via verified fields, never via the
// generic claim map.
var reserved = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {},
}

// Identity is a verified OIDC identity. Issuer/Subject/Audience/Expiry are set by
// the verifier from the authenticated token; claims holds the flattened,
// matchable claim set.
type Identity struct {
	Issuer   string
	Subject  string
	Audience []string
	Expiry   time.Time

	claims map[string]string
}

// New builds an Identity directly (used by tests and programmatic callers).
func New(subject string, claims map[string]string) *Identity {
	if claims == nil {
		claims = map[string]string{}
	}
	return &Identity{Subject: subject, claims: claims}
}

// Claim returns the flattened claim value for name, if present.
func (i *Identity) Claim(name string) (string, bool) {
	v, ok := i.claims[name]
	return v, ok
}

// Parse flattens a verified token's JSON payload into a matchable claim set. It
// does not populate the first-class fields (Issuer/Subject/Audience/Expiry); the
// verifier sets those from the authenticated token. Parsing degrades gracefully:
// unexpected shapes are skipped rather than erroring, as long as the payload is
// valid JSON.
func Parse(payload []byte) (*Identity, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode token claims: %w", err)
	}

	claims := map[string]string{}
	for k, v := range raw {
		if _, isReserved := reserved[k]; isReserved {
			continue
		}
		prefix := k
		if k == Namespace {
			prefix = awsPrefix
		}
		flatten(prefix, v, claims)
	}
	return &Identity{claims: claims}, nil
}

// flatten writes scalar leaves of v into out under dotted keys rooted at prefix.
// Arrays are skipped (not matchable as scalars).
func flatten(prefix string, v any, out map[string]string) {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			flatten(prefix+"."+k, child, out)
		}
	case string:
		out[prefix] = val
	case json.Number:
		out[prefix] = val.String()
	case bool:
		out[prefix] = strconv.FormatBool(val)
	}
}
