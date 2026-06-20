package identity

import "testing"

func mustClaim(t *testing.T, id *Identity, name, want string) {
	t.Helper()
	got, ok := id.Claim(name)
	if !ok {
		t.Errorf("claim %q missing", name)
		return
	}
	if got != want {
		t.Errorf("claim %q = %q, want %q", name, got, want)
	}
}

func TestParseAWSNamespacedClaimsArePrefixed(t *testing.T) {
	payload := []byte(`{
		"iss": "https://abc.tokens.sts.global.api.aws",
		"sub": "arn:aws:iam::123456789012:role/DataRole",
		"aud": ["nats://prod"],
		"https://sts.amazonaws.com/": {
			"aws_account": "123456789012",
			"org_id": "o-abc1234567",
			"principal_tags": {"team": "data", "env": "prod"}
		}
	}`)
	id, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	mustClaim(t, id, "aws.aws_account", "123456789012")
	mustClaim(t, id, "aws.org_id", "o-abc1234567")
	mustClaim(t, id, "aws.principal_tags.team", "data")
	mustClaim(t, id, "aws.principal_tags.env", "prod")

	// Bare names must NOT exist — only the prefixed forms.
	if _, ok := id.Claim("aws_account"); ok {
		t.Error("bare aws_account must not be present (prefix collision risk)")
	}
}

func TestParseGitHubClaimsAreTopLevel(t *testing.T) {
	payload := []byte(`{
		"iss": "https://token.actions.githubusercontent.com",
		"sub": "repo:sylr/nats-jwt-callout:ref:refs/heads/main",
		"aud": "nats://ci",
		"repository": "sylr/nats-jwt-callout",
		"repository_owner": "sylr",
		"repository_id": 123456789,
		"ref": "refs/heads/main",
		"runner_environment": "github-hosted"
	}`)
	id, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	mustClaim(t, id, "repository", "sylr/nats-jwt-callout")
	mustClaim(t, id, "repository_owner", "sylr")
	mustClaim(t, id, "ref", "refs/heads/main")
	// Numeric claim is stringified exactly (no float64 .0 / precision drift).
	mustClaim(t, id, "repository_id", "123456789")
}

func TestParseReservedClaimsExcluded(t *testing.T) {
	id, err := Parse([]byte(`{"iss":"x","sub":"y","aud":"z","exp":1,"nbf":2,"iat":3,"repository":"r"}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, k := range []string{"iss", "sub", "aud", "exp", "nbf", "iat"} {
		if _, ok := id.Claim(k); ok {
			t.Errorf("reserved claim %q must be excluded from the generic claim map", k)
		}
	}
	mustClaim(t, id, "repository", "r")
}

func TestParseLargeNumericIDNoPrecisionLoss(t *testing.T) {
	// A value beyond float64's exact integer range must survive intact.
	id, err := Parse([]byte(`{"sub":"s","repository_id":9007199254740993}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	mustClaim(t, id, "repository_id", "9007199254740993")
}

func TestParseBool(t *testing.T) {
	id, _ := Parse([]byte(`{"sub":"s","flag":true}`))
	mustClaim(t, id, "flag", "true")
}

func TestParseMalformed(t *testing.T) {
	if _, err := Parse([]byte(`{nope`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestNewAndClaim(t *testing.T) {
	id := New("sub-value", map[string]string{"repository": "o/r"})
	if id.Subject != "sub-value" {
		t.Errorf("subject = %q", id.Subject)
	}
	mustClaim(t, id, "repository", "o/r")
	if _, ok := id.Claim("missing"); ok {
		t.Error("missing claim should not be present")
	}
}

func TestParseKubernetesNestedClaims(t *testing.T) {
	// A bound/projected k8s service-account token nests claims under the
	// "kubernetes.io" key; they must flatten with dotted paths.
	payload := []byte(`{
		"iss": "https://k8s.example.com",
		"sub": "system:serviceaccount:myns:myapp",
		"aud": ["nats://callout"],
		"kubernetes.io": {
			"namespace": "myns",
			"serviceaccount": {"name": "myapp", "uid": "abc-123"},
			"pod": {"name": "myapp-0"}
		}
	}`)
	id, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	mustClaim(t, id, "kubernetes.io.namespace", "myns")
	mustClaim(t, id, "kubernetes.io.serviceaccount.name", "myapp")
	mustClaim(t, id, "kubernetes.io.serviceaccount.uid", "abc-123")
	mustClaim(t, id, "kubernetes.io.pod.name", "myapp-0")
}
