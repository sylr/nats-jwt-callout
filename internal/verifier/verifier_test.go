package verifier_test

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/sylr/nats-jwt-callout/internal/mockoidc"
	"github.com/sylr/nats-jwt-callout/internal/verifier"
)

const (
	testAudience = "nats://prod"
	testAccount  = "123456789012"
	testARN      = "arn:aws:iam::123456789012:role/DataRole"
)

func newVerifier(t *testing.T, idp *mockoidc.Server, account string) *verifier.Verifier {
	t.Helper()
	var require map[string]string
	if account != "" {
		require = map[string]string{"aws.aws_account": account}
	}
	v, err := verifier.New(context.Background(), verifier.Options{
		Issuers:     []verifier.IssuerOption{{URL: idp.Issuer(), RequireClaims: require}},
		Audiences:   []string{testAudience},
		SigningAlgs: []string{oidc.RS256},
		HTTPTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	return v
}

func TestVerifyValidToken(t *testing.T) {
	idp := mockoidc.New(t)
	v := newVerifier(t, idp, testAccount)

	tok := idp.Mint(t, mockoidc.TokenOptions{
		Subject:       testARN,
		Audience:      []string{testAudience},
		AWSAccount:    testAccount,
		OrgID:         "o-abc",
		PrincipalTags: map[string]string{"env": "prod"},
	})
	id, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Subject != testARN {
		t.Errorf("subject = %q", id.Subject)
	}
	if acct, _ := id.Claim("aws.aws_account"); acct != testAccount {
		t.Errorf("aws.aws_account = %q", acct)
	}
	if org, _ := id.Claim("aws.org_id"); org != "o-abc" {
		t.Errorf("aws.org_id = %q", org)
	}
	if id.Expiry.IsZero() {
		t.Error("expiry should be set from the verified token")
	}
}

func TestVerifyGitHubShapedToken(t *testing.T) {
	idp := mockoidc.New(t)
	v, err := verifier.New(context.Background(), verifier.Options{
		Issuers: []verifier.IssuerOption{{
			URL:           idp.Issuer(),
			RequireClaims: map[string]string{"repository_owner": "sylr"},
		}},
		Audiences:   []string{testAudience},
		SigningAlgs: []string{oidc.RS256},
		HTTPTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	tok := idp.Mint(t, mockoidc.TokenOptions{
		Subject:  "repo:sylr/nats-jwt-callout:ref:refs/heads/main",
		Audience: []string{testAudience},
		ExtraClaims: map[string]any{
			"repository":       "sylr/nats-jwt-callout",
			"repository_owner": "sylr",
			"repository_id":    123456789,
			"ref":              "refs/heads/main",
		},
	})
	id, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if repo, _ := id.Claim("repository"); repo != "sylr/nats-jwt-callout" {
		t.Errorf("repository = %q", repo)
	}
	if rid, _ := id.Claim("repository_id"); rid != "123456789" {
		t.Errorf("repository_id = %q (want exact, no float drift)", rid)
	}

	// require_claims binding: a different owner is rejected.
	tok2 := idp.Mint(t, mockoidc.TokenOptions{
		Subject:     "repo:someoneelse/x:ref:refs/heads/main",
		Audience:    []string{testAudience},
		ExtraClaims: map[string]any{"repository_owner": "someoneelse"},
	})
	if _, err := v.Verify(context.Background(), tok2); err == nil {
		t.Fatal("expected rejection when repository_owner != required value")
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	idp := mockoidc.New(t)
	v := newVerifier(t, idp, testAccount)
	tok := idp.Mint(t, mockoidc.TokenOptions{Subject: testARN, Audience: []string{"nats://other"}, AWSAccount: testAccount})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected rejection for wrong audience")
	}
}

func TestVerifyAcceptsOneOfMultipleAudiences(t *testing.T) {
	idp := mockoidc.New(t)
	v := newVerifier(t, idp, testAccount)
	tok := idp.Mint(t, mockoidc.TokenOptions{Subject: testARN, Audience: []string{"nats://other", testAudience}, AWSAccount: testAccount})
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("expected acceptance when one audience matches: %v", err)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	idp := mockoidc.New(t)
	v := newVerifier(t, idp, testAccount)
	tok := idp.Mint(t, mockoidc.TokenOptions{
		Subject: testARN, Audience: []string{testAudience}, AWSAccount: testAccount,
		IssuedAt: time.Now().Add(-10 * time.Minute), Expiry: time.Now().Add(-5 * time.Minute),
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected rejection for expired token")
	}
}

func TestVerifyRejectsNotYetValidToken(t *testing.T) {
	idp := mockoidc.New(t)
	v := newVerifier(t, idp, testAccount)
	tok := idp.Mint(t, mockoidc.TokenOptions{
		Subject: testARN, Audience: []string{testAudience}, AWSAccount: testAccount,
		NotBefore: time.Now().Add(10 * time.Minute), Expiry: time.Now().Add(20 * time.Minute),
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected rejection for not-yet-valid token")
	}
}

func TestVerifyRejectsUntrustedIssuer(t *testing.T) {
	idp := mockoidc.New(t)
	v := newVerifier(t, idp, testAccount)
	tok := idp.Mint(t, mockoidc.TokenOptions{
		Subject: testARN, Audience: []string{testAudience}, AWSAccount: testAccount,
		IssuerOverride: "https://evil.example.com",
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected rejection for untrusted issuer")
	}
}

func TestVerifyRejectsAccountMismatch(t *testing.T) {
	idp := mockoidc.New(t)
	v := newVerifier(t, idp, testAccount) // expects 123456789012
	tok := idp.Mint(t, mockoidc.TokenOptions{Subject: testARN, Audience: []string{testAudience}, AWSAccount: "999999999999"})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected rejection for aws_account mismatch")
	}
}

func TestVerifyRejectsUnknownKid(t *testing.T) {
	idp := mockoidc.New(t)
	v := newVerifier(t, idp, testAccount)
	tok := idp.Mint(t, mockoidc.TokenOptions{
		Subject: testARN, Audience: []string{testAudience}, AWSAccount: testAccount,
		KidOverride: "nonexistent-kid",
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected rejection for unknown kid")
	}
}

func TestVerifyKeyRotation(t *testing.T) {
	idp := mockoidc.New(t)
	v := newVerifier(t, idp, testAccount)

	// Rotate to a new key and sign with it; the verifier should refresh JWKS
	// and accept the token.
	idp.AddKey(t, "key-2")
	idp.SetDefaultKey("key-2")
	tok := idp.Mint(t, mockoidc.TokenOptions{Subject: testARN, Audience: []string{testAudience}, AWSAccount: testAccount})
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("expected acceptance after key rotation: %v", err)
	}
}

func TestVerifyRejectsEmptyAndMalformed(t *testing.T) {
	idp := mockoidc.New(t)
	v := newVerifier(t, idp, testAccount)
	for _, tok := range []string{"", "not-a-jwt", "a.b", "a.b.c"} {
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Errorf("expected rejection for %q", tok)
		}
	}
}

func TestNewFailsOnUnreachableIssuer(t *testing.T) {
	_, err := verifier.New(context.Background(), verifier.Options{
		Issuers:     []verifier.IssuerOption{{URL: "http://127.0.0.1:1/unreachable"}},
		Audiences:   []string{testAudience},
		SigningAlgs: []string{oidc.RS256},
		HTTPTimeout: 1 * time.Second,
	})
	if err == nil {
		t.Fatal("expected discovery failure for unreachable issuer")
	}
}
