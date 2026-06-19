package e2e

import "testing"

// TestPolicyReload drives a policy hot-swap through the full callout path: a
// reload to a non-matching policy denies a previously-authorized identity, and
// reloading back restores access — all on the same running NATS connection and
// callout service.
func TestPolicyReload(t *testing.T) {
	h := setup(t, appPolicy(testARN), awsRequire)

	// Initially authorized.
	if _, err := h.connectClient(t, h.validToken(t)); err != nil {
		t.Fatalf("initial connect should be authorized: %v", err)
	}

	// Reload to a policy that grants a different ARN → the same token is denied.
	denyPol := appPolicy("arn:aws:iam::123456789012:role/SomeoneElse")
	if err := denyPol.Validate(); err != nil {
		t.Fatalf("validate deny policy: %v", err)
	}
	h.authorizer.Reload(h.verifier, denyPol)
	if _, err := h.connectClient(t, h.validToken(t)); err == nil {
		t.Fatal("expected denial after reloading to a non-matching policy")
	}

	// Reload back to a granting policy → access restored.
	grantPol := appPolicy(testARN)
	if err := grantPol.Validate(); err != nil {
		t.Fatalf("validate grant policy: %v", err)
	}
	h.authorizer.Reload(h.verifier, grantPol)
	if _, err := h.connectClient(t, h.validToken(t)); err != nil {
		t.Fatalf("connect should be authorized again after reload: %v", err)
	}
}
