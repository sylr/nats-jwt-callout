package e2e

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/sylr/nats-jwt-callout/internal/mockoidc"
)

const (
	testARN     = "arn:aws:iam::123456789012:role/AppRole"
	testAccount = "123456789012"
)

// awsRequire binds the test issuer to the AWS account the mock tokens carry.
var awsRequire = map[string]string{"aws.aws_account": testAccount}

// validToken mints a token that should pass verification for the standard
// harness policy.
func (h *harness) validToken(t *testing.T) string {
	t.Helper()
	return h.idp.Mint(t, mockoidc.TokenOptions{
		Subject:    testARN,
		Audience:   []string{testAudience},
		AWSAccount: testAccount,
	})
}

func TestConnectAndPublishWithinGrant(t *testing.T) {
	h := setup(t, appPolicy(testARN), awsRequire)
	nc, err := h.connectClient(t, h.validToken(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Subscribe + publish within the granted "app.>" space.
	sub, err := nc.SubscribeSync("app.events")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := nc.Publish("app.events", []byte("hello")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("next msg: %v", err)
	}
	if string(msg.Data) != "hello" {
		t.Errorf("payload = %q", msg.Data)
	}
}

func TestPublishOutsideGrantDenied(t *testing.T) {
	h := setup(t, appPolicy(testARN), awsRequire)
	nc, err := h.connectClient(t, h.validToken(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Capture async permission-violation errors.
	errCh := make(chan error, 1)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) {
		select {
		case errCh <- e:
		default:
		}
	})

	// "forbidden.>" is outside the "app.>" grant.
	if err := nc.Publish("forbidden.topic", []byte("x")); err != nil {
		t.Fatalf("publish call: %v", err)
	}
	_ = nc.Flush()

	select {
	case e := <-errCh:
		if e == nil {
			t.Fatal("expected a permissions violation error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a permissions violation error, got none")
	}
}

func TestNoTokenRejected(t *testing.T) {
	h := setup(t, appPolicy(testARN), awsRequire)
	if _, err := h.connectClient(t, ""); err == nil {
		t.Fatal("expected connection rejection without a token")
	}
}

func TestMalformedTokenRejected(t *testing.T) {
	h := setup(t, appPolicy(testARN), awsRequire)
	if _, err := h.connectClient(t, "not-a-jwt"); err == nil {
		t.Fatal("expected rejection for malformed token")
	}
}

func TestWrongAudienceRejected(t *testing.T) {
	h := setup(t, appPolicy(testARN), awsRequire)
	tok := h.idp.Mint(t, mockoidc.TokenOptions{Subject: testARN, Audience: []string{"nats://other"}, AWSAccount: testAccount})
	if _, err := h.connectClient(t, tok); err == nil {
		t.Fatal("expected rejection for wrong audience")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	h := setup(t, appPolicy(testARN), awsRequire)
	tok := h.idp.Mint(t, mockoidc.TokenOptions{
		Subject: testARN, Audience: []string{testAudience}, AWSAccount: testAccount,
		IssuedAt: time.Now().Add(-10 * time.Minute), Expiry: time.Now().Add(-time.Minute),
	})
	if _, err := h.connectClient(t, tok); err == nil {
		t.Fatal("expected rejection for expired token")
	}
}

func TestUntrustedIssuerRejected(t *testing.T) {
	h := setup(t, appPolicy(testARN), awsRequire)
	tok := h.idp.Mint(t, mockoidc.TokenOptions{
		Subject: testARN, Audience: []string{testAudience}, AWSAccount: testAccount,
		IssuerOverride: "https://evil.example.com",
	})
	if _, err := h.connectClient(t, tok); err == nil {
		t.Fatal("expected rejection for untrusted issuer")
	}
}

func TestAWSAccountMismatchRejected(t *testing.T) {
	// Harness expects 123456789012, token carries a different account.
	h := setup(t, appPolicy(testARN), awsRequire)
	tok := h.idp.Mint(t, mockoidc.TokenOptions{Subject: testARN, Audience: []string{testAudience}, AWSAccount: "999999999999"})
	if _, err := h.connectClient(t, tok); err == nil {
		t.Fatal("expected rejection for aws_account mismatch")
	}
}

func TestUnmatchedPolicyRejected(t *testing.T) {
	// Policy only grants a different ARN.
	h := setup(t, appPolicy("arn:aws:iam::123456789012:role/SomeoneElse"), awsRequire)
	if _, err := h.connectClient(t, h.validToken(t)); err == nil {
		t.Fatal("expected rejection for identity with no matching rule")
	}
}

func TestAuthUserBypassesCallout(t *testing.T) {
	// The auth service user (and, by the same mechanism, system/service users
	// placed in auth_users) must connect without going through the callout.
	h := setup(t, appPolicy(testARN), awsRequire)
	nc, err := nats.Connect(h.srv.ClientURL(), nats.UserInfo(authUser, authPassword), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatalf("auth_users bypass connection failed: %v", err)
	}
	defer nc.Close()
	if !nc.IsConnected() {
		t.Fatal("expected auth user to be connected")
	}
}

func TestServerHealthyWithCallout(t *testing.T) {
	// The system account and server internals remain healthy while callout is
	// active.
	h := setup(t, appPolicy(testARN), awsRequire)
	if !h.srv.ReadyForConnections(2 * time.Second) {
		t.Fatal("server should be ready")
	}
	if h.srv.SystemAccount() == nil {
		t.Fatal("system account should be configured")
	}
}

func TestPolicyCapsExpiryToToken(t *testing.T) {
	// A short-lived AWS token must not yield a longer-lived NATS session; the
	// connection should drop near the token's expiry.
	h := setup(t, appPolicy(testARN), awsRequire)
	tok := h.idp.Mint(t, mockoidc.TokenOptions{
		Subject: testARN, Audience: []string{testAudience}, AWSAccount: testAccount,
		Expiry: time.Now().Add(2 * time.Second),
	})
	nc, err := h.connectClient(t, tok)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	closed := make(chan struct{})
	nc.SetClosedHandler(func(_ *nats.Conn) { close(closed) })
	nc.SetDisconnectErrHandler(func(_ *nats.Conn, _ error) {})

	select {
	case <-closed:
	case <-time.After(8 * time.Second):
		if nc.IsConnected() {
			t.Fatal("connection should have been closed at user JWT expiry")
		}
	}
}
