package authz

import (
	"testing"

	"github.com/sylr/nats-oidc-callout/internal/identity"
)

func celRule(expr string, allowBroad bool) *Policy {
	return &Policy{Rules: []Rule{{
		Name:  "cel",
		Match: Match{Expr: expr, AllowBroad: allowBroad},
		Grant: Grant{Account: "APP"},
	}}}
}

func TestCELMatch(t *testing.T) {
	p := celRule(`claims["repository_owner"] == "sylr"`, true)
	mustValidate(t, p)

	if _, err := p.Evaluate(id("repo:sylr/x", map[string]string{"repository_owner": "sylr"})); err != nil {
		t.Errorf("expected match: %v", err)
	}
	if _, err := p.Evaluate(id("repo:other/x", map[string]string{"repository_owner": "other"})); err == nil {
		t.Error("expected no match for different owner")
	}
}

func TestCELRequiresAllowBroad(t *testing.T) {
	p := celRule(`claims["repository_owner"] == "sylr"`, false)
	if err := p.Validate(); err == nil {
		t.Fatal("expr rule without allow_broad must fail validation")
	}
}

func TestCELInvalidSyntaxRejected(t *testing.T) {
	p := celRule(`claims[`, true)
	if err := p.Validate(); err == nil {
		t.Fatal("invalid CEL expr must fail validation")
	}
}

func TestCELNonBoolRejected(t *testing.T) {
	p := celRule(`claims["repository_owner"]`, true) // string, not bool
	if err := p.Validate(); err == nil {
		t.Fatal("non-bool CEL expr must fail validation")
	}
}

func TestCELAndedWithClaims(t *testing.T) {
	p := &Policy{Rules: []Rule{{
		Name: "cel",
		Match: Match{
			Claims:     map[string]string{"repository": "sylr/nats-oidc-callout"},
			Expr:       `claims["ref"].startsWith("refs/heads/")`,
			AllowBroad: true,
		},
		Grant: Grant{Account: "APP"},
	}}}
	mustValidate(t, p)

	match := id("s", map[string]string{"repository": "sylr/nats-oidc-callout", "ref": "refs/heads/main"})
	if _, err := p.Evaluate(match); err != nil {
		t.Errorf("expected match: %v", err)
	}
	// Claims match but expr fails (a tag, not a branch).
	tag := id("s", map[string]string{"repository": "sylr/nats-oidc-callout", "ref": "refs/tags/v1"})
	if _, err := p.Evaluate(tag); err == nil {
		t.Error("expected no match: ref is not a branch")
	}
	// Expr would match but claims don't (different repo).
	wrong := id("s", map[string]string{"repository": "sylr/other", "ref": "refs/heads/main"})
	if _, err := p.Evaluate(wrong); err == nil {
		t.Error("expected no match: different repository")
	}
}

func TestCELUsesIssAndAud(t *testing.T) {
	p := celRule(`iss == "https://issuer" && "nats://prod" in aud`, true)
	mustValidate(t, p)

	good := identity.New("s", nil)
	good.Issuer = "https://issuer"
	good.Audience = []string{"nats://prod", "other"}
	if _, err := p.Evaluate(good); err != nil {
		t.Errorf("expected match: %v", err)
	}

	bad := identity.New("s", nil)
	bad.Issuer = "https://issuer"
	bad.Audience = []string{"other"}
	if _, err := p.Evaluate(bad); err == nil {
		t.Error("expected no match: audience absent")
	}
}

func TestCELRuntimeErrorFailsClosed(t *testing.T) {
	// Indexing an absent claim is a CEL runtime error; the rule must fail closed
	// (treated as no match) rather than panic or match.
	p := celRule(`claims["absent"] == "x"`, true)
	mustValidate(t, p)
	if _, err := p.Evaluate(id("s", map[string]string{"present": "y"})); err == nil {
		t.Fatal("expected no match (fail closed) on CEL runtime error")
	}
}
