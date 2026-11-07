package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/paulmalmquist/storage_relspace/internal/markings"
)

var policy = NewPolicy([]string{"SP-EXPT", "EXPT"})

func user(mod func(*Principal)) *Principal {
	p := &Principal{Subject: "u", Kind: KindUser, Scopes: NewSet("records:read", "blobs:read"), USPerson: true,
		CUIAccess: true, CUICategories: NewSet("SP-EXPT", "PROPIN"), Dissemination: NewSet()}
	if mod != nil {
		mod(p)
	}
	return p
}

func eval(p *Principal, a Action, banner string) Decision {
	m := markings.MustParse(banner)
	return policy.Evaluate(p, a, &m)
}

func TestPolicyRules(t *testing.T) {
	if d := eval(user(func(p *Principal) { p.Scopes = NewSet() }), RecordRead, "CUI//SP-EXPT"); d.Allowed || d.Conceal || !strings.Contains(d.Reason, "scope") {
		t.Errorf("missing scope: %+v", d)
	}
	if !eval(user(func(p *Principal) { p.CUIAccess = false }), RecordRead, "UNCONTROLLED").Allowed {
		t.Error("uncontrolled needs only scope")
	}
	if d := eval(user(func(p *Principal) { p.CUIAccess = false }), RecordRead, "CUI//SP-EXPT"); d.Allowed || !d.Conceal {
		t.Errorf("CUI access: %+v", d)
	}
	if d := eval(user(func(p *Principal) { p.USPerson = false }), RecordRead, "CUI//SP-EXPT"); d.Allowed || !strings.Contains(d.Reason, "U.S. person") {
		t.Errorf("export control: %+v", d)
	}
	if !eval(user(nil), RecordRead, "CUI//SP-EXPT").Allowed {
		t.Error("cleared U.S. person should read SP-EXPT")
	}
	if d := eval(user(func(p *Principal) { p.CUICategories = NewSet("PROPIN") }), RecordRead, "CUI//SP-EXPT"); d.Allowed || !strings.Contains(d.Reason, "SP-EXPT") {
		t.Errorf("category: %+v", d)
	}
	if eval(user(func(p *Principal) { p.USPerson = false }), RecordRead, "CUI//PROPIN//NOFORN").Allowed {
		t.Error("NOFORN requires U.S. person")
	}
	if eval(user(nil), RecordRead, "CUI//PROPIN//FEDCON").Allowed {
		t.Error("FEDCON must be authorized")
	}
	if !eval(user(func(p *Principal) { p.Dissemination = NewSet("FEDCON") }), RecordRead, "CUI//PROPIN//FEDCON").Allowed {
		t.Error("authorized FEDCON should pass")
	}
	star := user(func(p *Principal) { p.Scopes, p.CUICategories, p.Dissemination = NewSet("*"), NewSet("*"), NewSet("*") })
	if !eval(star, BlobShred, "CUI//SP-CTI/PRVCY//FEDCON").Allowed {
		t.Error("wildcards")
	}
}

func TestAgentContentWithheld(t *testing.T) {
	agent := user(func(p *Principal) { p.Kind = KindAgent })
	for _, a := range []Action{RecordReadContent, BlobReadContent} {
		if d := eval(agent, a, "CUI//SP-EXPT"); d.Allowed || !d.Withheld {
			t.Errorf("%s should be withheld: %+v", a, d)
		}
		if !eval(agent, a, "UNCONTROLLED").Allowed {
			t.Error("uncontrolled content is fine for agents")
		}
		cleared := user(func(p *Principal) { p.Kind, p.LLMBoundaryAuthorized = KindAgent, true })
		if !eval(cleared, a, "CUI//SP-EXPT").Allowed {
			t.Error("agent inside the boundary may read")
		}
	}
	if !eval(agent, RecordRead, "CUI//SP-EXPT").Allowed {
		t.Error("metadata stays visible")
	}
}

func TestDelegationIsIntersection(t *testing.T) {
	u := user(func(p *Principal) {
		p.Subject, p.USPerson, p.Scopes, p.CUICategories = "alice", false, NewSet("*"), NewSet("PROPIN")
	})
	agent := &Principal{Subject: "agent:x", Kind: KindAgent, Scopes: NewSet("records:read", "delegate"), USPerson: true,
		CUIAccess: true, CUICategories: NewSet("*"), Dissemination: NewSet("*"), LLMBoundaryAuthorized: true}
	eff := u.DelegatedTo(agent)
	if eff.Subject != "alice" || eff.Actor != "agent:x" || eff.Kind != KindAgent || eff.USPerson {
		t.Fatalf("identity: %+v", eff)
	}
	if len(eff.Scopes) != 1 || !eff.Scopes["records:read"] {
		t.Fatalf("scopes %v (delegate must not propagate)", eff.Scopes.Sorted())
	}
	if eval(eff, RecordRead, "CUI//SP-EXPT").Allowed || eval(eff, RecordUpdate, "CUI//PROPIN").Allowed {
		t.Fatal("delegation must not widen access")
	}
}

// ---- tokens -------------------------------------------------------------------------------------

var rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)

const iss, aud = "https://accounts.google.com", "https://strongbox.internal"

func googleToken(t *testing.T, mod func(jwt.MapClaims)) string {
	t.Helper()
	now := time.Now()
	c := jwt.MapClaims{"iss": iss, "aud": aud, "sub": "1234567890", "email": "svc-mes@proj.iam.gserviceaccount.com",
		"email_verified": true, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	if mod != nil {
		mod(c)
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodRS256, c).SignedString(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func oidc() *OIDCVerifier {
	return NewOIDCVerifierWithKeyfunc(func(*jwt.Token) (any, error) { return &rsaKey.PublicKey, nil }, iss, []string{aud}, 30*time.Second, 24*time.Hour)
}

func TestOIDC(t *testing.T) {
	ctx := context.Background()
	vt, err := oidc().Verify(ctx, googleToken(t, nil))
	if err != nil || vt.Subject != "svc-mes@proj.iam.gserviceaccount.com" {
		t.Fatalf("email mapping: %v %v", err, vt)
	}
	vt, _ = oidc().Verify(ctx, googleToken(t, func(c jwt.MapClaims) { c["email_verified"] = false }))
	if vt.Subject != "1234567890" {
		t.Fatal("unverified email must fall back to sub")
	}
	bad := []func(jwt.MapClaims){
		func(c jwt.MapClaims) { c["aud"] = "https://other" },
		func(c jwt.MapClaims) { c["iss"] = "https://evil.example" },
		func(c jwt.MapClaims) {
			c["iat"], c["exp"] = time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix()
		},
		func(c jwt.MapClaims) { c["exp"] = time.Now().Add(10 * 24 * time.Hour).Unix() },
		func(c jwt.MapClaims) { delete(c, "iat") },
	}
	for i, mod := range bad {
		if _, err := oidc().Verify(ctx, googleToken(t, mod)); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	hs, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": iss, "aud": aud, "sub": "x"}).SignedString([]byte(strings.Repeat("s", 40)))
	if _, err := oidc().Verify(ctx, hs); err == nil {
		t.Error("HS256 accepted by OIDC verifier (alg confusion)")
	}
}

func TestDevTokens(t *testing.T) {
	secret := strings.Repeat("s", 40)
	v := NewDevVerifier(secret, []string{"strongbox"}, 30*time.Second, 24*time.Hour)
	tok, _ := MintDevToken(secret, "alice", "strongbox", time.Hour)
	if vt, err := v.Verify(context.Background(), tok); err != nil || vt.Subject != "alice" {
		t.Fatalf("dev token: %v", err)
	}
	forged, _ := MintDevToken(strings.Repeat("t", 40), "alice", "strongbox", time.Hour)
	if _, err := v.Verify(context.Background(), forged); err == nil {
		t.Fatal("forged token accepted")
	}
}

func TestSpecValidation(t *testing.T) {
	if err := (&Spec{Subject: "x", Kind: KindUser, Scopes: []string{"root"}}).Validate(); err == nil {
		t.Error("unknown scope accepted")
	}
	if err := (&Spec{Subject: "x", Kind: KindUser, LLMBoundaryAuthorized: true}).Validate(); err == nil {
		t.Error("llm boundary on a user accepted")
	}
}

// "*" on both sides of a delegation must not resurrect scopes a delegation never carries.
func TestWildcardDelegationIsConcrete(t *testing.T) {
	both := &Principal{Subject: "u", Kind: KindUser, Scopes: NewSet("*"), CUICategories: NewSet("*")}
	agent := &Principal{Subject: "a", Kind: KindAgent, Scopes: NewSet("*")}
	d := both.DelegatedTo(agent)
	for _, s := range []string{"delegate", "principals:admin"} {
		if d.HasScope(s) {
			t.Fatalf("delegated principal has %s", s)
		}
	}
	if !d.HasScope("records:write") || d.Scopes["*"] {
		t.Fatalf("delegated scopes %v", d.Scopes.Sorted())
	}
	if dec := NewPolicy(nil).Evaluate(d, PrincipalAdmin, nil); dec.Allowed || dec.Code != CodeMissingScope {
		t.Fatalf("delegated wildcard reached principal admin: %+v", dec)
	}
}
