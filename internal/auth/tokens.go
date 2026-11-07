package auth

import (
	"context"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

// DevIssuer is the issuer of development tokens (dev-hs256 mode only).
const DevIssuer = "strongbox-dev"

type VerifiedToken struct {
	Subject   string
	Issuer    string
	ExpiresAt time.Time
	Claims    jwt.MapClaims
}

// Verifier verifies bearer tokens.
//
//   - OIDCVerifier (production) checks RS256/ES256 JWTs against the issuer's JWKS. With the defaults it
//     accepts Google-signed ID tokens, which is how Cloud Run, GKE (Workload Identity) and IAP-fronted
//     users authenticate without shared secrets.
//   - DevVerifier uses a shared HS256 secret for local development. Production mode refuses it.
type Verifier interface {
	Verify(ctx context.Context, token string) (*VerifiedToken, error)
}

type baseRules struct {
	audiences   []string
	issuer      string
	leeway      time.Duration
	maxLifetime time.Duration
}

func (b baseRules) check(claims jwt.MapClaims) error {
	aud, err := claims.GetAudience()
	if err != nil {
		return errs.Unauthenticated("invalid token: bad audience claim")
	}
	ok := false
	for _, a := range aud {
		for _, want := range b.audiences {
			if a == want {
				ok = true
			}
		}
	}
	if !ok {
		return errs.Unauthenticated("invalid token: audience not accepted")
	}
	sub, _ := claims.GetSubject()
	if sub == "" {
		return errs.Unauthenticated("invalid token: missing subject")
	}
	exp, _ := claims.GetExpirationTime()
	iat, _ := claims.GetIssuedAt()
	if exp != nil && iat != nil && exp.Sub(iat.Time) > b.maxLifetime {
		return errs.Unauthenticated("token lifetime exceeds policy")
	}
	return nil
}

func (b baseRules) parse(token string, keyfn jwt.Keyfunc, methods []string, requireIAT bool) (*VerifiedToken, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(methods),
		jwt.WithIssuer(b.issuer),
		jwt.WithLeeway(b.leeway),
		jwt.WithExpirationRequired(),
	}
	if requireIAT {
		opts = append(opts, jwt.WithIssuedAt())
	}
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(token, claims, keyfn, opts...); err != nil {
		return nil, errs.Unauthenticated("invalid token: %v", err)
	}
	if requireIAT {
		if iat, _ := claims.GetIssuedAt(); iat == nil {
			return nil, errs.Unauthenticated("invalid token: missing iat")
		}
	}
	if err := b.check(claims); err != nil {
		return nil, err
	}
	sub, _ := claims.GetSubject()
	exp, _ := claims.GetExpirationTime()
	iss, _ := claims.GetIssuer()
	return &VerifiedToken{Subject: sub, Issuer: iss, ExpiresAt: exp.Time, Claims: claims}, nil
}

type DevVerifier struct {
	secret []byte
	rules  baseRules
}

func NewDevVerifier(secret string, audiences []string, leeway, maxLifetime time.Duration) *DevVerifier {
	return &DevVerifier{secret: []byte(secret), rules: baseRules{audiences, DevIssuer, leeway, maxLifetime}}
}

func (d *DevVerifier) Verify(_ context.Context, token string) (*VerifiedToken, error) {
	return d.rules.parse(token, func(*jwt.Token) (any, error) { return d.secret, nil }, []string{"HS256"}, false)
}

// MintDevToken issues a development token.
func MintDevToken(secret, subject, audience string, ttl time.Duration) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": subject, "aud": audience, "iss": DevIssuer, "iat": now.Unix(), "exp": now.Add(ttl).Unix(),
	}).SignedString([]byte(secret))
}

// OIDCVerifier verifies OIDC ID tokens. The principal subject is the verified email when present
// (Google service accounts and users), otherwise "sub".
type OIDCVerifier struct {
	keyfn jwt.Keyfunc
	rules baseRules
}

func NewOIDCVerifier(ctx context.Context, issuer, jwksURL string, audiences []string, leeway, maxLifetime time.Duration) (*OIDCVerifier, error) {
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, errs.Config("load JWKS from %s: %v", jwksURL, err)
	}
	return NewOIDCVerifierWithKeyfunc(kf.Keyfunc, issuer, audiences, leeway, maxLifetime), nil
}

func NewOIDCVerifierWithKeyfunc(kf jwt.Keyfunc, issuer string, audiences []string, leeway, maxLifetime time.Duration) *OIDCVerifier {
	return &OIDCVerifier{keyfn: kf, rules: baseRules{audiences, issuer, leeway, maxLifetime}}
}

func (o *OIDCVerifier) Verify(_ context.Context, token string) (*VerifiedToken, error) {
	vt, err := o.rules.parse(token, o.keyfn, []string{"RS256", "ES256"}, true)
	if err != nil {
		return nil, err
	}
	if email, _ := vt.Claims["email"].(string); email != "" {
		if verified, _ := vt.Claims["email_verified"].(bool); verified {
			vt.Subject = email
		}
	}
	return vt, nil
}
