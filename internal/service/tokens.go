package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"identity_service/internal/clock"
	"identity_service/internal/models"
)

// TokenIssuer signs and verifies short-lived access tokens (RS256, kid header)
// and is verified locally by peer services through the published JWKS.
type TokenIssuer struct {
	keys     *KeyManager
	issuer   string
	audience string
	ttl      time.Duration
	clock    clock.Clock
}

// NewTokenIssuer builds an access-token issuer.
func NewTokenIssuer(keys *KeyManager, issuer, audience string, ttl time.Duration, clk clock.Clock) *TokenIssuer {
	return &TokenIssuer{keys: keys, issuer: issuer, audience: audience, ttl: ttl, clock: clk}
}

// accessTokenClaims is the claim set of an access token: sub, sid,
// email_verified, exp, iat, iss, aud.
type accessTokenClaims struct {
	SessionID     string `json:"sid"`
	EmailVerified bool   `json:"email_verified"`
	jwt.RegisteredClaims
}

// Issue signs an access token for the user and session and returns it with its
// lifetime in seconds.
func (t *TokenIssuer) Issue(ctx context.Context, user *models.User, sessionID string) (string, int, error) {
	kid, key, err := t.keys.Current(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("service: load signing key: %w", err)
	}
	now := t.clock.Now()
	claims := accessTokenClaims{
		SessionID:     sessionID,
		EmailVerified: user.EmailVerified,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			Issuer:    t.issuer,
			Audience:  jwt.ClaimStrings{t.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(t.ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		return "", 0, fmt.Errorf("service: sign access token: %w", err)
	}
	return signed, int(t.ttl.Seconds()), nil
}

// ErrInvalidAccessToken is returned for any access token that fails validation.
var ErrInvalidAccessToken = errors.New("service: invalid access token")

// Verify validates the signature (against the published key set), issuer,
// audience and expiry of an access token and returns its claims.
func (t *TokenIssuer) Verify(ctx context.Context, raw string) (*models.AccessClaims, error) {
	claims := &accessTokenClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("%w: missing kid header", ErrInvalidAccessToken)
		}
		return t.keys.PublicKey(ctx, kid)
	},
		jwt.WithValidMethods([]string{SigningAlgorithm}),
		jwt.WithIssuer(t.issuer),
		jwt.WithAudience(t.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(t.clock.Now),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAccessToken, err)
	}
	if !token.Valid || claims.Subject == "" || claims.SessionID == "" {
		return nil, fmt.Errorf("%w: incomplete claims", ErrInvalidAccessToken)
	}
	var issuedAt time.Time
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}
	var expiresAt time.Time
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}
	return &models.AccessClaims{
		UserID:        claims.Subject,
		SessionID:     claims.SessionID,
		EmailVerified: claims.EmailVerified,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
	}, nil
}
