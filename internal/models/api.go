package models

import "time"

// ErrorResponse is the single error shape used by every endpoint.
type ErrorResponse struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// AcceptedResponse acknowledges a fire-and-forget request without revealing
// whether the account exists.
type AcceptedResponse struct {
	Accepted bool `json:"accepted"`
}

// RegisterRequest is the body of POST /auth/register.
type RegisterRequest struct {
	Email       string `json:"email" binding:"required"`
	Username    string `json:"username" binding:"required"`
	DisplayName string `json:"display_name" binding:"required"`
	Password    string `json:"password" binding:"required"`
}

// RegisterResponse is returned by a successful registration.
type RegisterResponse struct {
	UserID              string `json:"user_id"`
	VerificationPending bool   `json:"verification_pending"`
}

// VerifyEmailRequest is the body of POST /auth/verify-email.
type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

// VerifyEmailResponse identifies the account whose email was confirmed.
type VerifyEmailResponse struct {
	UserID        string `json:"user_id"`
	EmailVerified bool   `json:"email_verified"`
}

// ResendVerificationRequest is the body of POST /auth/verify-email/resend.
type ResendVerificationRequest struct {
	Email string `json:"email" binding:"required"`
}

// PasswordResetRequest is the body of POST /auth/password-reset/request.
type PasswordResetRequest struct {
	Email string `json:"email" binding:"required"`
}

// PasswordResetConfirmRequest is the body of POST /auth/password-reset/confirm.
type PasswordResetConfirmRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// LoginRequest is the body of POST /auth/login.
type LoginRequest struct {
	Email       string `json:"email" binding:"required"`
	Password    string `json:"password" binding:"required"`
	DeviceLabel string `json:"device_label"`
}

// LoginResponse is returned by a successful sign-in or refresh.
type LoginResponse struct {
	AccessToken string        `json:"access_token"`
	TokenType   string        `json:"token_type"`
	ExpiresIn   int           `json:"expires_in"`
	User        PublicProfile `json:"user"`
}

// BearerTokenType is the only token_type this service issues.
const BearerTokenType = "Bearer"

// SessionItem is one entry of the caller's session list.
type SessionItem struct {
	SessionID   string    `json:"session_id"`
	DeviceLabel string    `json:"device_label"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	IsCurrent   bool      `json:"is_current"`
}

// SessionList is the paginated response of GET /sessions.
type SessionList struct {
	Data       []SessionItem `json:"data"`
	NextCursor *string       `json:"next_cursor"`
}

// OwnProfile is the private profile of the authenticated caller.
type OwnProfile struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	Username      string `json:"username"`
	DisplayName   string `json:"display_name"`
	EmailVerified bool   `json:"email_verified"`
}

// UpdateProfileRequest is the body of PATCH /users/me.
type UpdateProfileRequest struct {
	DisplayName string `json:"display_name" binding:"required"`
}

// PublicProfile is the shareable projection of an account.
type PublicProfile struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

// PublicProfileList is the response of GET /users.
type PublicProfileList struct {
	Data []PublicProfile `json:"data"`
}

// JWK is a single public key published in the JWKS document.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the response of GET /.well-known/jwks.json. The current signing key
// comes first, followed by the pre-published next key.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// AccessClaims are the claims carried by an access token.
type AccessClaims struct {
	UserID        string
	SessionID     string
	EmailVerified bool
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// LoginResult is the internal outcome of a sign-in or refresh: the access token
// plus the raw refresh token that must be set as a cookie.
type LoginResult struct {
	AccessToken      string
	ExpiresIn        int
	User             PublicProfile
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// RegisterResult is the internal outcome of a registration.
type RegisterResult struct {
	UserID              string
	VerificationPending bool
}
