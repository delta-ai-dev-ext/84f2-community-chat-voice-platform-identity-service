package handler

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"identity_service/internal/metrics"
	"identity_service/internal/models"
)

// AuthService is the auth use-case surface consumed by the HTTP layer.
type AuthService interface {
	Register(ctx context.Context, req models.RegisterRequest, idempotencyKey string) (*models.RegisterResult, error)
	VerifyEmail(ctx context.Context, token string) (*models.VerifyEmailResponse, error)
	ResendVerification(ctx context.Context, email string) error
	Login(ctx context.Context, req models.LoginRequest, sourceKey string) (*models.LoginResult, error)
	Refresh(ctx context.Context, refreshToken string) (*models.LoginResult, error)
	Logout(ctx context.Context, sessionID string) error
	LogoutAll(ctx context.Context, userID string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ConfirmPasswordReset(ctx context.Context, token, newPassword string) error
}

// AccountService is the profile use-case surface consumed by the HTTP layer.
type AccountService interface {
	Profile(ctx context.Context, userID string) (*models.OwnProfile, error)
	UpdateDisplayName(ctx context.Context, userID, displayName string) (*models.OwnProfile, error)
	LookupByUsername(ctx context.Context, username string) (*models.PublicProfile, error)
	PublicProfiles(ctx context.Context, ids []string) (*models.PublicProfileList, error)
}

// SessionService is the session use-case surface consumed by the HTTP layer.
type SessionService interface {
	ListSessions(ctx context.Context, userID, currentSessionID, cursor string, limit int) (*models.SessionList, error)
	RevokeSession(ctx context.Context, userID, sessionID string) error
}

// KeyService publishes the access-token verification keys.
type KeyService interface {
	JWKS(ctx context.Context) (*models.JWKS, error)
}

// TokenVerifier validates bearer access tokens.
type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (*models.AccessClaims, error)
}

// ReadinessChecker reports whether critical dependencies are usable.
type ReadinessChecker interface {
	Ready(ctx context.Context) error
}

// CookieSettings describes the refresh-token cookie.
type CookieSettings struct {
	// Name is the cookie name (refresh_token).
	Name string
	// Path scopes the cookie to the auth endpoints.
	Path string
}

// Options are the router dependencies.
type Options struct {
	Auth      AuthService
	Account   AccountService
	Sessions  SessionService
	Keys      KeyService
	Tokens    TokenVerifier
	Readiness ReadinessChecker
	Metrics   *metrics.Metrics
	Logger    *zap.Logger
	Cookie    CookieSettings
}

// handlers holds the resolved dependencies.
type handlers struct {
	auth      AuthService
	account   AccountService
	sessions  SessionService
	keys      KeyService
	tokens    TokenVerifier
	readiness ReadinessChecker
	metrics   *metrics.Metrics
	logger    *zap.Logger
	cookie    CookieSettings
}

// NewRouter builds the gin engine with every route registered.
func NewRouter(opts Options) (*gin.Engine, error) {
	switch {
	case opts.Auth == nil:
		return nil, errors.New("handler: auth service is required")
	case opts.Account == nil:
		return nil, errors.New("handler: account service is required")
	case opts.Sessions == nil:
		return nil, errors.New("handler: session service is required")
	case opts.Keys == nil:
		return nil, errors.New("handler: key service is required")
	case opts.Tokens == nil:
		return nil, errors.New("handler: token verifier is required")
	}

	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	cookie := opts.Cookie
	if cookie.Name == "" {
		cookie.Name = "refresh_token"
	}
	if cookie.Path == "" {
		cookie.Path = "/auth"
	}

	h := &handlers{
		auth:      opts.Auth,
		account:   opts.Account,
		sessions:  opts.Sessions,
		keys:      opts.Keys,
		tokens:    opts.Tokens,
		readiness: opts.Readiness,
		metrics:   opts.Metrics,
		logger:    logger,
		cookie:    cookie,
	}

	router := gin.New()
	// Client addresses come from the connection, never from client-supplied
	// forwarding headers, so per-source throttling cannot be spoofed.
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, err
	}
	router.Use(traceMiddleware(), h.recoveryMiddleware(), h.metricsMiddleware())

	router.GET("/healthz", h.healthz)
	router.GET("/readyz", h.readyz)
	router.GET("/.well-known/jwks.json", h.getJWKS)

	auth := router.Group("/auth")
	auth.POST("/register", h.register)
	auth.POST("/verify-email", h.verifyEmail)
	auth.POST("/verify-email/resend", h.resendVerification)
	auth.POST("/login", h.login)
	auth.POST("/refresh", h.refresh)
	auth.POST("/password-reset/request", h.requestPasswordReset)
	auth.POST("/password-reset/confirm", h.confirmPasswordReset)
	auth.POST("/logout", h.authMiddleware(), h.logout)
	auth.POST("/logout-all", h.authMiddleware(), h.logoutAll)

	sessions := router.Group("/sessions", h.authMiddleware())
	sessions.GET("", h.listSessions)
	sessions.DELETE("/:session_id", h.revokeSession)

	users := router.Group("/users", h.authMiddleware())
	users.GET("/me", h.getProfile)
	users.PATCH("/me", h.updateProfile)
	users.GET("/lookup", h.lookupUser)
	users.GET("", h.listUsers)

	return router, nil
}
