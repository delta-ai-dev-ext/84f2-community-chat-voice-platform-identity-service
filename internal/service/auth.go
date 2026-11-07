package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"identity_service/internal/email"
	"identity_service/internal/models"
	"identity_service/internal/observability"
	"identity_service/internal/repository"
	"identity_service/internal/security"
)

// errRegistrationReplay signals that the Idempotency-Key was already used with
// the same email, so the original result must be returned unchanged.
var errRegistrationReplay = errors.New("service: registration replayed")

// Register creates an unverified account, stores a single-use verification
// token hash and sends the verification email. A retried request carrying the
// same Idempotency-Key returns the original account instead of creating a
// duplicate.
func (s *Service) Register(ctx context.Context, req models.RegisterRequest, idempotencyKey string) (*models.RegisterResult, error) {
	emailAddr, err := validateEmail(req.Email)
	if err != nil {
		s.metrics.RecordRegistration("invalid")
		return nil, err
	}
	username, err := validateUsername(req.Username)
	if err != nil {
		s.metrics.RecordRegistration("invalid")
		return nil, err
	}
	displayName, err := validateDisplayName(req.DisplayName)
	if err != nil {
		s.metrics.RecordRegistration("invalid")
		return nil, err
	}
	if err := validatePassword(req.Password); err != nil {
		s.metrics.RecordRegistration("invalid")
		return nil, err
	}

	passwordHash, err := s.hasher.Hash(req.Password)
	if err != nil {
		return nil, fmt.Errorf("service: hash password: %w", err)
	}
	userID, err := registrationUserID(idempotencyKey)
	if err != nil {
		return nil, err
	}

	now := s.clock.Now()
	var (
		user              *models.User
		verificationToken string
		tokenID           string
	)

	err = s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		existing, getErr := s.repos.Users.GetByID(ctx, userID)
		switch {
		case getErr == nil:
			if models.NormalizeEmail(existing.Email) == emailAddr {
				user = existing
				return errRegistrationReplay
			}
			return models.NewError(models.CodeBadRequest, "This Idempotency-Key was already used for a different registration.")
		case !errors.Is(getErr, repository.ErrNotFound):
			return fmt.Errorf("service: load account by id: %w", getErr)
		}

		if existing, err := s.repos.Users.GetByEmail(ctx, emailAddr); err == nil {
			if existing.ID != userID {
				return models.NewError(models.CodeEmailAlreadyRegistered, "This email is already registered.")
			}
		} else if !errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("service: load account by email: %w", err)
		}

		if existing, err := s.repos.Users.GetByUsername(ctx, username); err == nil {
			if existing.ID != userID {
				return models.NewError(models.CodeUsernameTaken, "This username is already taken.")
			}
		} else if !errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("service: load account by username: %w", err)
		}

		created := &models.User{
			ID:             userID,
			Email:          emailAddr,
			Username:       username,
			DisplayName:    displayName,
			EmailVerified:  false,
			Status:         models.UserStatusActive,
			AccountVersion: 1,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		if err := s.repos.Users.Create(ctx, created); err != nil {
			return mapUserCreateError(err)
		}
		if err := s.repos.Credentials.Upsert(ctx, created.ID, passwordHash); err != nil {
			return fmt.Errorf("service: store credential: %w", err)
		}

		raw, hash, err := security.NewOpaqueToken()
		if err != nil {
			return err
		}
		newTokenID, err := models.NewUUID()
		if err != nil {
			return err
		}
		// Single pending verification token per account.
		if err := s.repos.VerificationTokens.ConsumePending(ctx, created.ID, now); err != nil {
			return fmt.Errorf("service: invalidate pending verification tokens: %w", err)
		}
		if err := s.repos.VerificationTokens.Create(ctx, &models.VerificationToken{
			ID:        newTokenID,
			UserID:    created.ID,
			TokenHash: hash,
			ExpiresAt: now.Add(s.cfg.EmailVerificationTokenTTL),
			CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("service: store verification token: %w", err)
		}

		user = created
		verificationToken = raw
		tokenID = newTokenID
		return nil
	})

	if errors.Is(err, errRegistrationReplay) {
		s.metrics.RecordRegistration("success")
		return &models.RegisterResult{UserID: user.ID, VerificationPending: true}, nil
	}
	if err != nil {
		switch models.ErrorCodeOf(err) {
		case models.CodeEmailAlreadyRegistered, models.CodeUsernameTaken:
			s.metrics.RecordRegistration("duplicate")
		}
		return nil, err
	}

	if err := s.notifier.SendVerification(ctx, email.VerificationMessage{
		To:       user.Email,
		Username: user.Username,
		Token:    verificationToken,
		TokenID:  tokenID,
	}); err != nil {
		// The account exists and the user can request a new link (US-003), so a
		// delivery failure never fails the registration.
		s.logFailure(ctx, "register.send_verification", err)
	}

	s.metrics.RecordRegistration("success")
	return &models.RegisterResult{UserID: user.ID, VerificationPending: true}, nil
}

// VerifyEmail consumes a single-use verification token, marks the account
// verified and publishes the EVT-001 email_verified snapshot.
func (s *Service) VerifyEmail(ctx context.Context, rawToken string) (*models.VerifyEmailResponse, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" || len(rawToken) > 512 {
		return nil, models.ValidationErrorf("token must be between 1 and 512 characters.")
	}

	now := s.clock.Now()
	token, err := s.repos.VerificationTokens.GetByHash(ctx, security.HashToken(rawToken))
	switch {
	case errors.Is(err, repository.ErrNotFound):
		s.metrics.RecordEmailVerification("expired")
		return nil, models.NewError(models.CodeVerificationExpired, "This verification link is no longer valid.")
	case err != nil:
		return nil, fmt.Errorf("service: load verification token: %w", err)
	}
	if token.Consumed() {
		s.metrics.RecordEmailVerification("used")
		return nil, models.NewError(models.CodeVerificationUsed, "This verification link was already used.")
	}
	if token.Expired(now) {
		s.metrics.RecordEmailVerification("expired")
		return nil, models.NewError(models.CodeVerificationExpired, "This verification link is no longer valid.")
	}

	var verified *models.User
	err = s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		user, err := s.repos.Users.GetByID(ctx, token.UserID)
		if err != nil {
			return fmt.Errorf("service: load account: %w", err)
		}
		if user.EmailVerified {
			return models.NewError(models.CodeAlreadyVerified, "This email is already verified.")
		}
		if err := s.repos.VerificationTokens.Consume(ctx, token.ID, now); err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return models.NewError(models.CodeVerificationUsed, "This verification link was already used.")
			}
			return fmt.Errorf("service: consume verification token: %w", err)
		}
		updated, err := s.repos.Users.MarkEmailVerified(ctx, user.ID)
		if err != nil {
			return fmt.Errorf("service: mark email verified: %w", err)
		}
		if err := s.enqueueAccountChanged(ctx, updated, models.AccountChangeEmailVerified); err != nil {
			return err
		}
		verified = updated
		return nil
	})
	if err != nil {
		switch models.ErrorCodeOf(err) {
		case models.CodeAlreadyVerified:
			s.metrics.RecordEmailVerification("already_verified")
		case models.CodeVerificationUsed:
			s.metrics.RecordEmailVerification("used")
		}
		return nil, err
	}

	s.metrics.RecordEmailVerification("success")
	return &models.VerifyEmailResponse{UserID: verified.ID, EmailVerified: true}, nil
}

// ResendVerification issues a fresh verification email for an unverified
// account. Unknown and already-verified addresses are accepted silently so the
// endpoint cannot be used to enumerate accounts.
func (s *Service) ResendVerification(ctx context.Context, rawEmail string) error {
	emailAddr, err := validateEmail(rawEmail)
	if err != nil {
		return err
	}

	user, err := s.repos.Users.GetByEmail(ctx, emailAddr)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("service: load account: %w", err)
	}
	if user.EmailVerified {
		return nil
	}

	raw, hash, err := security.NewOpaqueToken()
	if err != nil {
		return err
	}
	tokenID, err := models.NewUUID()
	if err != nil {
		return err
	}

	// Deliver first: a provider outage must not invalidate the link the user
	// already holds, and no token is consumed when the send fails.
	if err := s.notifier.SendVerification(ctx, email.VerificationMessage{
		To:       user.Email,
		Username: user.Username,
		Token:    raw,
		TokenID:  tokenID,
	}); err != nil {
		s.logFailure(ctx, "resend_verification.send", err)
		return models.NewError(models.CodeEmailUnavailable, "We couldn't send the email. Try again.")
	}

	now := s.clock.Now()
	return s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repos.VerificationTokens.ConsumePending(ctx, user.ID, now); err != nil {
			return fmt.Errorf("service: invalidate pending verification tokens: %w", err)
		}
		if err := s.repos.VerificationTokens.Create(ctx, &models.VerificationToken{
			ID:        tokenID,
			UserID:    user.ID,
			TokenHash: hash,
			ExpiresAt: now.Add(s.cfg.EmailVerificationTokenTTL),
			CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("service: store verification token: %w", err)
		}
		return nil
	})
}

// Login authenticates an account, applies the DB-backed throttle and, on
// success, creates a session with a rotating refresh-token family.
func (s *Service) Login(ctx context.Context, req models.LoginRequest, sourceKey string) (*models.LoginResult, error) {
	emailAddr, err := validateEmail(req.Email)
	if err != nil {
		return nil, err
	}
	deviceLabel, err := validateDeviceLabel(req.DeviceLabel)
	if err != nil {
		return nil, err
	}
	if req.Password == "" || len(req.Password) > MaxPasswordLength {
		return nil, models.ValidationErrorf("password must be between 1 and %d characters.", MaxPasswordLength)
	}

	throttle := s.throttle()
	accountKey := emailAddr

	decision, err := throttle.Check(ctx, accountKey, sourceKey)
	if err != nil {
		return nil, err
	}
	if decision.Locked {
		if recordErr := throttle.Record(ctx, accountKey, sourceKey, models.LoginOutcomeLocked); recordErr != nil {
			s.logFailure(ctx, "login.record_locked", recordErr)
		}
		s.metrics.RecordLogin("locked")
		return nil, models.NewError(models.CodeLocked, lockoutDetail(decision.RetryAfter))
	}

	invalidCredentials := models.NewError(models.CodeInvalidCredentials, "Email or password is incorrect.")

	user, err := s.repos.Users.GetByEmail(ctx, emailAddr)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		// Burn comparable CPU and never reveal that the account is unknown.
		s.hasher.VerifyDummy(req.Password)
		s.recordFailure(ctx, UnknownAccountKey, sourceKey)
		s.metrics.RecordLogin("invalid_credentials")
		return nil, invalidCredentials
	case err != nil:
		return nil, fmt.Errorf("service: load account: %w", err)
	}

	passwordHash, err := s.repos.Credentials.GetPasswordHash(ctx, user.ID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			s.hasher.VerifyDummy(req.Password)
			s.logFailure(ctx, "login.missing_credential", fmt.Errorf("account %s has no credential", user.ID))
			s.recordFailure(ctx, accountKey, sourceKey)
			s.metrics.RecordLogin("invalid_credentials")
			return nil, invalidCredentials
		}
		return nil, fmt.Errorf("service: load credential: %w", err)
	}

	ok, verifyErr := s.hasher.Verify(req.Password, passwordHash)
	if verifyErr != nil {
		s.logFailure(ctx, "login.verify_password", verifyErr)
	}
	if !ok || verifyErr != nil {
		s.recordFailure(ctx, accountKey, sourceKey)
		s.metrics.RecordLogin("invalid_credentials")
		return nil, invalidCredentials
	}

	if user.Status != models.UserStatusActive {
		s.recordFailure(ctx, accountKey, sourceKey)
		s.metrics.RecordLogin("invalid_credentials")
		return nil, invalidCredentials
	}

	// The password was correct, so the failure window is cleared either way.
	if err := throttle.Record(ctx, accountKey, sourceKey, models.LoginOutcomeSuccess); err != nil {
		s.logFailure(ctx, "login.record_success", err)
	}
	if err := throttle.Reset(ctx, accountKey); err != nil {
		s.logFailure(ctx, "login.reset_failures", err)
	}

	if !user.EmailVerified {
		s.metrics.RecordLogin("unverified")
		return nil, models.NewError(models.CodeEmailNotVerified, "Verify your email before signing in.")
	}

	result, err := s.startSession(ctx, user, deviceLabel)
	if err != nil {
		return nil, err
	}
	s.metrics.RecordLogin("success")
	return result, nil
}

// startSession creates the session, its refresh-token family and the access
// token returned to the client.
func (s *Service) startSession(ctx context.Context, user *models.User, deviceLabel string) (*models.LoginResult, error) {
	now := s.clock.Now()
	sessionID, err := models.NewUUID()
	if err != nil {
		return nil, err
	}
	familyID, err := models.NewUUID()
	if err != nil {
		return nil, err
	}
	refreshToken, refreshHash, err := security.NewOpaqueToken()
	if err != nil {
		return nil, err
	}
	refreshID, err := models.NewUUID()
	if err != nil {
		return nil, err
	}
	refreshExpiresAt := now.Add(s.cfg.RefreshTokenTTL)

	err = s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repos.Sessions.Create(ctx, &models.Session{
			ID:          sessionID,
			UserID:      user.ID,
			DeviceLabel: deviceLabel,
			CreatedAt:   now,
			LastSeenAt:  now,
		}); err != nil {
			return fmt.Errorf("service: create session: %w", err)
		}
		if err := s.repos.RefreshTokens.Create(ctx, &models.RefreshToken{
			ID:        refreshID,
			SessionID: sessionID,
			FamilyID:  familyID,
			TokenHash: refreshHash,
			Status:    models.RefreshTokenActive,
			ExpiresAt: refreshExpiresAt,
			CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("service: create refresh token: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	accessToken, expiresIn, err := s.tokens.Issue(ctx, user, sessionID)
	if err != nil {
		return nil, err
	}
	return &models.LoginResult{
		AccessToken:      accessToken,
		ExpiresIn:        expiresIn,
		User:             user.PublicProfile(),
		RefreshToken:     refreshToken,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

// Refresh rotates a refresh token. Presenting a token that is no longer active
// is treated as reuse: the session and its whole token family are revoked
// (ADR-001).
func (s *Service) Refresh(ctx context.Context, rawRefreshToken string) (*models.LoginResult, error) {
	if strings.TrimSpace(rawRefreshToken) == "" {
		return nil, models.NewError(models.CodeInvalidRefreshToken, "Sign in again.")
	}

	invalidToken := models.NewError(models.CodeInvalidRefreshToken, "Sign in again.")
	sessionRevoked := models.NewError(models.CodeSessionRevoked, "This session was revoked. Sign in again.")

	now := s.clock.Now()
	var (
		session     *models.Session
		user        *models.User
		rotatedRaw  string
		rotatedTill time.Time
	)

	err := s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		token, err := s.repos.RefreshTokens.GetByHashForUpdate(ctx, security.HashToken(rawRefreshToken))
		switch {
		case errors.Is(err, repository.ErrNotFound):
			return invalidToken
		case err != nil:
			return fmt.Errorf("service: load refresh token: %w", err)
		}

		if token.Status != models.RefreshTokenActive {
			// Reuse detection: kill the session and every token in its family.
			if err := s.repos.Sessions.Revoke(ctx, token.SessionID, now); err != nil {
				return fmt.Errorf("service: revoke session: %w", err)
			}
			if err := s.repos.RefreshTokens.RevokeFamily(ctx, token.FamilyID); err != nil {
				return fmt.Errorf("service: revoke token family: %w", err)
			}
			observability.LoggerWithTrace(s.logger, observability.TraceFrom(ctx), "auth.refresh").
				Warn("refresh token reuse detected", zap.String("status", "reuse_detected"))
			return sessionRevoked
		}
		if !now.Before(token.ExpiresAt) {
			return invalidToken
		}

		loaded, err := s.repos.Sessions.GetByID(ctx, token.SessionID)
		switch {
		case errors.Is(err, repository.ErrNotFound):
			return invalidToken
		case err != nil:
			return fmt.Errorf("service: load session: %w", err)
		}
		if !loaded.Active() {
			if err := s.repos.RefreshTokens.RevokeFamily(ctx, token.FamilyID); err != nil {
				return fmt.Errorf("service: revoke token family: %w", err)
			}
			return sessionRevoked
		}

		account, err := s.repos.Users.GetByID(ctx, loaded.UserID)
		if err != nil {
			return fmt.Errorf("service: load account: %w", err)
		}
		if account.Status != models.UserStatusActive {
			return sessionRevoked
		}

		newRaw, newHash, err := security.NewOpaqueToken()
		if err != nil {
			return err
		}
		newID, err := models.NewUUID()
		if err != nil {
			return err
		}
		expiresAt := now.Add(s.cfg.RefreshTokenTTL)
		if err := s.repos.RefreshTokens.Create(ctx, &models.RefreshToken{
			ID:        newID,
			SessionID: loaded.ID,
			FamilyID:  token.FamilyID,
			TokenHash: newHash,
			Status:    models.RefreshTokenActive,
			ExpiresAt: expiresAt,
			CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("service: create refresh token: %w", err)
		}
		if err := s.repos.RefreshTokens.MarkRotated(ctx, token.ID, newID); err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return sessionRevoked
			}
			return fmt.Errorf("service: mark refresh token rotated: %w", err)
		}
		if err := s.repos.Sessions.Touch(ctx, loaded.ID, now); err != nil {
			return fmt.Errorf("service: touch session: %w", err)
		}

		session = loaded
		user = account
		rotatedRaw = newRaw
		rotatedTill = expiresAt
		return nil
	})
	if err != nil {
		return nil, err
	}

	accessToken, expiresIn, err := s.tokens.Issue(ctx, user, session.ID)
	if err != nil {
		return nil, err
	}
	return &models.LoginResult{
		AccessToken:      accessToken,
		ExpiresIn:        expiresIn,
		User:             user.PublicProfile(),
		RefreshToken:     rotatedRaw,
		RefreshExpiresAt: rotatedTill,
	}, nil
}

// Logout revokes the caller's session and its refresh family. It is idempotent.
func (s *Service) Logout(ctx context.Context, sessionID string) error {
	if !models.IsUUID(sessionID) {
		return nil
	}
	now := s.clock.Now()
	return s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		session, err := s.repos.Sessions.GetByID(ctx, sessionID)
		switch {
		case errors.Is(err, repository.ErrNotFound):
			return nil
		case err != nil:
			return fmt.Errorf("service: load session: %w", err)
		}
		if err := s.repos.Sessions.Revoke(ctx, session.ID, now); err != nil {
			return fmt.Errorf("service: revoke session: %w", err)
		}
		if err := s.repos.RefreshTokens.RevokeBySession(ctx, session.ID); err != nil {
			return fmt.Errorf("service: revoke refresh tokens: %w", err)
		}
		return nil
	})
}

// LogoutAll revokes every session of the account, including the current one.
func (s *Service) LogoutAll(ctx context.Context, userID string) error {
	if !models.IsUUID(userID) {
		return nil
	}
	now := s.clock.Now()
	return s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repos.Sessions.RevokeAllByUser(ctx, userID, now); err != nil {
			return fmt.Errorf("service: revoke sessions: %w", err)
		}
		if err := s.repos.RefreshTokens.RevokeByUser(ctx, userID); err != nil {
			return fmt.Errorf("service: revoke refresh tokens: %w", err)
		}
		return nil
	})
}

// RequestPasswordReset starts a reset flow. It always succeeds from the
// caller's point of view: unknown addresses are accepted without an email so
// the endpoint cannot enumerate accounts.
func (s *Service) RequestPasswordReset(ctx context.Context, rawEmail string) error {
	emailAddr, err := validateEmail(rawEmail)
	if err != nil {
		return err
	}

	user, err := s.repos.Users.GetByEmail(ctx, emailAddr)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		s.metrics.RecordPasswordReset("request", "accepted")
		return nil
	case err != nil:
		return fmt.Errorf("service: load account: %w", err)
	}

	raw, hash, err := security.NewOpaqueToken()
	if err != nil {
		return err
	}
	tokenID, err := models.NewUUID()
	if err != nil {
		return err
	}

	if err := s.notifier.SendPasswordReset(ctx, email.PasswordResetMessage{
		To:       user.Email,
		Username: user.Username,
		Token:    raw,
		TokenID:  tokenID,
	}); err != nil {
		s.logFailure(ctx, "password_reset.send", err)
		s.metrics.RecordPasswordReset("request", "email_unavailable")
		return models.NewError(models.CodeEmailUnavailable, "We couldn't send the email. Try again.")
	}

	now := s.clock.Now()
	err = s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repos.PasswordResets.ConsumePending(ctx, user.ID, now); err != nil {
			return fmt.Errorf("service: invalidate pending reset tokens: %w", err)
		}
		if err := s.repos.PasswordResets.Create(ctx, &models.PasswordResetToken{
			ID:        tokenID,
			UserID:    user.ID,
			TokenHash: hash,
			ExpiresAt: now.Add(s.cfg.PasswordResetTokenTTL),
			CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("service: store reset token: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.metrics.RecordPasswordReset("request", "accepted")
	return nil
}

// ConfirmPasswordReset replaces the password, revokes every session of the
// account and sends a confirmation email. Used and expired tokens are
// indistinguishable (410 reset_link_expired).
func (s *Service) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string) error {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" || len(rawToken) > 512 {
		return models.ValidationErrorf("token must be between 1 and 512 characters.")
	}
	if err := validatePassword(newPassword); err != nil {
		s.metrics.RecordPasswordReset("confirm", "invalid")
		return err
	}

	passwordHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("service: hash password: %w", err)
	}

	now := s.clock.Now()
	expired := models.NewError(models.CodeResetLinkExpired, "This reset link is no longer valid.")
	var user *models.User

	err = s.repos.Transactor.WithTx(ctx, func(ctx context.Context) error {
		token, err := s.repos.PasswordResets.GetByHash(ctx, security.HashToken(rawToken))
		switch {
		case errors.Is(err, repository.ErrNotFound):
			return expired
		case err != nil:
			return fmt.Errorf("service: load reset token: %w", err)
		}
		if token.Consumed() || token.Expired(now) {
			return expired
		}

		account, err := s.repos.Users.GetByID(ctx, token.UserID)
		if err != nil {
			return fmt.Errorf("service: load account: %w", err)
		}
		if err := s.repos.PasswordResets.Consume(ctx, token.ID, now); err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return expired
			}
			return fmt.Errorf("service: consume reset token: %w", err)
		}
		if err := s.repos.Credentials.Upsert(ctx, account.ID, passwordHash); err != nil {
			return fmt.Errorf("service: replace credential: %w", err)
		}
		if err := s.repos.Sessions.RevokeAllByUser(ctx, account.ID, now); err != nil {
			return fmt.Errorf("service: revoke sessions: %w", err)
		}
		if err := s.repos.RefreshTokens.RevokeByUser(ctx, account.ID); err != nil {
			return fmt.Errorf("service: revoke refresh tokens: %w", err)
		}
		user = account
		return nil
	})
	if err != nil {
		if models.ErrorCodeOf(err) == models.CodeResetLinkExpired {
			s.metrics.RecordPasswordReset("confirm", "expired")
		}
		return err
	}

	// The confirmation email is informational: a failure is logged and never
	// fails the completed reset.
	if err := s.notifier.SendPasswordChanged(ctx, email.PasswordChangedMessage{
		To:       user.Email,
		Username: user.Username,
		UserID:   user.ID,
	}); err != nil {
		s.logFailure(ctx, "password_reset.send_confirmation", err)
	}

	s.metrics.RecordPasswordReset("confirm", "success")
	return nil
}

// throttle builds the throttle policy from configuration.
func (s *Service) throttle() *Throttle {
	return NewThrottle(s.repos.LoginAttempts, s.clock, s.cfg.LoginMaxFailures,
		s.cfg.LoginSourceMaxFailures, s.cfg.LoginWindow, s.cfg.LoginLockout)
}

// recordFailure appends a failed attempt to the ledger, logging ledger errors
// without failing the request.
func (s *Service) recordFailure(ctx context.Context, accountKey, sourceKey string) {
	if err := s.throttle().Record(ctx, accountKey, sourceKey, models.LoginOutcomeFailure); err != nil {
		s.logFailure(ctx, "login.record_failure", err)
	}
}

// lockoutDetail renders the human-readable lockout message.
func lockoutDetail(retryAfter time.Duration) string {
	minutes := int(retryAfter.Minutes() + 0.5)
	if minutes < 1 {
		minutes = 1
	}
	return fmt.Sprintf("Too many attempts. Try again in %d minutes.", minutes)
}

// registrationUserID derives a stable user id from the client's Idempotency-Key
// so that a retried registration can never create a second account, without
// adding state that would break statelessness. Without a key a random id is
// used.
func registrationUserID(idempotencyKey string) (string, error) {
	key := strings.TrimSpace(idempotencyKey)
	if key == "" {
		return models.NewUUID()
	}
	sum := sha256.Sum256([]byte("identity_service:register:" + key))
	return models.UUIDFromHash(sum), nil
}

// mapUserCreateError translates unique-constraint violations into the error
// codes required by the OpenAPI contract.
func mapUserCreateError(err error) error {
	switch {
	case errors.Is(err, repository.ErrEmailConflict):
		return models.NewError(models.CodeEmailAlreadyRegistered, "This email is already registered.")
	case errors.Is(err, repository.ErrUsernameConflict):
		return models.NewError(models.CodeUsernameTaken, "This username is already taken.")
	case errors.Is(err, repository.ErrIDConflict):
		return models.NewError(models.CodeBadRequest, "This Idempotency-Key was already used for a different registration.")
	default:
		return fmt.Errorf("service: create account: %w", err)
	}
}
