package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"identity_service/internal/models"
)

// maxIdempotencyKeyLength bounds the client-supplied Idempotency-Key header.
const maxIdempotencyKeyLength = 64

// register handles POST /auth/register.
func (h *handlers) register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondBadRequest(c, "")
		return
	}
	idempotencyKey := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if len(idempotencyKey) > maxIdempotencyKeyLength {
		h.respondValidationFailed(c, "Idempotency-Key must be at most 64 characters.")
		return
	}

	result, err := h.auth.Register(c.Request.Context(), req, idempotencyKey)
	if err != nil {
		h.respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, models.RegisterResponse{
		UserID:              result.UserID,
		VerificationPending: result.VerificationPending,
	})
}

// verifyEmail handles POST /auth/verify-email.
func (h *handlers) verifyEmail(c *gin.Context) {
	var req models.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondBadRequest(c, "")
		return
	}
	response, err := h.auth.VerifyEmail(c.Request.Context(), req.Token)
	if err != nil {
		h.respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, response)
}

// resendVerification handles POST /auth/verify-email/resend (always 202 for a
// well-formed request).
func (h *handlers) resendVerification(c *gin.Context) {
	var req models.ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondBadRequest(c, "")
		return
	}
	if err := h.auth.ResendVerification(c.Request.Context(), req.Email); err != nil {
		h.respondError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, models.AcceptedResponse{Accepted: true})
}

// login handles POST /auth/login.
func (h *handlers) login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondBadRequest(c, "")
		return
	}
	result, err := h.auth.Login(c.Request.Context(), req, c.ClientIP())
	if err != nil {
		h.respondError(c, err)
		return
	}
	h.setRefreshCookie(c, result)
	c.JSON(http.StatusOK, models.LoginResponse{
		AccessToken: result.AccessToken,
		TokenType:   models.BearerTokenType,
		ExpiresIn:   result.ExpiresIn,
		User:        result.User,
	})
}

// refresh handles POST /auth/refresh.
func (h *handlers) refresh(c *gin.Context) {
	raw, _ := c.Cookie(h.cookie.Name)
	result, err := h.auth.Refresh(c.Request.Context(), raw)
	if err != nil {
		// A failed refresh always drops the (now useless) cookie.
		h.clearRefreshCookie(c)
		h.respondError(c, err)
		return
	}
	h.setRefreshCookie(c, result)
	c.JSON(http.StatusOK, models.LoginResponse{
		AccessToken: result.AccessToken,
		TokenType:   models.BearerTokenType,
		ExpiresIn:   result.ExpiresIn,
		User:        result.User,
	})
}

// logout handles POST /auth/logout.
func (h *handlers) logout(c *gin.Context) {
	if err := h.auth.Logout(c.Request.Context(), callerSessionID(c)); err != nil {
		h.respondError(c, err)
		return
	}
	h.clearRefreshCookie(c)
	c.Status(http.StatusNoContent)
}

// logoutAll handles POST /auth/logout-all.
func (h *handlers) logoutAll(c *gin.Context) {
	if err := h.auth.LogoutAll(c.Request.Context(), callerUserID(c)); err != nil {
		h.respondError(c, err)
		return
	}
	h.clearRefreshCookie(c)
	c.Status(http.StatusNoContent)
}

// requestPasswordReset handles POST /auth/password-reset/request (always 202
// for a well-formed request).
func (h *handlers) requestPasswordReset(c *gin.Context) {
	var req models.PasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondBadRequest(c, "")
		return
	}
	if err := h.auth.RequestPasswordReset(c.Request.Context(), req.Email); err != nil {
		h.respondError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, models.AcceptedResponse{Accepted: true})
}

// confirmPasswordReset handles POST /auth/password-reset/confirm.
func (h *handlers) confirmPasswordReset(c *gin.Context) {
	var req models.PasswordResetConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondBadRequest(c, "")
		return
	}
	if err := h.auth.ConfirmPasswordReset(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		h.respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// setRefreshCookie writes the rotating refresh token cookie:
// HttpOnly; Secure; SameSite=Strict; Path=/auth.
func (h *handlers) setRefreshCookie(c *gin.Context, result *models.LoginResult) {
	maxAge := int(result.RefreshExpiresAt.Sub(nowFunc()).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(h.cookie.Name, result.RefreshToken, maxAge, h.cookie.Path, "", true, true)
}

// clearRefreshCookie expires the refresh cookie.
func (h *handlers) clearRefreshCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(h.cookie.Name, "", -1, h.cookie.Path, "", true, true)
}

var _ = time.Second
