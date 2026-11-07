package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"identity_service/internal/models"
)

// getProfile handles GET /users/me.
func (h *handlers) getProfile(c *gin.Context) {
	profile, err := h.account.Profile(c.Request.Context(), callerUserID(c))
	if err != nil {
		h.respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, profile)
}

// updateProfile handles PATCH /users/me.
func (h *handlers) updateProfile(c *gin.Context) {
	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondBadRequest(c, "")
		return
	}
	profile, err := h.account.UpdateDisplayName(c.Request.Context(), callerUserID(c), req.DisplayName)
	if err != nil {
		h.respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, profile)
}

// lookupUser handles GET /users/lookup?username=.
func (h *handlers) lookupUser(c *gin.Context) {
	username := strings.TrimSpace(c.Query("username"))
	if username == "" {
		h.respondValidationFailed(c, "username is required.")
		return
	}
	profile, err := h.account.LookupByUsername(c.Request.Context(), username)
	if err != nil {
		h.respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, profile)
}

// listUsers handles GET /users?ids=.
func (h *handlers) listUsers(c *gin.Context) {
	raw := strings.TrimSpace(c.Query("ids"))
	if raw == "" {
		h.respondValidationFailed(c, "ids is required.")
		return
	}
	ids := strings.Split(raw, ",")
	profiles, err := h.account.PublicProfiles(c.Request.Context(), ids)
	if err != nil {
		h.respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, profiles)
}

// listSessions handles GET /sessions.
func (h *handlers) listSessions(c *gin.Context) {
	limit, err := parseLimit(c.Query("limit"))
	if err != nil {
		h.respondValidationFailed(c, err.Error())
		return
	}
	list, listErr := h.sessions.ListSessions(c.Request.Context(), callerUserID(c), callerSessionID(c),
		strings.TrimSpace(c.Query("cursor")), limit)
	if listErr != nil {
		h.respondError(c, listErr)
		return
	}
	c.JSON(http.StatusOK, list)
}

// revokeSession handles DELETE /sessions/{session_id}.
func (h *handlers) revokeSession(c *gin.Context) {
	if err := h.sessions.RevokeSession(c.Request.Context(), callerUserID(c), c.Param("session_id")); err != nil {
		h.respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// parseLimit parses the optional limit query parameter (1..100, default 0
// meaning "service default").
func parseLimit(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, models.ValidationErrorf("limit must be an integer between 1 and 100.")
		}
		value = value*10 + int(r-'0')
		if value > 1000 {
			return 0, models.ValidationErrorf("limit must be an integer between 1 and 100.")
		}
	}
	if value < 1 || value > 100 {
		return 0, models.ValidationErrorf("limit must be an integer between 1 and 100.")
	}
	return value, nil
}

// healthz handles GET /healthz: liveness only, never dependency probes.
func (h *handlers) healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// readyz handles GET /readyz: PostgreSQL and the Kafka producer must be usable,
// and the service must not be shutting down.
func (h *handlers) readyz(c *gin.Context) {
	if h.readiness == nil {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
		return
	}
	if err := h.readiness.Ready(c.Request.Context()); err != nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, models.ErrorResponse{
			Error:  string(models.CodeServiceUnavailable),
			Detail: defaultDetail(models.CodeServiceUnavailable),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}

// getJWKS handles GET /.well-known/jwks.json.
func (h *handlers) getJWKS(c *gin.Context) {
	jwks, err := h.keys.JWKS(c.Request.Context())
	if err != nil {
		h.respondError(c, err)
		return
	}
	c.Header("Cache-Control", "public, max-age=60")
	c.JSON(http.StatusOK, jwks)
}
