package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"identity_service/internal/metrics"
	"identity_service/internal/models"
	"identity_service/tests/mocks"
)

const testUserID = "3f0f5a5e-6f0f-4b3f-9a5e-111111111111"
const testSessionID = "4f0f5a5e-6f0f-4b3f-9a5e-222222222222"
const testToken = "header.payload.signature"

func init() {
	gin.SetMode(gin.TestMode)
}

// testRouter bundles the router and its doubles.
type testRouter struct {
	engine    *gin.Engine
	auth      *mocks.AuthService
	account   *mocks.AccountService
	sessions  *mocks.SessionService
	keys      *mocks.KeyService
	tokens    *mocks.TokenVerifier
	readiness *mocks.Readiness
	metrics   *metrics.Metrics
	registry  *prometheus.Registry
}

// newTestRouter wires the HTTP layer with testimony mocks.
func newTestRouter(t *testing.T, authenticated bool) *testRouter {
	t.Helper()

	registry := prometheus.NewRegistry()
	appMetrics := metrics.New(registry)

	doubles := &testRouter{
		auth:      new(mocks.AuthService),
		account:   new(mocks.AccountService),
		sessions:  new(mocks.SessionService),
		keys:      new(mocks.KeyService),
		tokens:    new(mocks.TokenVerifier),
		readiness: &mocks.Readiness{},
		metrics:   appMetrics,
		registry:  registry,
	}

	if authenticated {
		doubles.tokens.On("Verify", mock.Anything, testToken).Return(&models.AccessClaims{
			UserID:    testUserID,
			SessionID: testSessionID,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Minute),
		}, nil)
	}

	engine, err := NewRouter(Options{
		Auth:      doubles.auth,
		Account:   doubles.account,
		Sessions:  doubles.sessions,
		Keys:      doubles.keys,
		Tokens:    doubles.tokens,
		Readiness: doubles.readiness,
		Metrics:   appMetrics,
		Cookie:    CookieSettings{Name: "refresh_token", Path: "/auth"},
	})
	require.NoError(t, err)
	doubles.engine = engine
	return doubles
}

// do performs a request against the router.
func (r *testRouter) do(t *testing.T, method, path string, body string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	r.engine.ServeHTTP(recorder, request)
	return recorder
}

// authHeader returns a bearer header for the mocked token.
func authHeader() map[string]string {
	return map[string]string{"Authorization": "Bearer " + testToken}
}

// decodeError asserts the standard error shape and returns the code.
func decodeError(t *testing.T, recorder *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var payload map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	require.Contains(t, payload, "error")
	require.Contains(t, payload, "detail")
	require.Len(t, payload, 2, "error responses have exactly error and detail")
	code, ok := payload["error"].(string)
	require.True(t, ok)
	detail, ok := payload["detail"].(string)
	require.True(t, ok)
	return code, detail
}

func TestHealthzIsIndependentOfDependencies(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	router.readiness.Err = errors.New("postgres down")

	response := router.do(t, http.MethodGet, "/healthz", "", nil)
	require.Equal(t, http.StatusOK, response.Code)
}

func TestReadyzReportsDependencyState(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)

	response := router.do(t, http.MethodGet, "/readyz", "", nil)
	require.Equal(t, http.StatusOK, response.Code)

	router.readiness.Err = errors.New("kafka producer is not connected")
	response = router.do(t, http.MethodGet, "/readyz", "", nil)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	code, _ := decodeError(t, response)
	require.Equal(t, string(models.CodeServiceUnavailable), code)
}

func TestJWKSIsPublic(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	router.keys.On("JWKS", mock.Anything).Return(&models.JWKS{Keys: []models.JWK{
		{Kty: "RSA", Kid: "kid-1", Alg: "RS256", Use: "sig", N: "abc", E: "AQAB"},
	}}, nil)

	response := router.do(t, http.MethodGet, "/.well-known/jwks.json", "", nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"kid":"kid-1"`)
}

func TestErrorShapeForEveryCode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		code   models.ErrorCode
		status int
	}{
		{models.CodeBadRequest, http.StatusBadRequest},
		{models.CodeValidationFailed, http.StatusUnprocessableEntity},
		{models.CodeUnauthorized, http.StatusUnauthorized},
		{models.CodeInvalidCredentials, http.StatusUnauthorized},
		{models.CodeInvalidRefreshToken, http.StatusUnauthorized},
		{models.CodeSessionRevoked, http.StatusUnauthorized},
		{models.CodeEmailNotVerified, http.StatusForbidden},
		{models.CodeSessionNotFound, http.StatusNotFound},
		{models.CodeUserNotFound, http.StatusNotFound},
		{models.CodeEmailAlreadyRegistered, http.StatusConflict},
		{models.CodeUsernameTaken, http.StatusConflict},
		{models.CodeAlreadyVerified, http.StatusConflict},
		{models.CodeLocked, http.StatusTooManyRequests},
		{models.CodeVerificationExpired, http.StatusGone},
		{models.CodeVerificationUsed, http.StatusGone},
		{models.CodeResetLinkExpired, http.StatusGone},
		{models.CodeEmailUnavailable, http.StatusServiceUnavailable},
		{models.CodeServiceUnavailable, http.StatusServiceUnavailable},
		{models.CodeInternalError, http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(string(tc.code), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.status, statusFor(tc.code))
			require.NotEmpty(t, defaultDetail(tc.code))

			router := newTestRouter(t, false)
			router.auth.On("ResendVerification", mock.Anything, mock.Anything).
				Return(models.NewError(tc.code, ""))

			response := router.do(t, http.MethodPost, "/auth/verify-email/resend",
				`{"email":"user@example.com"}`, nil)
			require.Equal(t, tc.status, response.Code)
			code, detail := decodeError(t, response)
			require.Equal(t, string(tc.code), code)
			require.NotEmpty(t, detail)

			if tc.code == models.CodeInternalError {
				require.NotContains(t, response.Body.String(), "internal error details")
				require.Equal(t, "Something went wrong. Try again.", detail)
			}
		})
	}
}

func TestRegisterEndpoint(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	request := models.RegisterRequest{Email: "user@example.com", Username: "user", DisplayName: "User", Password: "correct-horse-battery"}
	router.auth.On("Register", mock.Anything, request, "idem-1").
		Return(&models.RegisterResult{UserID: testUserID, VerificationPending: true}, nil)

	response := router.do(t, http.MethodPost, "/auth/register",
		`{"email":"user@example.com","username":"user","display_name":"User","password":"correct-horse-battery"}`,
		map[string]string{"Idempotency-Key": "idem-1"})

	require.Equal(t, http.StatusCreated, response.Code)
	var body models.RegisterResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.Equal(t, testUserID, body.UserID)
	require.True(t, body.VerificationPending)
}

func TestRegisterEndpointRejectsMalformedRequests(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)

	response := router.do(t, http.MethodPost, "/auth/register", `{`, nil)
	require.Equal(t, http.StatusBadRequest, response.Code)
	code, _ := decodeError(t, response)
	require.Equal(t, string(models.CodeBadRequest), code)

	response = router.do(t, http.MethodPost, "/auth/register",
		`{"email":"user@example.com","username":"user","display_name":"User","password":"x"}`,
		map[string]string{"Idempotency-Key": strings.Repeat("k", 65)})
	require.Equal(t, http.StatusUnprocessableEntity, response.Code)
}

func TestVerificationEndpoints(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	router.auth.On("VerifyEmail", mock.Anything, "token-1").
		Return(&models.VerifyEmailResponse{UserID: testUserID, EmailVerified: true}, nil)
	router.auth.On("VerifyEmail", mock.Anything, "expired").Return(nil,
		models.NewError(models.CodeVerificationExpired, "This verification link is no longer valid."))
	router.auth.On("ResendVerification", mock.Anything, "user@example.com").Return(nil)

	response := router.do(t, http.MethodPost, "/auth/verify-email", `{"token":"token-1"}`, nil)
	require.Equal(t, http.StatusOK, response.Code)

	response = router.do(t, http.MethodPost, "/auth/verify-email", `{"token":"expired"}`, nil)
	require.Equal(t, http.StatusGone, response.Code)
	code, _ := decodeError(t, response)
	require.Equal(t, string(models.CodeVerificationExpired), code)

	// Resend always answers 202 for a well-formed request.
	response = router.do(t, http.MethodPost, "/auth/verify-email/resend", `{"email":"user@example.com"}`, nil)
	require.Equal(t, http.StatusAccepted, response.Code)
	var accepted models.AcceptedResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &accepted))
	require.True(t, accepted.Accepted)
}

func TestPasswordResetEndpoints(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	router.auth.On("RequestPasswordReset", mock.Anything, "user@example.com").Return(nil)
	router.auth.On("ConfirmPasswordReset", mock.Anything, "token-1", "correct-horse-battery").
		Return(models.NewError(models.CodeResetLinkExpired, ""))

	response := router.do(t, http.MethodPost, "/auth/password-reset/request", `{"email":"user@example.com"}`, nil)
	require.Equal(t, http.StatusAccepted, response.Code)

	response = router.do(t, http.MethodPost, "/auth/password-reset/confirm",
		`{"token":"token-1","new_password":"correct-horse-battery"}`, nil)
	require.Equal(t, http.StatusGone, response.Code)
	code, _ := decodeError(t, response)
	require.Equal(t, string(models.CodeResetLinkExpired), code)
}

func TestLoginSetsHardenedRefreshCookie(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	result := &models.LoginResult{
		AccessToken:      "access-token",
		ExpiresIn:        600,
		User:             models.PublicProfile{UserID: testUserID, Username: "user", DisplayName: "User"},
		RefreshToken:     "refresh-token",
		RefreshExpiresAt: time.Now().Add(time.Hour),
	}
	router.auth.On("Login", mock.Anything, mock.Anything, "192.0.2.1").Return(result, nil)

	request := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"email":"user@example.com","password":"correct-horse-battery","device_label":"Test"}`))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.1:12345"
	recorder := httptest.NewRecorder()
	router.engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	cookie := recorder.Header().Get("Set-Cookie")
	require.Contains(t, cookie, "refresh_token=refresh-token")
	require.Contains(t, cookie, "HttpOnly")
	require.Contains(t, cookie, "Secure")
	require.Contains(t, cookie, "SameSite=Strict")
	require.Contains(t, cookie, "Path=/auth")

	var body models.LoginResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	require.Equal(t, "Bearer", body.TokenType)
	require.Equal(t, 600, body.ExpiresIn)
}

func TestLoginAndRefreshErrorPaths(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	router.auth.On("Login", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, models.NewError(models.CodeInvalidCredentials, "Email or password is incorrect."))
	router.auth.On("Refresh", mock.Anything, mock.Anything).
		Return(nil, models.NewError(models.CodeSessionRevoked, "This session was revoked. Sign in again."))

	response := router.do(t, http.MethodPost, "/auth/login",
		`{"email":"user@example.com","password":"wrong-password"}`, nil)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	code, detail := decodeError(t, response)
	require.Equal(t, string(models.CodeInvalidCredentials), code)
	require.Equal(t, "Email or password is incorrect.", detail)

	// A failed refresh clears the cookie and returns 401.
	response = router.do(t, http.MethodPost, "/auth/refresh", "", nil,
		&http.Cookie{Name: "refresh_token", Value: "stale"})
	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Contains(t, response.Header().Get("Set-Cookie"), "Max-Age=0")
	code, _ = decodeError(t, response)
	require.Equal(t, string(models.CodeSessionRevoked), code)
}

func TestRefreshRotatesCookie(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	router.auth.On("Refresh", mock.Anything, "old-token").Return(&models.LoginResult{
		AccessToken:      "new-access",
		ExpiresIn:        600,
		User:             models.PublicProfile{UserID: testUserID},
		RefreshToken:     "new-token",
		RefreshExpiresAt: time.Now().Add(time.Hour),
	}, nil)

	response := router.do(t, http.MethodPost, "/auth/refresh", "", nil,
		&http.Cookie{Name: "refresh_token", Value: "old-token"})
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Header().Get("Set-Cookie"), "refresh_token=new-token")
}

func TestProtectedEndpointsRequireBearerToken(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/auth/logout"},
		{http.MethodPost, "/auth/logout-all"},
		{http.MethodGet, "/sessions"},
		{http.MethodDelete, "/sessions/" + testSessionID},
		{http.MethodGet, "/users/me"},
		{http.MethodPatch, "/users/me"},
		{http.MethodGet, "/users/lookup?username=user"},
		{http.MethodGet, "/users?ids=" + testUserID},
	} {
		response := router.do(t, route.method, route.path, "", nil)
		require.Equal(t, http.StatusUnauthorized, response.Code, route.path)
		code, _ := decodeError(t, response)
		require.Equal(t, string(models.CodeUnauthorized), code)
	}

	// An invalid token is rejected as well.
	router.tokens.On("Verify", mock.Anything, "bad-token").Return(nil, errors.New("invalid"))
	response := router.do(t, http.MethodGet, "/users/me", "", map[string]string{"Authorization": "Bearer bad-token"})
	require.Equal(t, http.StatusUnauthorized, response.Code)
}

func TestLogoutEndpoints(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, true)
	router.auth.On("Logout", mock.Anything, testSessionID).Return(nil)
	router.auth.On("LogoutAll", mock.Anything, testUserID).Return(nil)

	response := router.do(t, http.MethodPost, "/auth/logout", "", authHeader())
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Contains(t, response.Header().Get("Set-Cookie"), "Max-Age=0")

	response = router.do(t, http.MethodPost, "/auth/logout-all", "", authHeader())
	require.Equal(t, http.StatusNoContent, response.Code)
}

func TestSessionEndpoints(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, true)
	list := &models.SessionList{Data: []models.SessionItem{{
		SessionID: testSessionID, DeviceLabel: "Browser", IsCurrent: true,
	}}}
	router.sessions.On("ListSessions", mock.Anything, testUserID, testSessionID, "cursor-1", 25).Return(list, nil)
	router.sessions.On("RevokeSession", mock.Anything, testUserID, testSessionID).Return(nil)

	response := router.do(t, http.MethodGet, "/sessions?limit=25&cursor=cursor-1", "", authHeader())
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"is_current":true`)

	// Out-of-range limits are rejected before hitting the service.
	response = router.do(t, http.MethodGet, "/sessions?limit=500", "", authHeader())
	require.Equal(t, http.StatusUnprocessableEntity, response.Code)

	response = router.do(t, http.MethodDelete, "/sessions/"+testSessionID, "", authHeader())
	require.Equal(t, http.StatusNoContent, response.Code)

	router.sessions.On("RevokeSession", mock.Anything, testUserID, "unknown").Return(nil)
	router.sessions.ExpectedCalls = router.sessions.ExpectedCalls[:len(router.sessions.ExpectedCalls)-1]
	router.sessions.On("RevokeSession", mock.Anything, testUserID, mock.Anything).
		Return(models.NewError(models.CodeSessionNotFound, "No such active session.")).Maybe()
	response = router.do(t, http.MethodDelete, "/sessions/unknown", "", authHeader())
	require.Equal(t, http.StatusNotFound, response.Code)
	code, _ := decodeError(t, response)
	require.Equal(t, string(models.CodeSessionNotFound), code)
}

func TestUserEndpoints(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, true)
	profile := &models.OwnProfile{
		UserID: testUserID, Email: "user@example.com", Username: "user",
		DisplayName: "User", EmailVerified: true,
	}
	router.account.On("Profile", mock.Anything, testUserID).Return(profile, nil)
	router.account.On("UpdateDisplayName", mock.Anything, testUserID, "New Name").Return(profile, nil)
	router.account.On("LookupByUsername", mock.Anything, "user").Return(
		&models.PublicProfile{UserID: testUserID, Username: "user", DisplayName: "User"}, nil)
	router.account.On("PublicProfiles", mock.Anything, []string{testUserID, "unknown"}).Return(
		&models.PublicProfileList{Data: []models.PublicProfile{{UserID: testUserID}}}, nil)

	response := router.do(t, http.MethodGet, "/users/me", "", authHeader())
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"email":"user@example.com"`)

	response = router.do(t, http.MethodPatch, "/users/me", `{"display_name":"New Name"}`, authHeader())
	require.Equal(t, http.StatusOK, response.Code)

	response = router.do(t, http.MethodGet, "/users/lookup?username=user", "", authHeader())
	require.Equal(t, http.StatusOK, response.Code)
	require.NotContains(t, response.Body.String(), "email", "public profiles never expose email")

	response = router.do(t, http.MethodGet, "/users?ids="+testUserID+",unknown", "", authHeader())
	require.Equal(t, http.StatusOK, response.Code)

	// Missing query parameters are validation errors.
	response = router.do(t, http.MethodGet, "/users", "", authHeader())
	require.Equal(t, http.StatusUnprocessableEntity, response.Code)
	response = router.do(t, http.MethodGet, "/users/lookup", "", authHeader())
	require.Equal(t, http.StatusUnprocessableEntity, response.Code)
}

func TestTraceMiddlewarePropagatesIdentifiers(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)

	response := router.do(t, http.MethodGet, "/healthz", "", map[string]string{
		"traceparent": "00-0123456789abcdef0123456789abcdef-b7ad6b7169203331-01",
	})
	require.Equal(t, "0123456789abcdef0123456789abcdef", response.Header().Get("X-Trace-Id"))

	response = router.do(t, http.MethodGet, "/healthz", "", map[string]string{
		"X-Trace-Id": "fedcba9876543210fedcba9876543210",
	})
	require.Equal(t, "fedcba9876543210fedcba9876543210", response.Header().Get("X-Trace-Id"))

	// With no inbound identifiers a fresh trace id is minted.
	response = router.do(t, http.MethodGet, "/healthz", "", nil)
	require.Len(t, response.Header().Get("X-Trace-Id"), 32)
}

func TestMetricsRecordRouteMethodAndStatusClass(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	router.do(t, http.MethodGet, "/healthz", "", nil)

	families, err := router.registry.Gather()
	require.NoError(t, err)

	var found bool
	for _, family := range families {
		if family.GetName() != "http_requests_total" {
			continue
		}
		found = true
		labels := family.GetMetric()[0].GetLabel()
		values := map[string]string{}
		for _, label := range labels {
			values[label.GetName()] = label.GetValue()
		}
		require.Equal(t, "/healthz", values["route"])
		require.Equal(t, http.MethodGet, values["method"])
		require.Equal(t, "2xx", values["status_class"])
	}
	require.True(t, found, "http_requests_total must be exported")
}

func TestParseLimit(t *testing.T) {
	t.Parallel()

	cases := map[string]int{"": 0, "1": 1, "100": 100}
	for raw, want := range cases {
		got, err := parseLimit(raw)
		require.NoError(t, err, raw)
		require.Equal(t, want, got)
	}
	for _, raw := range []string{"0", "-1", "101", "abc", "1000"} {
		_, err := parseLimit(raw)
		require.Error(t, err, raw)
	}
}

func TestBearerTokenParsing(t *testing.T) {
	t.Parallel()

	require.Equal(t, "abc", bearerToken("Bearer abc"))
	require.Equal(t, "abc", bearerToken("bearer   abc "))
	require.Equal(t, "", bearerToken(""))
	require.Equal(t, "", bearerToken("Basic abc"))
	require.Equal(t, "", bearerToken("Bearer"))
}

func TestStatusClassMapping(t *testing.T) {
	t.Parallel()

	require.Equal(t, "2xx", metrics.StatusClass(204))
	require.Equal(t, "4xx", metrics.StatusClass(404))
	require.Equal(t, "5xx", metrics.StatusClass(503))
	require.Equal(t, "3xx", metrics.StatusClass(302))
	require.Equal(t, "1xx", metrics.StatusClass(100))
}

func TestRecoveryMiddlewareConvertsPanics(t *testing.T) {
	t.Parallel()

	router := newTestRouter(t, false)
	// Registering a panicking handler on the built engine exercises the
	// recovery middleware installed by NewRouter.
	router.engine.GET("/panic", func(context2 *gin.Context) {
		panic("boom")
	})

	response := router.do(t, http.MethodGet, "/panic", "", nil)
	require.Equal(t, http.StatusInternalServerError, response.Code)
	code, _ := decodeError(t, response)
	require.Equal(t, string(models.CodeInternalError), code)
}

var _ = context.Background
