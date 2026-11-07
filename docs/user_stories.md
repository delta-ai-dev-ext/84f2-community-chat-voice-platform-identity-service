# identity_service — User Stories

Behavioral requirements for the identity service: accounts, email verification, sign-in, sessions, access/refresh tokens, password reset, public profile lookup, and signing-key publication. Derived from the system design; not from any API artifact.

Conventions referenced below: errors are `{"error": "<code>", "detail": "<human text>"}`; email delivery is transactional via Resend; verification/reset tokens never leave this service.

---

## US-001: Register an account

**As a** visitor,
**I want to** create an account with my email, username, display name, and password,
**So that** I can join communities and chat.

### Acceptance Criteria
- Given a valid, unused email and username and a password meeting the strength policy, when I submit registration, then an account is created unverified and I receive a response with my `user_id` and `verification_pending: true`.
- Given registration succeeds, then a verification email is sent to my address within seconds.
- Given the email is already registered, when I submit registration, then I receive `409` with error `email_already_registered` and no email is sent.
- Given the username is already taken (case-insensitively), when I submit registration, then I receive `409` with error `username_taken`.
- Given a malformed payload (bad email, username outside 2–32 chars, display name empty or over 64 chars, weak password), when I submit, then I receive `422` with error `validation_failed` and nothing is created.
- Given a retried registration with the same `Idempotency-Key`, when the first attempt already succeeded, then no duplicate account is created and the original result is returned.

### Out of Scope
- Social login, phone numbers, and age verification.

---

## US-002: Verify my email address

**As a** new registrant,
**I want to** confirm my email by following the emailed link/token,
**So that** other members can reach me and I can sign in.

### Acceptance Criteria
- Given a valid, unexpired (≤ 24 h), unused verification token, when I submit it, then my email is marked verified and the response identifies the verified user.
- Given verification succeeds for a first-time verification, then downstream services are informed that my account is reachable (account snapshot published) with `change: email_verified`.
- Given an already-used token, when I submit it, then I receive `410` with error `verification_link_used`.
- Given an expired (> 24 h) or unknown token, when I submit it, then I receive `410` with error `verification_link_expired`.
- Given an already-verified account, when I submit a valid-but-new token, then I receive `409` with error `already_verified` and no duplicate event is published.

### Out of Scope
- Changing the email address through the verification flow (email change is a profile concern, see US-012).

---

## US-003: Request a new verification email

**As a** registrant whose verification link expired or was lost,
**I want to** request a fresh verification email,
**So that** I can still verify my address.

### Acceptance Criteria
- Given an existing unverified account for the submitted email, when I request a resend, then the request is accepted (`202`) and a new single-use token (invalidating the previous one) is emailed.
- Given the email does not belong to any account, when I request a resend, then I still receive `202` (no account enumeration).
- Given the email belongs to an already-verified account, when I request a resend, then I still receive `202` and no email is sent.
- Given an email provider outage, when the send ultimately fails after bounded retries, then I receive a clear "we couldn't send the email, try again" outcome and no token is consumed.

### Out of Scope
- Bulk or unsolicited resend flooding protection beyond per-account/per-IP throttling (see US-005).

---

## US-004: Sign in

**As a** registered user,
**I want to** sign in with my email and password,
**So that** I can use the platform on this device.

### Acceptance Criteria
- Given correct credentials for an active account, when I sign in, then I receive a short-lived signed access token and a long-lived rotating refresh token set as an HttpOnly, Secure, SameSite cookie, and a new session is recorded with a device label.
- Given correct credentials but an unverified email, when I sign in, then I receive `403` with error `email_not_verified` and no tokens are issued.
- Given a wrong password or unknown email, when I sign in, then I receive `401` with error `invalid_credentials` (indistinguishable between the two).
- Given my account is temporarily locked from repeated failures, when I sign in with correct credentials, then I receive `429` with error `locked` and the response indicates when to retry.
- Given the issued access token, when any service verifies it locally, then it validates against this service's published public keys and carries claims `sub`, `sid`, `email_verified`, `exp`, `iat`, `iss`, `aud`.
- Given an access token signed by a retired key, when it is verified, then verification fails once that key is removed from publication.

### Out of Scope
- Two-factor authentication and "remember this device" prompts.

---

## US-005: Be protected from brute-force sign-in attempts

**As a** platform operator,
**I want** sign-in attempts throttled per account and per source,
**So that** password guessing is impractical.

### Acceptance Criteria
- Given repeated failed sign-ins for the same account within the throttle window, when the failure threshold is exceeded, then further attempts get `429 locked` until the lockout expires, even with the correct password.
- Given repeated failed sign-ins from the same source address across different accounts, when the per-source threshold is exceeded, then further attempts from that source get `429 locked`.
- Given a successful sign-in, when it occurs, then the failure counters for that account reset.
- Given a locked window that has expired, when the user retries, then sign-in proceeds normally.

### Out of Scope
- CAPTCHA or third-party anti-abuse services.

---

## US-006: Stay signed in across normal browser use

**As a** signed-in user,
**I want** my session to renew silently while I use the app,
**So that** I am not unexpectedly logged out.

### Acceptance Criteria
- Given a valid, unexpired, unused refresh token cookie, when I refresh, then I receive a new short-lived access token and a new refresh cookie, and the old refresh token can never be used again.
- Given a refresh, when it succeeds, then the session's last-seen timestamp advances.
- Given an expired refresh token, when I refresh, then I receive `401` with error `invalid_refresh_token` and the cookie is cleared.
- Given a missing refresh cookie, when I refresh, then I receive `401` with error `invalid_refresh_token`.

### Out of Scope
- Multi-device token sharing warnings.

---

## US-007: Detect stolen refresh tokens

**As a** platform operator,
**I want** reuse of an already-rotated refresh token to revoke the whole session family,
**So that** a stolen token cannot outlive its legitimate use.

### Acceptance Criteria
- Given a refresh token that was already rotated (used once), when it is presented again, then the entire session family (all refresh tokens of that session) is revoked and the caller gets `401` with error `session_revoked`.
- Given a revoked family, when the legitimate user refreshes with the current token, then they get `401` and must sign in again.
- Given a normal single rotation, when it completes, then no family member is revoked.

### Out of Scope
- Notification emails about session revocation.

---

## US-008: Sign out of my current session

**As a** signed-in user,
**I want to** end my current session,
**So that** a shared or lost device stops having access.

### Acceptance Criteria
- Given an authenticated caller, when I sign out, then the current session is revoked, its refresh token family is invalidated, and I receive `204`.
- Given an already-revoked session, when I sign out again with the same token, then I still receive `204` (idempotent).
- Given an unauthenticated caller, when they attempt sign-out, then they receive `401`.

### Out of Scope
- Remote sign-out of other devices via this endpoint (see US-009).

---

## US-009: See and end all of my sessions

**As a** signed-in user,
**I want to** list my active sessions and end any of them (or all at once),
**So that** I control every device that can act as me.

### Acceptance Criteria
- Given an authenticated caller, when I list my sessions, then I see each active session's id, device label, created and last-seen times, and which one is current — paginated with `cursor`/`limit`.
- Given an authenticated caller, when I revoke one of my own sessions by id, then that session and its refresh family are revoked and I receive `204`.
- Given a session id that is not mine (or unknown), when I revoke it, then I receive `404` with error `session_not_found` and nothing is changed.
- Given an authenticated caller, when I end every session, then all my sessions (including the current one) are revoked and I receive `204`.
- Given revoked sessions, when I list sessions again, then they no longer appear as active.

### Out of Scope
- Admin-initiated session revocation.

---

## US-010: Start a password reset

**As a** user who forgot my password,
**I want to** request a reset link by email,
**So that** I can regain access to my account.

### Acceptance Criteria
- Given the email of an existing account, when I request a reset, then the request is accepted (`202`) and a single-use, 1-hour token is emailed.
- Given an email that does not belong to any account, when I request a reset, then I still receive `202` (no account enumeration) and no email is sent.
- Given a pending reset request, when I request again, then a new token is issued and the previous one is invalidated.
- Given an email provider failure after bounded retries, when the send ultimately fails, then I receive a clear "we couldn't send the email, try again" outcome and no token is consumed.

### Out of Scope
- Password reset via SMS or security questions.

---

## US-011: Complete a password reset

**As a** user with a valid reset token,
**I want to** set a new password,
**So that** I can sign in again securely.

### Acceptance Criteria
- Given a valid, unexpired, unused reset token and a password meeting the strength policy, when I confirm, then my password is replaced and I receive `204`.
- Given a successful reset, then every active session of the account is revoked (all refresh families invalidated) and a password-changed confirmation email is sent.
- Given an expired (> 1 h) or unknown token, when I confirm, then I receive `410` with error `reset_link_expired`.
- Given an already-used token, when I confirm, then I receive `410` with error `reset_link_expired` (re-use is indistinguishable from expiry).
- Given a weak new password, when I confirm, then I receive `422` with error `validation_failed` and the password is unchanged.

### Out of Scope
- Notifying other active devices individually (revocation is blanket).

---

## US-012: View and update my own profile

**As a** signed-in user,
**I want to** see my profile and change my display name,
**So that** others see who I am.

### Acceptance Criteria
- Given an authenticated caller, when I fetch my profile, then I see my user id, email, username, display name, and verification status.
- Given an authenticated caller, when I update my display name (1–64 chars), then the new value is returned and downstream services are informed (account snapshot published with `change: profile_updated`).
- Given an unauthenticated caller, when they fetch or update the profile, then they receive `401`.
- Given an empty or over-long display name, when I update, then I receive `422` with error `validation_failed` and the value is unchanged.

### Out of Scope
- Changing username or email at launch (email change is supported by the account event contract but no UI/endpoint flow is in scope beyond the contract).

---

## US-013: Find people by username and render names in bulk

**As a** platform user (via the frontend) and peer services,
**I want to** resolve a username to a public profile and fetch display names for a batch of user ids,
**So that** I can befriend people and UIs render names instead of ids.

### Acceptance Criteria
- Given a username that exists, when I look it up, then I receive the public profile: `user_id`, `username`, `display_name` (no email, no status internals).
- Given an unknown username, when I look it up, then I receive `404` with error `user_not_found`.
- Given a batch of up to 100 user ids, when I query, then I receive the public profiles of the found users; unknown ids are simply absent from the result.
- Given more than 100 ids in one batch, when I query, then I receive `422` with error `validation_failed`.
- Given an unauthenticated caller, when they use either lookup, then they receive `401`.

### Out of Scope
- Fuzzy search, directories, or public discovery (explicitly out of scope platform-wide).

---

## US-014: Publish token verification keys

**As a** peer service or operator tooling,
**I want to** fetch the current and next public verification keys,
**So that** access tokens can be verified locally and key rotation does not break anyone.

### Acceptance Criteria
- Given the service is running, when the JWKS endpoint is fetched, then it returns the current and next public keys in standard JWKS form, unauthenticated.
- Given a key rotation in progress, when the JWKS is fetched, then both the outgoing and incoming public keys are present so no verifier fails during the overlap.
- Given a retired key past its overlap window, when the JWKS is fetched, then that key is absent and tokens signed by it stop validating.

### Out of Scope
- Private key material exposure (private keys never leave this service).

---

## US-015: Notify the platform when an account changes

**As a** downstream service (notification inbox),
**I want** account changes published as events,
**So that** my contact projections stay accurate.

### Acceptance Criteria
- Given email verification, display-name update, email change, or deactivation, when the change commits, then an account-changed event is published with the full account snapshot (user id, email, username, display name, verified flag, status, account version) and a monotonic version that downstream consumers use to ignore stale snapshots.
- Given a publish that fails transiently, when the system retries, then no duplicate logical change is observable by consumers (at-least-once delivery with deduplication keys).
- Given registration without verification, when it occurs, then no account event is published (the account is not yet reachable).

### Out of Scope
- Publishing verification or reset tokens (they never leave this service).
