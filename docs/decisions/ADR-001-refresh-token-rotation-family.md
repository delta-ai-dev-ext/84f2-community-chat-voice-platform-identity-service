# ADR-001 — Refresh-token rotation family with reuse detection

- **Status:** Accepted
- **Date:** 2026-02-11
- **Deciders:** Tech Lead (identity_service)

## Context

The platform issues short-lived access tokens (~10 min, verified locally by peers via JWKS) and long-lived refresh tokens carried in an `HttpOnly; Secure; SameSite=Strict` cookie. A long-lived bearer cookie that never changes is a high-value theft target: once copied, it works until it expires. The system design mandates rotating refresh tokens and "reuse revokes the whole session family", but not the mechanism.

## Decision

1. Refresh tokens are **opaque, high-entropy random values** (not JWTs). Only a SHA-256 hash is stored; the raw value exists only in the cookie.
2. Every refresh creates a **new token row** and marks the presented one `rotated`, linked via `replaced_by_id`. All tokens descending from one sign-in share a `family_id`.
3. **Reuse detection:** presenting a token whose status is not `active` (already rotated or revoked) is treated as evidence of theft — the service revokes the session and every token in the `family_id`. The legitimate user is forced to sign in again.
4. Revoking a session (logout, logout-all, password reset, family revocation) always revokes the whole family, so access-token `sid` claims become stale in one step.

## Consequences

- A copied cookie is detected the first time the legitimate client refreshes (the stolen replay loses the race and kills the family).
- Users behind flaky networks that drop the refresh response can be logged out once (family revoked) — accepted; the client re-signs in. Mitigation at the client: persist nothing, re-login is cheap.
- Password reset revoking all sessions is a single bulk update over `sessions`/`refresh_tokens` by `user_id`.
- No per-request cryptographic cost for refresh (hash lookup only), keeping `/auth/refresh` p95 < 50 ms feasible.

## Alternatives considered

- **JWT refresh tokens with `jti` denylist** — requires a denylist store anyway (no win over opaque tokens) and puts claims in a long-lived credential.
- **Non-rotating long-lived tokens** — simplest, but a stolen cookie is undetectable; rejected by the system design.

## References

- `docs/architecture.md` §2.1 (sign-in/refresh flows), §4 (`sessions`, `refresh_tokens` schema)
- `docs/user_stories.md` US-006, US-007
- `SYSTEM_DESIGN.md` §2.1 (identity_service)
