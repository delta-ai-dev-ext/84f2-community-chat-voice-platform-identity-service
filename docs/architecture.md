# identity_service — Architecture

Clean service-level architecture for the identity service of the Community Chat & Voice Platform. This document is the source of truth for behavior and data; implementation details (libraries, frameworks, file layout) live in `docs/engineering_guide.md`.

## 1. Service Responsibilities & Boundaries

`identity_service` owns everything about **who a user is and how they prove it**:

1. **Account lifecycle** — registration (email, username, display name, password), email verification (single-use hashed tokens, 24 h expiry), resend of verification emails, and account deactivation (supported by the event contract).
2. **Authentication** — sign-in with email + password (memory-hard salted credential verification), sign-out of the current session or all sessions.
3. **Session & token management** — short-lived signed access tokens (JWT, asymmetric signature, ~10 min) and long-lived **rotating** refresh tokens delivered as `HttpOnly; Secure; SameSite=Strict` cookies. Refresh-token **reuse detection** revokes the entire session family. Access tokens carry claims `sub` (user_id), `sid` (session id), `email_verified`, `exp`, `iat`, `iss`, `aud`.
4. **Token signing keys** — owns the signing keys and their rotation; publishes current + next public keys at `GET /.well-known/jwks.json` so every peer verifies tokens **locally** (no runtime call to this service).
5. **Password reset** — request (single-use hashed token, 1 h expiry, always-202 response with no account enumeration) and confirm (revokes all sessions of the account, sends a confirmation email).
6. **Brute-force protection** — per-account and per-IP sign-in throttling with temporary lockout, persisted in PostgreSQL (survives restarts and is shared across replicas).
7. **Public profile lookup** — username → public profile and batch user_id → public profiles (up to 100), used by the frontend and peer services to render names.

**Does NOT own:** communities, channels, memberships, roles, or permissions (`community_service`); messaging, moderation, social graph, voice, notifications, or realtime delivery.

**Internal components:**

| Component | Responsibility |
|---|---|
| Auth handlers | HTTP surface for `/auth/*` (register, verify, login, refresh, logout, logout-all, password reset) |
| Session/token service | Session lifecycle, access-token minting, refresh rotation + reuse detection, throttling policy |
| Account/profile service | Registration, verification, profile updates, public lookups |
| Key manager | Signing-key generation, rotation (current → next → retired), JWKS publication |
| Email notifier | Transactional email via Resend (verification, reset, password-changed confirmation) with idempotency and bounded retries |
| Event publisher | Publishes account-change events to Kafka with the mandatory envelope |

## 2. Flows

### 2.1 Synchronous HTTP flows

**Registration → verification:**
1. `POST /auth/register` — validate input, check email/username uniqueness (case-insensitive), create user + credential in one transaction, honor `Idempotency-Key` for client retries.
2. Generate a single-use verification token; store only its **hash** (24 h expiry).
3. Send the verification email via Resend using an idempotency key derived from the token id; retry with bounded exponential back-off on 429/5xx. On ultimate failure the account still exists and the user can use resend (US-003).
4. `POST /auth/verify-email` — hash-lookup the token, check expiry/used state, mark the account verified, consume the token, and publish `user_account_changed` (`change: email_verified`) with an incremented `account_version`.

**Sign-in:**
1. `POST /auth/login` — resolve account by email; record the attempt for throttling; verify the password hash.
2. Outcomes: success → create a `Session` row (device label) + refresh-token family, issue the access JWT signed with the current key, set the refresh cookie; unverified → `403 email_not_verified`; bad credentials → `401 invalid_credentials`; throttled/locked → `429 locked`.
3. `/auth/refresh` — validate the cookie's refresh token: active → rotate (mark old token rotated, link to its replacement, issue new access token); **reused/rotated token → revoke the whole session family** and return `401 session_revoked`; expired/missing → `401 invalid_refresh_token`.

**Sign-out / session management:**
- `POST /auth/logout` — revoke the current session and its refresh family; clear the cookie. Idempotent.
- `POST /auth/logout-all` — revoke every session of the user.
- `GET /sessions` — active sessions of the caller (cursor pagination); `DELETE /sessions/{session_id}` — revoke one (404 when not owned/active).

**Password reset:**
1. `POST /auth/password-reset/request` — always `202`; if the account exists, mint a single-use token (hash stored, 1 h expiry, previous pending token invalidated) and email it.
2. `POST /auth/password-reset/confirm` — validate token (`410 reset_link_expired` for expired/unknown/used), replace the credential hash, **revoke all sessions** of the account, send the password-changed confirmation email, return `204`.

**Profile & lookup:**
- `GET /users/me` / `PATCH /users/me` — own profile view and display-name update (publishes `user_account_changed` with `change: profile_updated`).
- `GET /users/lookup?username=` and `GET /users?ids=` — public profiles only (`user_id`, `username`, `display_name`); never email or internal state.

**Key publication:** `GET /.well-known/jwks.json` returns the current and next public keys. Rotation: generate the `next` key, publish both, cut signing over to `next`, then retire the old key after the overlap window (access tokens outlive it by design margin).

### 2.2 Asynchronous flows (Kafka producer)

- Topic **`identity_events`**, key = `user_id`, event **`user_account_changed` (EVT-001)**, published on: email verification, display-name update, email change, deactivation.
- Every message is `{"envelope": {...}, "payload": {...}}` per the mandatory envelope (see Inter-Service Contracts below). `trace_id` comes from the originating HTTP request; a background flow (e.g. scheduled token cleanup) mints one at the edge.
- Publishing happens **after** the PostgreSQL transaction commits (transactional outbox, §4); a failed publish is retried (at-least-once). The payload is a full snapshot with a monotonically increasing `account_version` so consumers apply only newer versions.
- Verification and reset **tokens are never published**.

### 2.3 External provider integration — Resend (transactional email)

- Outbound only; **no inbound webhook at launch**.
- Emails: verification (on register / resend), password reset, password-changed confirmation.
- Each send carries an **idempotency key derived from the token id**, so an at-least-once retry cannot cause duplicate emails.
- Failures: bounded exponential back-off on transient errors (429/5xx); on final failure the user-facing flow returns "we couldn't send the email, try again" (`503 email_unavailable`) and the token is not consumed (or, for confirmation emails, the failure is logged and does not fail the main operation).
- Tokens are embedded only in links inside the email body; they never appear in events, logs, or other services.

## Inter-Service Contracts

Synchronous internal calls: **none** — identity is the origin of trust; peers verify tokens locally from the JWKS. The Dependency Registry contains one edge for this service (DEP-004, async, EVT-001).

### Envelope (mandatory, every event)

Every message on every topic is a JSON object with exactly two top-level keys, `envelope` and `payload`:

| Field | Type | Required | Rule |
|---|---|---|---|
| `event_id` | string (uuid) | yes | Unique per event. Consumer deduplication key. |
| `event_type` | string (snake_case) | yes | Must match a registered contract. |
| `event_version` | integer | yes | >= 1. A breaking payload change bumps it. |
| `occurred_at` | string (RFC3339 UTC) | yes | Producer clock at emit time. |
| `producer` | string (snake_case) | yes | Must equal the registered producer. |
| `trace_id` | string (32 lowercase hex) | yes | **Never empty.** Propagated from the originating request; minted at the edge when absent. |
| `correlation_id` | string (uuid) | yes | Groups every event of one business flow. |
| `causation_id` | string (uuid) or null | yes | `event_id` of the causing event. `null` only for the flow's first event. |
| `schema_ref` | string | yes | `EVENT_CONTRACTS.md#<event_type>-v<version>`. |

Rules: the envelope is not optional and not per-topic; a payload MUST NOT declare an envelope field name at its top level; the envelope is also mirrored into Kafka message headers (`trace_id`, `event_type`); delivery is at-least-once and consumers dedupe on `envelope.event_id`.

### EVT-001 — `user_account_changed` v1 (produced)

Producer `identity_service`, consumer `notification_service`, topic `identity_events`, key `user_id`; delivery at-least-once, consumers dedupe on `envelope.event_id` and apply only if `account_version` is newer.

**Payload** (the `payload` object), copied verbatim from `EVENT_CONTRACTS.md`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["user_id", "change", "email", "username", "display_name", "email_verified", "status", "account_version"],
  "properties": {
    "user_id": {"type": "string", "format": "uuid"},
    "change": {"type": "string", "enum": ["email_verified", "profile_updated", "email_changed", "deactivated"]},
    "email": {"type": "string", "format": "email"},
    "username": {"type": "string", "minLength": 2, "maxLength": 32},
    "display_name": {"type": "string", "minLength": 1, "maxLength": 64},
    "email_verified": {"type": "boolean"},
    "status": {"type": "string", "enum": ["active", "deactivated"]},
    "account_version": {"type": "integer", "minimum": 1}
  }
}
```

## 4. PostgreSQL Database Schema

All tables are owned by this service. UUIDs are generated by the service. Timestamps are `timestamptz`.

### `users`
| Column | Type | Constraints |
|---|---|---|
| `id` | `uuid` | PK |
| `email` | `citext` | UNIQUE NOT NULL (case-insensitive) |
| `username` | `citext` | UNIQUE NOT NULL (case-insensitive), `CHECK (char_length(username) BETWEEN 2 AND 32)` |
| `display_name` | `text` | NOT NULL, `CHECK (char_length(display_name) BETWEEN 1 AND 64)` |
| `email_verified` | `boolean` | NOT NULL DEFAULT `false` |
| `status` | `text` | NOT NULL, `CHECK (status IN ('active','deactivated'))` DEFAULT `'active'` |
| `account_version` | `bigint` | NOT NULL DEFAULT 1 (incremented on every event-worthy change) |
| `created_at` | `timestamptz` | NOT NULL DEFAULT `now()` |
| `updated_at` | `timestamptz` | NOT NULL DEFAULT `now()` |

### `credentials`
| Column | Type | Constraints |
|---|---|---|
| `user_id` | `uuid` | PK, FK → `users(id)` `ON DELETE CASCADE` |
| `password_hash` | `text` | NOT NULL (salted memory-hard hash, PHC string format) |
| `updated_at` | `timestamptz` | NOT NULL DEFAULT `now()` |

### `email_verification_tokens`
| Column | Type | Constraints |
|---|---|---|
| `id` | `uuid` | PK |
| `user_id` | `uuid` | NOT NULL, FK → `users(id)` `ON DELETE CASCADE` |
| `token_hash` | `text` | UNIQUE NOT NULL (SHA-256 of the opaque token) |
| `expires_at` | `timestamptz` | NOT NULL (issued_at + 24 h) |
| `consumed_at` | `timestamptz` | NULL until used |
| `created_at` | `timestamptz` | NOT NULL DEFAULT `now()` |

Indexes: unique on `token_hash`, index on `user_id`. Issuing a new token for a user marks prior unconsumed tokens consumed (single pending token per user).

### `password_reset_tokens`
| Column | Type | Constraints |
|---|---|---|
| `id` | `uuid` | PK |
| `user_id` | `uuid` | NOT NULL, FK → `users(id)` `ON DELETE CASCADE` |
| `token_hash` | `text` | UNIQUE NOT NULL |
| `expires_at` | `timestamptz` | NOT NULL (issued_at + 1 h) |
| `consumed_at` | `timestamptz` | NULL until used |
| `created_at` | `timestamptz` | NOT NULL DEFAULT `now()` |

Indexes: unique on `token_hash`, index on `user_id`. Single pending token per user (same invalidation rule).

### `sessions`
| Column | Type | Constraints |
|---|---|---|
| `id` | `uuid` | PK (= JWT `sid` claim) |
| `user_id` | `uuid` | NOT NULL, FK → `users(id)` `ON DELETE CASCADE` |
| `device_label` | `text` | NOT NULL DEFAULT `''` (≤ 100 chars) |
| `created_at` | `timestamptz` | NOT NULL DEFAULT `now()` |
| `last_seen_at` | `timestamptz` | NOT NULL DEFAULT `now()` |
| `revoked_at` | `timestamptz` | NULL while active |

Indexes: `sessions_user_id_active_idx` ON (`user_id`) WHERE `revoked_at IS NULL`; PK index serves `sid` lookup.

### `refresh_tokens`
| Column | Type | Constraints |
|---|---|---|
| `id` | `uuid` | PK |
| `session_id` | `uuid` | NOT NULL, FK → `sessions(id)` `ON DELETE CASCADE` |
| `family_id` | `uuid` | NOT NULL (rotation family; all tokens of one session share it) |
| `token_hash` | `text` | UNIQUE NOT NULL |
| `status` | `text` | NOT NULL, `CHECK (status IN ('active','rotated','revoked'))` DEFAULT `'active'` |
| `replaced_by_id` | `uuid` | NULL, FK → `refresh_tokens(id)` (rotation chain) |
| `expires_at` | `timestamptz` | NOT NULL |
| `created_at` | `timestamptz` | NOT NULL DEFAULT `now()` |

Indexes: unique on `token_hash`; `refresh_tokens_family_idx` ON (`family_id`, `status`). Reuse detection: presenting a token with `status <> 'active'` revokes the session and every token of its `family_id`.

### `signing_keys`
| Column | Type | Constraints |
|---|---|---|
| `kid` | `text` | PK (key id, appears in JWT header and JWKS) |
| `algorithm` | `text` | NOT NULL (asymmetric signing algorithm) |
| `public_key_jwk` | `jsonb` | NOT NULL (public part published via JWKS) |
| `private_key` | `text` | NOT NULL (private key material, never exposed via API) |
| `status` | `text` | NOT NULL, `CHECK (status IN ('current','next','retired'))` |
| `created_at` | `timestamptz` | NOT NULL DEFAULT `now()` |
| `retired_at` | `timestamptz` | NULL until retired |

Exactly one `current` and at most one `next` at any time.

### `login_attempts` (throttling records)
| Column | Type | Constraints |
|---|---|---|
| `id` | `bigserial` | PK |
| `account_key` | `text` | NOT NULL (normalized email of the attempted account; `'_'` when unknown) |
| `source_key` | `text` | NOT NULL (normalized client IP or network prefix) |
| `outcome` | `text` | NOT NULL, `CHECK (outcome IN ('success','failure','locked'))` |
| `attempted_at` | `timestamptz` | NOT NULL DEFAULT `now()` |

Indexes: `login_attempts_account_time_idx` ON (`account_key`, `attempted_at` DESC); `login_attempts_source_time_idx` ON (`source_key`, `attempted_at` DESC). Throttle decisions are computed from rolling windows over these rows; a success resets the account's failure window.

### `event_outbox`
| Column | Type | Constraints |
|---|---|---|
| `id` | `uuid` | PK |
| `topic` | `text` | NOT NULL |
| `key` | `text` | NOT NULL (Kafka message key, e.g. user_id) |
| `envelope` | `jsonb` | NOT NULL |
| `payload` | `jsonb` | NOT NULL |
| `published_at` | `timestamptz` | NULL until published |
| `created_at` | `timestamptz` | NOT NULL DEFAULT `now()` |

Index: `event_outbox_unpublished_idx` ON (`created_at`) WHERE `published_at IS NULL`. Event publication uses this transactional outbox, so a committed state change is never lost and a published event is never duplicated beyond at-least-once.

### Relationships
`users 1—1 credentials`; `users 1—N email_verification_tokens`; `users 1—N password_reset_tokens`; `users 1—N sessions`; `sessions 1—N refresh_tokens` (self-referencing `replaced_by_id` rotation chain within a `family_id`).

## 5. Stateless Container Operational Model

- **Statelessness:** all state lives in PostgreSQL; no local disk or in-memory session state. Safe with `replicas >= 1`; throttling and rotation work identically on any replica because they are DB-backed.
- **Probes:** `GET /healthz` (liveness — process responsive; does not check dependencies) and `GET /readyz` (readiness — PostgreSQL reachable and Kafka producer connected; returns `503` once shutdown starts).
- **Graceful shutdown:** on `SIGTERM`/`SIGINT` — mark readiness failing, stop accepting new HTTP requests, finish in-flight requests within a bounded timeout, flush/close the Kafka producer (publish any pending outbox rows if possible), close the DB pool, exit `0`.
- **Failure modes & resilience:**
  - **Resend outage** → bounded exponential back-off, then surfaced as `503 email_unavailable` for token-bearing flows; confirmation-email failure never fails the main operation.
  - **Kafka unavailable** → user-facing auth flows still succeed; events remain in the outbox and are published when connectivity returns.
  - **PostgreSQL unavailable** → readiness fails; auth endpoints return `503`.
  - **Idempotency:** `Idempotency-Key` on registration; Resend sends keyed by token id; refresh rotation and logout are inherently idempotent.
  - **Timing/enumeration safety:** failed logins and unknown accounts take comparable time (constant-time comparisons, dummy hash verification); password-reset and resend always answer `202`.

## 6. Observability

**Business metrics (low-cardinality labels only):**
- `identity_registrations_total{result}` (`success|duplicate|invalid`)
- `identity_email_verifications_total{result}` (`success|expired|used|already_verified`)
- `identity_logins_total{result}` (`success|invalid_credentials|unverified|locked`)
- `identity_password_resets_total{stage,result}` (`stage=request|confirm`)
- `identity_active_sessions` (gauge)
- `identity_emails_sent_total{kind,result}` (`kind=verification|password_reset|password_changed`)
- RED metrics: `http_requests_total{route,method,status_class}`, `http_request_duration_seconds{route,method}`
- Provider: `external_call_duration_seconds{provider="resend",operation}`, `external_call_errors_total{provider="resend",operation,error_class}`

**SLOs:** `/auth/login` p95 < 300 ms (password hashing dominated), `/auth/refresh` p95 < 50 ms, 5xx rate < 0.1 %, Resend send success ≥ 99.5 %.

**Tracing:** `traceparent` / `X-Trace-Id` propagated on every HTTP request and mirrored into the Kafka envelope's `trace_id`; all logs carry the active `trace_id`.

## 7. Security Invariants

- Passwords stored only as salted memory-hard hashes; plaintext never logged or persisted.
- Verification/reset tokens and refresh tokens stored only as hashes; opaque, high-entropy, single-use.
- Refresh cookie: `HttpOnly; Secure; SameSite=Strict`, scoped path.
- No account enumeration on resend, reset request, or login (same error for unknown email vs. wrong password).
- Access tokens contain no PII beyond `sub`/`sid`; private keys never leave the service and are never served by any endpoint.
- Throttling state is persisted (shared across replicas, survives restarts).
- All SQL is parameterized; all external inputs validated at the boundary.
