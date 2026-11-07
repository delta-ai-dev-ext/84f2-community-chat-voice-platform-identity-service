# identity_service — Engineering Guide

Persistent technical memory for the identity service (Go). The Coding Agent MUST follow this guide; `Pinned Decisions` at the bottom is append-only.

## 1. Runtime & Toolchain

- **Language / runtime:** Go 1.26 (module initialised as `go mod init identity_service`; never a `github.com/...` module path).
- **Package manager:** Go modules (`go.mod` / `go.sum`); restore with `go mod download`, add with `go get <module>@latest` then `go mod tidy`.
- **Build/test entrypoints (Makefile):**
  - `make install` — `go mod download` (always first on a cold workspace)
  - `make test` — `go test ./... -race -count=1 -parallel 4`
  - `make build` — `docker build -t identity_service:local .` (image build runs in CI/developer environment; the agent runtime has no Docker daemon)
  - `make run` — `go run ./cmd/server`
  - `make lint` — `golangci-lint run ./...`
- **Container image:** multi-stage build `golang:1.26-alpine` → distroless static image, `CGO_ENABLED=0`, non-root `USER nonroot:nonroot`, entrypoint `/app/server`.

## 2. Libraries & External Provider SDKs

| Concern | Package / Library | Source | Usage Notes |
|---|---|---|---|
| REST API framework | `github.com/gin-gonic/gin` | language-skill | Gin context for binding/validation and responses; middleware for trace-id, auth, recovery |
| JWT issuing/verification (access tokens) | `github.com/golang-jwt/jwt/v5` | tech-lead-research | Sign RS256 with the `current` key (`kid` header); parse with the published key set; claims `sub`, `sid`, `email_verified`, `exp`, `iat`, `iss`, `aud` |
| Password hashing | `golang.org/x/crypto/argon2` | tech-lead-research | Argon2id, PHC-format encoded hash strings; verify with constant-time comparison |
| PostgreSQL driver | `github.com/jackc/pgx/v5` | language-skill | `pgxpool` pool; parameterized queries only; `citext` extension for case-insensitive email/username |
| Migrations | `github.com/golang-migrate/migrate/v4` | language-skill | Versioned SQL migrations, run at startup or as a job |
| Kafka client | `github.com/IBM/sarama` | language-skill | Sarama sync producer for `identity_events`; enables `Return.Successes`; idempotent producer mode |
| Transactional email (Resend) | `github.com/resend/resend-go/v4` | tech-lead-research | Official SDK: `resend.NewClient(apiKey)` then `client.Emails.Send(&resend.SendEmailRequest{...})`; errors via `errors.As(*resend.ResendError)` / `*resend.RateLimitError`; no built-in retries — implement bounded exponential back-off at the application boundary |
| Logging | `go.uber.org/zap` | language-skill | Structured JSON production logger; fields per §7 |
| Metrics | `github.com/prometheus/client_golang/prometheus` | language-skill | Register business + RED metrics at startup (§7 of architecture.md) |
| Environment loading | `github.com/joho/godotenv` | language-skill | Local development only; production reads plain env vars |
| Testing | `testing` + `github.com/stretchr/testify` | language-skill | `require`/`assert`; table-driven tests; `t.Parallel()` everywhere |
| Mocking | `github.com/stretchr/testify/mock` | language-skill | Mock repositories, publisher, notifier (§4) |
| HTTP mocking | `github.com/jarcoal/httpmock` | language-skill | Stub Resend HTTP calls in tests; never hit the real API |

Dependency resolution precedence: `Pinned Decisions` → existing `go.mod`/`go.sum` → this table → language-skill defaults. Resolve versions with `go get @latest`; verify unfamiliar APIs via `technical_research_agent`.

## 3. Container Lifecycle & Probes

- **Statelessness:** no local disk or in-memory session/throttle state; everything lives in PostgreSQL. Any replica can serve any request.
- **Startup:** load and validate configuration (fail fast with a structured error on missing/invalid vars), run/check migrations, open `pgxpool`, connect the Kafka producer, register metrics, then start serving.
- **Liveness `GET /healthz`:** returns `200` when the process event loop is responsive. Does NOT probe PostgreSQL/Kafka — a transient dependency hiccup must not get the container killed.
- **Readiness `GET /readyz`:** returns `200` only when the PostgreSQL pool is pingable and the Kafka producer is connected; returns `503` once shutdown has begun.
- **Graceful shutdown (`SIGTERM`/`SIGINT` via `signal.NotifyContext`):**
  1. Mark readiness failing (`503`).
  2. Stop accepting new requests; pause event publishing.
  3. Drain in-flight requests with `http.Server.Shutdown(ctx)` bounded to ~15–30 s.
  4. Flush the Kafka producer (best-effort drain of the event outbox), close the producer, close the DB pool, exit `0`.

## 4. Testing Strategy

- **Layout:** unit tests next to the code under test; integration tests in `tests/integration/`; shared doubles in `tests/mocks/` or `tests/fixtures/`.
- **All external dependencies are faked/mocked — no real network or infrastructure in tests:**
  - **PostgreSQL:** repository interfaces mocked with `testify/mock`; query logic additionally covered by an in-memory fake implementing the repository interface. No real database in the agent test run.
  - **Kafka:** the event publisher is an interface; tests use a recording fake publisher that asserts envelope completeness (`trace_id` non-empty, `schema_ref` correct, payload matches EVT-001) and ordering semantics.
  - **Resend:** the email notifier is an interface; unit tests use fakes; `httpmock` covers the thin adapter boundary (429/5xx retry behavior, idempotency key presence).
  - **Clock:** inject a `Clock` interface for token expiry, lockout windows, and throttling so tests are deterministic.
- **TDD:** write the failing test first for every behavior (registration validation, verification expiry/consumption, rotation reuse detection, throttling windows).
- **Determinism & parallelism:** every test function calls `t.Parallel()`; no shared mutable state; no sleeps — use injected clocks/tickers.
- **Coverage target:** ≥ 80 %, with exhaustive branch coverage on auth/session logic (reuse detection, lockout, enumeration-safe paths).
- **Run via Makefile only:** `make test`. No ad-hoc test commands; no Docker.

## 5. Coding Conventions & Project Structure

```
identity_service/
├── cmd/server/main.go          # entrypoint: config, wiring, graceful shutdown
├── internal/
│   ├── config/config.go        # typed Config from env, validated at startup
│   ├── handler/                # thin HTTP handlers (bind → service → respond)
│   ├── service/                # business logic (auth, session, account, keys, throttle)
│   ├── repository/             # pgx-backed data access, interfaces defined here
│   ├── events/                 # envelope construction + Kafka publisher
│   ├── email/                  # Resend notifier + adapter boundary
│   └── models/                 # domain types, request/response structs
├── migrations/                 # SQL migrations
├── tests/{unit,integration,mocks,fixtures}/
├── Makefile / Dockerfile / go.mod / go.sum
```

- **Layering:** handler → service → repository. Handlers never touch SQL; services never import gin; repositories never make policy decisions.
- **Errors:** return `error` values; wrap with context (`fmt.Errorf("...: %w", err)`); map domain errors to HTTP codes only in handlers. Never `panic` outside init. Error responses use the platform shape `{"error": "<code>", "detail": "<human text>"}` and never expose internals.
- **Typing:** exported types/functions carry doc comments; use typed constants for enums (event `change` values, token statuses); no bare `interface{}` at boundaries.
- **SQL:** parameterized only (`pgx` placeholders); no string-built SQL ever.
- **Naming:** `snake_case` JSON fields (matching the OpenAPI spec), Go idiomatic naming, package names short and lowercase.

## 6. Configuration & Secrets Management

12-factor env vars, validated at startup (fail fast). Never commit secrets; `.env` only for local development and git-ignored.

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string (`postgres://...`) |
| `KAFKA_BROKERS` | Comma-separated Kafka bootstrap brokers |
| `KAFKA_TOPIC_IDENTITY_EVENTS` | Topic name (default `identity_events`) |
| `RESEND_API_KEY` | Resend API key (secret) |
| `MAIL_FROM` | Verified sender address for transactional email |
| `APP_BASE_URL` | Public base URL used to build email links |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `iss` / `aud` claim values |
| `ACCESS_TOKEN_TTL` | Access-token lifetime (default `10m`) |
| `REFRESH_TOKEN_TTL` | Refresh-token lifetime |
| `SIGNING_KEY_ROTATION_OVERLAP` | Window the retired key stays published |
| `LOGIN_MAX_FAILURES` / `LOGIN_WINDOW` / `LOGIN_LOCKOUT` | Brute-force throttling policy |
| `SERVICE_LOG_LEVEL` | zap level (`debug` in dev, `info` in prod) |

## 7. Observability & Logging Conventions

- **Structured JSON logging** via zap: fields always include `timestamp`, `level`, `service_name` (`identity_service`), `trace_id`, `operation`, `status`, plus relevant context (e.g. `result`, `kind`). Never log passwords, tokens, token hashes, cookies, or full email bodies.
- **Trace propagation:** read `traceparent` / `X-Trace-Id` on every HTTP request (mint one when absent); include `trace_id` in every log line and propagate it into the Kafka envelope.
- **Metrics:** register the business, RED, and provider metrics listed in `docs/architecture.md` §6 at startup; low-cardinality labels only (never user/session/request ids).
- **Mandatory event envelope:** every message published to Kafka is `{"envelope": {...}, "payload": {...}}`. The envelope carries exactly: `event_id` (uuid), `event_type`, `event_version` (≥ 1), `occurred_at` (RFC3339 UTC), `producer` (`identity_service`), `trace_id` (32 lowercase hex, **never empty** — propagated from the originating request or minted at the edge of flows with no originating request), `correlation_id` (uuid), `causation_id` (uuid or null for the flow's first event), `schema_ref` (`EVENT_CONTRACTS.md#user_account_changed-v1`). The payload MUST NOT contain an envelope field at its top level. Model the envelope as a single reusable struct — never ad-hoc maps at publish sites. Mirror `trace_id` and `event_type` into Kafka message headers.

## 8. Pinned Decisions

| Dependency / Area | Pin / Constraint | Rationale | Added By | Date |
|---|---|---|---|---|
| Language / runtime | Go 1.26 | Platform-wide runtime choice from SYSTEM_DESIGN.md (security-sensitive, high-rate token issuance) | tech-lead | 2026-02-11 |
| Access-token signature | Asymmetric RS256 via `github.com/golang-jwt/jwt/v5`; JWKS publishes `current` + `next` keys | Peers verify locally without calling identity; two published keys make rotation seamless | tech-lead | 2026-02-11 |
| Password hashing | Argon2id via `golang.org/x/crypto/argon2`, PHC-format strings | Memory-hard per security standard; industry default for new services | tech-lead | 2026-02-11 |
| Refresh-token model | Opaque high-entropy tokens stored hashed, rotating chains with `family_id`; reuse of a non-active token revokes the family | Detects token theft; matches SYSTEM_DESIGN.md §2.1 | tech-lead | 2026-02-11 |
| Email SDK | `github.com/resend/resend-go/v4` (official SDK) | First-class Resend integration per SYSTEM_DESIGN.md; verified via technical research | tech-lead | 2026-02-11 |
| Event publication | Transactional outbox table + Sarama sync producer; topic `identity_events`, key `user_id` | Committed state changes are never lost; at-least-once with consumer-side dedupe on `event_id` | tech-lead | 2026-02-11 |
| Account change tracking | `users.account_version` monotonic counter in every EVT-001 snapshot | Consumers apply only newer snapshots (stale-version guard) | tech-lead | 2026-02-11 |
