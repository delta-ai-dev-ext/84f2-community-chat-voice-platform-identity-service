-- identity_service initial schema (docs/architecture.md §4).

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id uuid PRIMARY KEY,
    email citext NOT NULL UNIQUE,
    username citext NOT NULL UNIQUE CHECK (char_length(username) BETWEEN 2 AND 32),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64),
    email_verified boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deactivated')),
    account_version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE email_verification_tokens (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX email_verification_tokens_user_id_idx ON email_verification_tokens (user_id);

CREATE TABLE password_reset_tokens (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX password_reset_tokens_user_id_idx ON password_reset_tokens (user_id);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_label text NOT NULL DEFAULT '' CHECK (char_length(device_label) <= 100),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE INDEX sessions_user_id_active_idx ON sessions (user_id) WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    family_id uuid NOT NULL,
    token_hash text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotated', 'revoked')),
    replaced_by_id uuid REFERENCES refresh_tokens (id),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id, status);

CREATE TABLE signing_keys (
    kid text PRIMARY KEY,
    algorithm text NOT NULL,
    public_key_jwk jsonb NOT NULL,
    private_key text NOT NULL,
    status text NOT NULL CHECK (status IN ('current', 'next', 'retired')),
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);

CREATE UNIQUE INDEX signing_keys_single_current_idx ON signing_keys (status) WHERE status = 'current';

CREATE UNIQUE INDEX signing_keys_single_next_idx ON signing_keys (status) WHERE status = 'next';

CREATE TABLE login_attempts (
    id bigserial PRIMARY KEY,
    account_key text NOT NULL,
    source_key text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('success', 'failure', 'locked')),
    attempted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX login_attempts_account_time_idx ON login_attempts (account_key, attempted_at DESC);

CREATE INDEX login_attempts_source_time_idx ON login_attempts (source_key, attempted_at DESC);

CREATE TABLE event_outbox (
    id uuid PRIMARY KEY,
    topic text NOT NULL,
    key text NOT NULL,
    envelope jsonb NOT NULL,
    payload jsonb NOT NULL,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX event_outbox_unpublished_idx ON event_outbox (created_at) WHERE published_at IS NULL;
