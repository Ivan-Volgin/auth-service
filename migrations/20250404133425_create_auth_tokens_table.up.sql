CREATE TABLE auth_tokens
(
    id                 SERIAL PRIMARY KEY,
    user_id           UUID        NOT NULL,
    access_token       TEXT        NOT NULL UNIQUE,
    refresh_token      TEXT        NOT NULL UNIQUE,
    access_expires_at  TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_auth_tokens_user_id ON auth_tokens (user_id);