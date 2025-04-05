DROP INDEX IF EXISTS idx_auth_tokens_owner_id;

ALTER TABLE auth_tokens RENAME COLUMN owner_id TO user_id;

CREATE INDEX idx_auth_tokens_user_id ON auth_tokens (user_id);