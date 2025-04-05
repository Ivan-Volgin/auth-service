ALTER TABLE auth_tokens RENAME COLUMN user_id TO owner_id;

DROP INDEX IF EXISTS idx_auth_tokens_user_id;
CREATE INDEX idx_auth_tokens_owner_id ON auth_tokens (owner_id);