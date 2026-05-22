CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS sfae_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  domain text NOT NULL,
  label text,
  keys text[] NOT NULL,
  value text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sfae_credentials_user_domain_idx
  ON sfae_credentials (user_id, domain);

CREATE TABLE IF NOT EXISTS oauth_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  state_hash text NOT NULL UNIQUE,
  provider text NOT NULL,
  user_id text NOT NULL,
  domain text NOT NULL,
  label text,
  scopes text[] NOT NULL,
  return_url text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  error_code text,
  provider_subject text,
  credential_id uuid,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE oauth_sessions
  ADD COLUMN IF NOT EXISTS session_mode text NOT NULL DEFAULT 'backend',
  ADD COLUMN IF NOT EXISTS redeem_challenge_hash text,
  ADD COLUMN IF NOT EXISTS redeem_challenge_method text,
  ADD COLUMN IF NOT EXISTS completion_challenge_hash text,
  ADD COLUMN IF NOT EXISTS completion_verifier_ciphertext text,
  ADD COLUMN IF NOT EXISTS local_credential_ciphertext text,
  ADD COLUMN IF NOT EXISTS redeemed_at timestamptz;

CREATE INDEX IF NOT EXISTS oauth_sessions_user_provider_idx
  ON oauth_sessions (user_id, provider, created_at DESC);

CREATE INDEX IF NOT EXISTS oauth_sessions_mode_created_idx
  ON oauth_sessions (session_mode, created_at DESC);

CREATE TABLE IF NOT EXISTS oauth_accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL,
  provider text NOT NULL,
  provider_subject text NOT NULL,
  display_name text,
  email text,
  scopes text[] NOT NULL,
  status text NOT NULL DEFAULT 'active',
  last_authorized_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, provider, provider_subject)
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  account_id uuid PRIMARY KEY REFERENCES oauth_accounts(id) ON DELETE CASCADE,
  access_token_ciphertext text NOT NULL,
  refresh_token_ciphertext text,
  token_type text,
  scopes text[] NOT NULL,
  expires_at timestamptz,
  refresh_version integer NOT NULL DEFAULT 0,
  last_refresh_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS local_oauth_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider text NOT NULL,
  provider_subject text NOT NULL,
  secret_hash text NOT NULL,
  refresh_token_hash text,
  status text NOT NULL DEFAULT 'active',
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE local_oauth_grants
  ADD COLUMN IF NOT EXISTS refresh_token_hash text;

CREATE INDEX IF NOT EXISTS local_oauth_grants_provider_subject_idx
  ON local_oauth_grants (provider, provider_subject);

CREATE TABLE IF NOT EXISTS oauth_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid,
  account_id uuid,
  provider text NOT NULL,
  event_type text NOT NULL,
  error_code text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
