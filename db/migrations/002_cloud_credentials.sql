CREATE TABLE IF NOT EXISTS cloud_credentials (
    id            SERIAL PRIMARY KEY,
    owner         TEXT NOT NULL,
    label         TEXT NOT NULL,
    provider      TEXT NOT NULL CHECK (provider IN ('azure', 'gcp')),
    purpose       TEXT NOT NULL CHECK (purpose IN ('read', 'operate', 'deploy')),
    config        JSONB NOT NULL,
    secret_enc    TEXT NOT NULL,
    hint          TEXT,
    verified_at   TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ DEFAULT now(),
    UNIQUE (owner, label)
);
