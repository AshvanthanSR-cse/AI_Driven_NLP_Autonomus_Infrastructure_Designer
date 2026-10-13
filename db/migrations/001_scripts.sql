CREATE TABLE IF NOT EXISTS scripts (
    id           SERIAL PRIMARY KEY,
    owner        TEXT NOT NULL,
    title        TEXT NOT NULL,
    request      TEXT,
    steps        JSONB NOT NULL,
    script_text  TEXT NOT NULL,
    risk         TEXT NOT NULL,
    destructive  BOOLEAN NOT NULL DEFAULT false,
    region       TEXT,
    status       TEXT NOT NULL DEFAULT 'draft',
    run_at       TIMESTAMPTZ,
    created_at   TIMESTAMPTZ DEFAULT now(),
    approved_at  TIMESTAMPTZ,
    last_run_at  TIMESTAMPTZ,
    result       TEXT
);
CREATE INDEX IF NOT EXISTS scripts_owner_status_idx ON scripts (owner, status);
