-- 001: scripts generated from write requests (review, run now, or schedule).
-- Safe to run repeatedly. Applied automatically at app start by core/db.py ensure_schema().
CREATE TABLE IF NOT EXISTS scripts (
    id           SERIAL PRIMARY KEY,
    owner        TEXT NOT NULL,
    title        TEXT NOT NULL,
    request      TEXT,                      -- the user's original chat request
    steps        JSONB NOT NULL,            -- [{service, operation, params, description, guard?}]
    script_text  TEXT NOT NULL,             -- human-readable AWS CLI equivalent, for review
    risk         TEXT NOT NULL,             -- operate | deploy
    destructive  BOOLEAN NOT NULL DEFAULT false,
    region       TEXT,
    status       TEXT NOT NULL DEFAULT 'draft',  -- draft (waiting for review) | approved | denied | scheduled | running | succeeded | failed
    run_at       TIMESTAMPTZ,               -- when scheduled
    created_at   TIMESTAMPTZ DEFAULT now(),
    approved_at  TIMESTAMPTZ,               -- when the user clicked Run / Schedule
    last_run_at  TIMESTAMPTZ,
    result       TEXT
);
CREATE INDEX IF NOT EXISTS scripts_owner_status_idx ON scripts (owner, status);
