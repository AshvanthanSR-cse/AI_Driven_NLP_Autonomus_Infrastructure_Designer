-- CloudAI app database schema (PostgreSQL 17, database: cloudai, owner role: cloudai_app)
-- Reconstructed from the scripts run during design. Claude Code: verify against the live DB
-- (information_schema.columns) before changing anything.
--
-- HISTORY
-- 1. Database was first created as "cloudai(FOAI_Project)" and renamed to cloudai.
-- 2. Role cloudai_app was first created without LOGIN; fixed with ALTER ROLE ... WITH LOGIN.
-- 3. The 7 base tables below were created.
-- 4. A test row was inserted into audit_logs, then all tables were emptied:
--      TRUNCATE connections, conversations, messages, audit_logs, findings,
--               deployments, deployment_resources RESTART IDENTITY CASCADE;
-- 5. aws_credentials v1 (name UNIQUE, single shared admin/read keys) was designed, then DROPPED
--    and replaced by v2 below (per-user owner, label, auth_mode, encrypted secret, verification).
--    v2 was pushed to the DB.

CREATE TABLE connections (          -- LEGACY / currently unused: superseded by aws_credentials
    id             SERIAL PRIMARY KEY,
    name           TEXT NOT NULL,
    provider       TEXT NOT NULL DEFAULT 'aws',
    mode           TEXT NOT NULL,
    read_profile   TEXT,
    deploy_profile TEXT,
    role_arn       TEXT,
    region         TEXT NOT NULL DEFAULT 'ap-south-1',
    created_at     TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE conversations (
    id         SERIAL PRIMARY KEY,
    title      TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE messages (
    id              SERIAL PRIMARY KEY,
    conversation_id INT REFERENCES conversations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,          -- user | assistant | tool
    content         TEXT,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE audit_logs (
    id             SERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ DEFAULT now(),
    actor          TEXT,
    request        TEXT,
    tool_name      TEXT,
    tool_args      JSONB,
    risk           TEXT,                    -- read | operate | deploy (earlier drafts: write | destructive)
    approval       TEXT,                    -- not_required | approved | rejected
    status         TEXT,                    -- success | failed | blocked
    result_summary TEXT
);

CREATE TABLE findings (
    id             SERIAL PRIMARY KEY,
    created_at     TIMESTAMPTZ DEFAULT now(),
    category       TEXT,                    -- cost | anomaly | security
    resource_id    TEXT,
    severity       TEXT,
    details        JSONB,
    recommendation TEXT
);

CREATE TABLE deployments (
    id         SERIAL PRIMARY KEY,
    request    TEXT,
    status     TEXT,                        -- planned | applying | applied | failed | discarded
    code_path  TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE deployment_resources (
    id            SERIAL PRIMARY KEY,
    deployment_id INT REFERENCES deployments(id) ON DELETE CASCADE,
    address       TEXT,
    action        TEXT,                     -- create | update | delete
    risk          TEXT,
    status        TEXT DEFAULT 'pending'    -- pending | applying | applied | failed
);

CREATE TABLE aws_credentials (              -- v2 (current)
    id            SERIAL PRIMARY KEY,
    owner         TEXT NOT NULL,            -- app username (no users table yet)
    label         TEXT NOT NULL,
    purpose       TEXT NOT NULL,            -- read | operate | deploy
    auth_mode     TEXT NOT NULL,            -- keys | assume_role | profile
    access_key_id TEXT,
    key_hint      TEXT,                     -- last 4 chars, for display only
    secret_enc    TEXT,                     -- Fernet-encrypted secret (null for non-key modes)
    role_arn      TEXT,
    external_id   TEXT,
    profile_name  TEXT,
    region        TEXT DEFAULT 'ap-south-1',
    account_id    TEXT,                     -- filled after sts verification
    verified_at   TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ DEFAULT now(),
    UNIQUE (owner, label)
);

-- PLANNED, NOT CREATED YET (decide during build):
-- app_users(id, username, role)        -- needed for RBAC (Developer / DevOps / Admin); owner is plain text today
-- pending_actions(id, tool, args, ...) -- optional, to persist approval requests like "stop i-xxx?"
