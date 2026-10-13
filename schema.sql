CREATE TABLE connections (
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
    role            TEXT NOT NULL,
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
    risk           TEXT,
    approval       TEXT,
    status         TEXT,
    result_summary TEXT
);

CREATE TABLE findings (
    id             SERIAL PRIMARY KEY,
    created_at     TIMESTAMPTZ DEFAULT now(),
    category       TEXT,
    resource_id    TEXT,
    severity       TEXT,
    details        JSONB,
    recommendation TEXT
);

CREATE TABLE deployments (
    id         SERIAL PRIMARY KEY,
    request    TEXT,
    status     TEXT,
    code_path  TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE deployment_resources (
    id            SERIAL PRIMARY KEY,
    deployment_id INT REFERENCES deployments(id) ON DELETE CASCADE,
    address       TEXT,
    action        TEXT,
    risk          TEXT,
    status        TEXT DEFAULT 'pending'
);

CREATE TABLE aws_credentials (
    id            SERIAL PRIMARY KEY,
    owner         TEXT NOT NULL,
    label         TEXT NOT NULL,
    purpose       TEXT NOT NULL,
    auth_mode     TEXT NOT NULL,
    access_key_id TEXT,
    key_hint      TEXT,
    secret_enc    TEXT,
    role_arn      TEXT,
    external_id   TEXT,
    profile_name  TEXT,
    region        TEXT DEFAULT 'ap-south-1',
    account_id    TEXT,
    verified_at   TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ DEFAULT now(),
    UNIQUE (owner, label)
);
