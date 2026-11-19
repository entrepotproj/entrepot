-- +goose Up
CREATE TABLE blob_stores (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    type        text NOT NULL CHECK (type IN ('file', 's3')),
    config      jsonb NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE repositories (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    format          text NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('hosted', 'proxy', 'group')),
    blob_store_id   uuid NOT NULL REFERENCES blob_stores(id) ON DELETE RESTRICT,
    description     text NOT NULL DEFAULT '',
    online          boolean NOT NULL DEFAULT true,
    anonymous_read  boolean NOT NULL DEFAULT false,
    config          jsonb NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Content-addressed blobs, deduplicated per blob store.
CREATE TABLE blobs (
    store_id    uuid NOT NULL REFERENCES blob_stores(id) ON DELETE CASCADE,
    digest      text NOT NULL,
    size        bigint NOT NULL,
    refcount    integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (store_id, digest)
);
CREATE INDEX blobs_unreferenced ON blobs (store_id, updated_at) WHERE refcount <= 0;

CREATE TABLE components (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id  uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name           text NOT NULL,
    version        text NOT NULL DEFAULT '',
    attrs          jsonb NOT NULL DEFAULT '{}',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (repository_id, name, version)
);
CREATE INDEX components_name ON components (lower(name) text_pattern_ops);

CREATE TABLE assets (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id       uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    component_id        uuid REFERENCES components(id) ON DELETE SET NULL,
    path                text NOT NULL,
    digest              text NOT NULL,
    size                bigint NOT NULL,
    content_type        text NOT NULL DEFAULT 'application/octet-stream',
    attrs               jsonb NOT NULL DEFAULT '{}',
    created_by          text NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    -- For proxy repositories: when the content was last validated upstream.
    cached_at           timestamptz,
    last_downloaded_at  timestamptz,
    UNIQUE (repository_id, path)
);
CREATE INDEX assets_path_prefix ON assets (repository_id, path text_pattern_ops);
CREATE INDEX assets_component ON assets (component_id);

CREATE TABLE users (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer         text NOT NULL,
    subject        text NOT NULL,
    username       text NOT NULL,
    email          text NOT NULL DEFAULT '',
    display_name   text NOT NULL DEFAULT '',
    groups         text[] NOT NULL DEFAULT '{}',
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz,
    UNIQUE (issuer, subject)
);

CREATE TABLE api_tokens (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          text NOT NULL,
    hint          text NOT NULL,
    hash          bytea NOT NULL UNIQUE,
    scopes        text[] NOT NULL DEFAULT '{}',
    expires_at    timestamptz,
    last_used_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX api_tokens_user ON api_tokens (user_id);

CREATE TABLE roles (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE,
    description  text NOT NULL DEFAULT '',
    actions      text[] NOT NULL,
    builtin      boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE gitlab_trust_policies (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    description  text NOT NULL DEFAULT '',
    -- Name of the trusted GitLab instance from configuration.
    gitlab       text NOT NULL,
    -- Map of claim name -> glob pattern; all must match.
    conditions   jsonb NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE role_bindings (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id             uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    subject_type        text NOT NULL CHECK (subject_type IN ('user', 'group', 'gitlab_policy', 'authenticated')),
    subject             text NOT NULL DEFAULT '',
    repository_pattern  text NOT NULL DEFAULT '*',
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (role_id, subject_type, subject, repository_pattern)
);

CREATE TABLE docker_uploads (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id  uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    image          text NOT NULL,
    size           bigint NOT NULL DEFAULT 0,
    chunks         integer NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor       text NOT NULL,
    action      text NOT NULL,
    target      text NOT NULL DEFAULT '',
    details     jsonb NOT NULL DEFAULT '{}',
    remote_ip   text NOT NULL DEFAULT ''
);
CREATE INDEX audit_events_at ON audit_events (at DESC);

INSERT INTO roles (name, description, actions, builtin) VALUES
    ('viewer',    'Read and download packages',                    ARRAY['read'], true),
    ('developer', 'Read, upload and overwrite packages',           ARRAY['read', 'write'], true),
    ('maintainer','Read, upload and delete packages',              ARRAY['read', 'write', 'delete'], true),
    ('admin',     'Full control; on pattern * grants system admin', ARRAY['read', 'write', 'delete', 'admin'], true);

-- +goose Down
DROP TABLE audit_events;
DROP TABLE docker_uploads;
DROP TABLE role_bindings;
DROP TABLE gitlab_trust_policies;
DROP TABLE roles;
DROP TABLE api_tokens;
DROP TABLE users;
DROP TABLE assets;
DROP TABLE components;
DROP TABLE blobs;
DROP TABLE repositories;
DROP TABLE blob_stores;
