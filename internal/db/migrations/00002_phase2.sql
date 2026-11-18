-- +goose Up
-- Phase 2: signing keys, scanning pipeline, cleanup policies, routing rules.

-- Who uploaded an asset (principal kind/name and, for GitLab CI jobs, the
-- project/pipeline/commit claims used for feedback).
ALTER TABLE assets ADD COLUMN uploader jsonb NOT NULL DEFAULT '{}';

-- Scan state is denormalised onto components so download-time quarantine
-- checks are a single indexed lookup.
ALTER TABLE components
    ADD COLUMN scan_state text NOT NULL DEFAULT 'unscanned'
        CHECK (scan_state IN ('unscanned', 'pending', 'clean', 'vulnerable', 'error', 'unsupported')),
    ADD COLUMN quarantined boolean NOT NULL DEFAULT false,
    ADD COLUMN scanned_at timestamptz;
CREATE INDEX components_scan_state ON components (repository_id, scan_state);

CREATE TABLE signing_keys (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id   uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint     text NOT NULL,
    public_armored  text NOT NULL,
    -- Armored private key, sealed with internal/secrets.
    private_sealed  text NOT NULL,
    active          boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX signing_keys_active ON signing_keys (repository_id) WHERE active;

CREATE TABLE scanners (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    type        text NOT NULL CHECK (type IN ('trivy', 'grype', 'webhook')),
    -- Driver configuration; secret fields are sealed.
    config      jsonb NOT NULL DEFAULT '{}',
    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scan_jobs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    component_id  uuid NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    scanner_id    uuid NOT NULL REFERENCES scanners(id) ON DELETE CASCADE,
    status        text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    reason        text NOT NULL DEFAULT '',          -- upload | proxy | manual | rescan
    attempts      integer NOT NULL DEFAULT 0,
    run_after     timestamptz NOT NULL DEFAULT now(),
    locked_by     text NOT NULL DEFAULT '',
    locked_until  timestamptz,
    -- For webhook scanners: hash of the per-job callback token.
    token_hash    bytea,
    error         text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz
);
CREATE INDEX scan_jobs_ready ON scan_jobs (run_after) WHERE status = 'queued';
CREATE INDEX scan_jobs_component ON scan_jobs (component_id, created_at DESC);
-- At most one outstanding job per component and scanner.
CREATE UNIQUE INDEX scan_jobs_outstanding ON scan_jobs (component_id, scanner_id) WHERE status IN ('queued', 'running');

CREATE TABLE scan_results (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    component_id  uuid NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    scanner_id    uuid NOT NULL REFERENCES scanners(id) ON DELETE CASCADE,
    job_id        uuid REFERENCES scan_jobs(id) ON DELETE SET NULL,
    status        text NOT NULL CHECK (status IN ('ok', 'error', 'unsupported')),
    -- Counts by severity, scanner/DB versions, target description, error.
    summary       jsonb NOT NULL DEFAULT '{}',
    scanned_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scan_results_component ON scan_results (component_id, scanner_id, scanned_at DESC);

CREATE TABLE scan_findings (
    id                 bigserial PRIMARY KEY,
    result_id          uuid NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    vuln_id            text NOT NULL,
    severity           text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    package            text NOT NULL DEFAULT '',
    installed_version  text NOT NULL DEFAULT '',
    fixed_version      text NOT NULL DEFAULT '',
    title              text NOT NULL DEFAULT '',
    url                text NOT NULL DEFAULT ''
);
CREATE INDEX scan_findings_result ON scan_findings (result_id);
CREATE INDEX scan_findings_vuln ON scan_findings (vuln_id);

CREATE TABLE waivers (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id             text NOT NULL,          -- e.g. CVE-2024-1234, or * for all
    repository_pattern  text NOT NULL DEFAULT '*',
    component_pattern   text NOT NULL DEFAULT '*',   -- glob over "name" or "name@version"
    reason              text NOT NULL DEFAULT '',
    expires_at          timestamptz,
    created_by          text NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cleanup_policies (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    description text NOT NULL DEFAULT '',
    -- Restrict to one format ('' = any).
    format      text NOT NULL DEFAULT '',
    criteria    jsonb NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE routing_rules (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    description text NOT NULL DEFAULT '',
    mode        text NOT NULL CHECK (mode IN ('allow', 'block')),
    -- Regular expressions matched against the request path / package name.
    matchers    text[] NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE routing_rules;
DROP TABLE cleanup_policies;
DROP TABLE waivers;
DROP TABLE scan_findings;
DROP TABLE scan_results;
DROP TABLE scan_jobs;
DROP TABLE scanners;
DROP TABLE signing_keys;
DROP INDEX components_scan_state;
ALTER TABLE components DROP COLUMN scanned_at, DROP COLUMN quarantined, DROP COLUMN scan_state;
ALTER TABLE assets DROP COLUMN uploader;
