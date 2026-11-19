-- +goose Up
-- Usage statistics per repository. Minute buckets (kept ~2 days) give
-- request rates and recent charts; hour buckets (kept ~400 days) give trends.
CREATE TABLE usage_minute (
    bucket         timestamptz NOT NULL,
    repository_id  uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    requests       bigint NOT NULL DEFAULT 0,
    errors         bigint NOT NULL DEFAULT 0,
    downloads      bigint NOT NULL DEFAULT 0,
    uploads        bigint NOT NULL DEFAULT 0,
    bytes_out      bigint NOT NULL DEFAULT 0,
    bytes_in       bigint NOT NULL DEFAULT 0,
    cache_hits     bigint NOT NULL DEFAULT 0,
    cache_misses   bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, repository_id)
);
CREATE INDEX usage_minute_repo ON usage_minute (repository_id, bucket);

CREATE TABLE usage_hour (LIKE usage_minute INCLUDING DEFAULTS);
ALTER TABLE usage_hour ADD PRIMARY KEY (bucket, repository_id);
ALTER TABLE usage_hour ADD FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE;
CREATE INDEX usage_hour_repo ON usage_hour (repository_id, bucket);

-- Who downloaded/uploaded/deleted what, from where (retention configurable).
CREATE TABLE activity_events (
    id             bigserial PRIMARY KEY,
    at             timestamptz NOT NULL DEFAULT now(),
    repository_id  uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    kind           text NOT NULL CHECK (kind IN ('download', 'upload', 'delete')),
    path           text NOT NULL,
    component_id   uuid REFERENCES components(id) ON DELETE SET NULL,
    actor          text NOT NULL DEFAULT '',
    actor_kind     text NOT NULL DEFAULT '',
    remote_ip      text NOT NULL DEFAULT '',
    user_agent     text NOT NULL DEFAULT '',
    bytes          bigint NOT NULL DEFAULT 0
);
CREATE INDEX activity_events_at ON activity_events (at DESC);
CREATE INDEX activity_events_repo ON activity_events (repository_id, at DESC);
CREATE INDEX activity_events_actor ON activity_events (actor, at DESC);
CREATE INDEX audit_events_actor ON audit_events (actor, at DESC);

-- +goose Down
DROP TABLE activity_events;
DROP INDEX IF EXISTS audit_events_actor;
DROP TABLE usage_hour;
DROP TABLE usage_minute;
