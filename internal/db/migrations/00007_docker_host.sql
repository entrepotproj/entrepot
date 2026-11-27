-- +goose Up
-- Docker repositories may be served on their own hostname
-- (config.docker.host); a hostname belongs to at most one repository.
CREATE UNIQUE INDEX repositories_docker_host ON repositories (lower(config->'docker'->>'host'))
    WHERE config->'docker'->>'host' IS NOT NULL AND config->'docker'->>'host' <> '';

-- +goose Down
DROP INDEX IF EXISTS repositories_docker_host;
