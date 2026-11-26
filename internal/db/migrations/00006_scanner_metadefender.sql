-- +goose Up
-- MetaDefender Core scanners (file content analysis).
ALTER TABLE scanners DROP CONSTRAINT IF EXISTS scanners_type_check;
ALTER TABLE scanners ADD CONSTRAINT scanners_type_check
    CHECK (type IN ('trivy', 'grype', 'webhook', 'metadefender'));

-- +goose Down
DELETE FROM scanners WHERE type = 'metadefender';
ALTER TABLE scanners DROP CONSTRAINT IF EXISTS scanners_type_check;
ALTER TABLE scanners ADD CONSTRAINT scanners_type_check
    CHECK (type IN ('trivy', 'grype', 'webhook'));
