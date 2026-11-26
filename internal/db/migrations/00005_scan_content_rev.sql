-- +goose Up
-- content_rev counts changes to a component's content (a file added or
-- replaced). A scan job records the revision it scanned, and so does its
-- result: a result is current when its revision is at least the component's.
-- Existing rows start at 0, so every existing result stays current.
ALTER TABLE components ADD COLUMN content_rev bigint NOT NULL DEFAULT 0;
ALTER TABLE scan_jobs ADD COLUMN content_rev bigint NOT NULL DEFAULT 0;
ALTER TABLE scan_results ADD COLUMN content_rev bigint NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE scan_results DROP COLUMN content_rev;
ALTER TABLE scan_jobs DROP COLUMN content_rev;
ALTER TABLE components DROP COLUMN content_rev;
