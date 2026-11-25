-- +goose Up
ALTER TABLE users ADD COLUMN given_name text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE users DROP COLUMN given_name;
