ALTER TABLE integrations ADD COLUMN errors_total bigint NOT NULL DEFAULT 0 CHECK(errors_total>=0);
