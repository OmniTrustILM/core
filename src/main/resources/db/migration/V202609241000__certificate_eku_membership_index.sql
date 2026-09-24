CREATE INDEX CONCURRENTLY "idx_certificate_extended_key_usage_gin"
    ON "certificate" USING GIN (("extended_key_usage"::jsonb) jsonb_path_ops);
