-- A transactional build rolls back on failure but blocks certificate writes until it completes.
-- Schedule this migration during low traffic for large inventories.
CREATE INDEX "idx_certificate_extended_key_usage_gin"
    ON "certificate" USING GIN (("extended_key_usage"::jsonb) jsonb_path_ops);
