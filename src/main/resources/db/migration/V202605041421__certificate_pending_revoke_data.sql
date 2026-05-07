-- Adds two nullable columns to `certificate` to preserve the destroy-key flag and
-- revoke attributes from a revocation request whose connector response was
-- asynchronous. Read at manual confirmation time, cleared on confirm or cancel.

ALTER TABLE certificate
    ADD COLUMN pending_revoke_destroy_key BOOLEAN NULL,
    ADD COLUMN pending_revoke_attributes  JSONB   NULL;
