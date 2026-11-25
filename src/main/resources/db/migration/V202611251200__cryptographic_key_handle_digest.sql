ALTER TABLE cryptographic_key
    ADD COLUMN handle_digest VARCHAR(64);

-- PostgreSQL treats nulls as distinct, so any number of keys on a token may lack a digest.
ALTER TABLE cryptographic_key
    ADD CONSTRAINT uq_cryptographic_key_handle_digest UNIQUE (token_instance_uuid, handle_digest);
