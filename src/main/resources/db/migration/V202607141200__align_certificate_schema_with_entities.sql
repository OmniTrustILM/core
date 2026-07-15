-- Align certificate and certificate_request schema with the JPA entities.
-- Relaxed columns: registration creates identity-only placeholders without key material
-- (public_key_algorithm) and, for SAN-only identities, without a subject DN; the CSR-attach
-- path copies both into certificate_request. Dropped columns have no readers in code.
ALTER TABLE certificate
    ALTER COLUMN public_key_algorithm DROP NOT NULL,
    ALTER COLUMN public_key_algorithm DROP DEFAULT,
    ALTER COLUMN subject_dn DROP NOT NULL,
    ALTER COLUMN subject_dn DROP DEFAULT,
    ALTER COLUMN state DROP NOT NULL,
    ALTER COLUMN validation_status DROP NOT NULL,
    ALTER COLUMN certificate_type DROP NOT NULL,
    DROP COLUMN discovery_uuid;

ALTER TABLE certificate_request
    ALTER COLUMN subject_dn DROP NOT NULL,
    ALTER COLUMN public_key_algorithm DROP NOT NULL,
    DROP COLUMN subject_dn_normalized;

-- Columns mapped to Java primitives can never hold null; backfill defensively, then constrain.
UPDATE certificate SET key_usage = 0 WHERE key_usage IS NULL;
UPDATE certificate SET hybrid_certificate = false WHERE hybrid_certificate IS NULL;
UPDATE certificate SET archived = false WHERE archived IS NULL;
ALTER TABLE certificate
    ALTER COLUMN key_usage SET DEFAULT 0,
    ALTER COLUMN key_usage SET NOT NULL,
    ALTER COLUMN hybrid_certificate SET DEFAULT false,
    ALTER COLUMN hybrid_certificate SET NOT NULL,
    ALTER COLUMN archived SET DEFAULT false,
    ALTER COLUMN archived SET NOT NULL;

UPDATE certificate_request SET key_usage = 0 WHERE key_usage IS NULL;
ALTER TABLE certificate_request
    ALTER COLUMN key_usage SET DEFAULT 0,
    ALTER COLUMN key_usage SET NOT NULL;
