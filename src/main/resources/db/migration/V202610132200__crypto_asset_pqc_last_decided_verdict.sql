ALTER TABLE crypto_asset ADD COLUMN pqc_last_decided_verdict TEXT;

ALTER TABLE crypto_asset ADD CONSTRAINT ck_crypto_asset_pqc_last_decided_verdict
    CHECK (pqc_last_decided_verdict IN ('READY', 'NOT_READY', 'NOT_APPLICABLE')) NOT VALID;
