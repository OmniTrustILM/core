-- A secret key has no public key, so its import is recorded without a fingerprint.
ALTER TABLE "key_import" ALTER COLUMN "spki_fingerprint" DROP NOT NULL;

-- An import without a fingerprint has at most one attempt whose outcome is open, including one the reconciliation is
-- undoing.
CREATE UNIQUE INDEX "uq_key_import_open_secret_attempt" ON "key_import" ("idempotency_key")
    WHERE "spki_fingerprint" IS NULL AND "state" IN ('REQUESTED', 'ACCEPTED', 'COMPENSATING');
