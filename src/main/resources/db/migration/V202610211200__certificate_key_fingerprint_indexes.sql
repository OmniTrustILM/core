-- A key that joins the inventory links the certificates carrying its public key, as their key or as their alternative
-- key, so it looks certificates up by both fingerprints. Only hybrid certificates carry an alternative key, so its
-- index holds those alone.
--
-- CREATE INDEX blocks writes to certificate while it builds; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX "idx_certificate_public_key_fingerprint" ON "certificate" ("public_key_fingerprint");
CREATE INDEX "idx_certificate_alt_key_fingerprint" ON "certificate" ("alt_key_fingerprint")
    WHERE "alt_key_fingerprint" IS NOT NULL;
