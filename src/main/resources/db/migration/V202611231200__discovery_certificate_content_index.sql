-- The unused-content cleanup that runs on every discovery delete looks each certificate content up among the discovery
-- results, which had no index leading with the content, so every delete scanned all of discovery_certificate.
--
-- CREATE INDEX blocks writes to discovery_certificate while it builds; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX "idx_discovery_certificate_content"
    ON "discovery_certificate" ("certificate_content_id");
