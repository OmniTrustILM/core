-- Deleting a certificate content checks the foreign key from discovery_certificate. Without an index leading with the
-- content, each check scanned the whole table, so a discovery delete that removes thousands of unused contents scanned
-- it thousands of times.
--
-- CREATE INDEX blocks writes to discovery_certificate while it builds; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX "idx_discovery_certificate_content"
    ON "discovery_certificate" ("certificate_content_id");
