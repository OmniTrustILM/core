-- Every certificate content a discovery delete removes checks the foreign key from discovery_certificate; without this
-- index each check scanned the whole table.
--
-- CREATE INDEX blocks writes to discovery_certificate while it builds; Flyway's transaction rules out CONCURRENTLY.
CREATE INDEX "idx_discovery_certificate_content"
    ON "discovery_certificate" ("certificate_content_id");
