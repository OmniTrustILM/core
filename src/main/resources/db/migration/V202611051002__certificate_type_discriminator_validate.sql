-- Scans the table under a lock that lets reads and writes continue.
ALTER TABLE certificate VALIDATE CONSTRAINT certificate_certificate_type_not_null;
