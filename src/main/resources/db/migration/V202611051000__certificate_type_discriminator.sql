-- certificate_type becomes the discriminator of the certificate and certificate request entity hierarchies, so every
-- row needs a value. The NOT NULL is added through a validated CHECK constraint, which takes no long lock and lets
-- the later SET NOT NULL skip its own table scan.
UPDATE certificate SET certificate_type = 'X509' WHERE certificate_type IS NULL OR certificate_type = '';
UPDATE certificate_request SET certificate_type = 'X509' WHERE certificate_type IS NULL OR certificate_type = '';

ALTER TABLE certificate ADD CONSTRAINT certificate_certificate_type_not_null CHECK (certificate_type IS NOT NULL) NOT VALID;
ALTER TABLE certificate VALIDATE CONSTRAINT certificate_certificate_type_not_null;
ALTER TABLE certificate
    ALTER COLUMN certificate_type SET NOT NULL,
    ALTER COLUMN certificate_type SET DEFAULT 'X509';
ALTER TABLE certificate DROP CONSTRAINT certificate_certificate_type_not_null;

ALTER TABLE certificate_request ALTER COLUMN certificate_type SET DEFAULT 'X509';

-- key_usage is an X.509 attribute; rows of other certificate types have none.
ALTER TABLE certificate ALTER COLUMN key_usage DROP NOT NULL;
ALTER TABLE certificate_request ALTER COLUMN key_usage DROP NOT NULL;
