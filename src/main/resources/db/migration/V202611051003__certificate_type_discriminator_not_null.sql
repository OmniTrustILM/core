-- The validated constraint lets SET NOT NULL skip its own table scan.
ALTER TABLE certificate
    ALTER COLUMN certificate_type SET NOT NULL,
    ALTER COLUMN certificate_type SET DEFAULT 'X509';
ALTER TABLE certificate DROP CONSTRAINT certificate_certificate_type_not_null;

ALTER TABLE certificate_request ALTER COLUMN certificate_type SET DEFAULT 'X509';

-- key_usage is an X.509 attribute; rows of other certificate types have none.
ALTER TABLE certificate ALTER COLUMN key_usage DROP NOT NULL;
ALTER TABLE certificate_request ALTER COLUMN key_usage DROP NOT NULL;
