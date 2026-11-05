-- certificate_type becomes the discriminator of the certificate and certificate request entity hierarchies, so every
-- row needs a value. The NOT NULL is added in three migrations that commit separately: the constraint is added NOT VALID
-- here, validated in the next one and turned into the column's NOT NULL in the last. Done in one transaction, the
-- validation scan would run while the table is locked against reads.
UPDATE certificate SET certificate_type = 'X509' WHERE certificate_type IS NULL OR certificate_type = '';
UPDATE certificate_request SET certificate_type = 'X509' WHERE certificate_type IS NULL OR certificate_type = '';

ALTER TABLE certificate ADD CONSTRAINT certificate_certificate_type_not_null CHECK (certificate_type IS NOT NULL) NOT VALID;
