-- The NOT NULL is added in three steps that commit separately: the constraint is added NOT VALID here (a brief lock,
-- no scan), validated in the next migration and turned into the column's NOT NULL in the last. Done in one transaction,
-- the validation scan would run while the table is locked against reads.
ALTER TABLE certificate ADD CONSTRAINT certificate_certificate_type_not_null CHECK (certificate_type IS NOT NULL) NOT VALID;
