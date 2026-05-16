-- Add columns to
-- * track whether the Extended Key Usage extension is marked critical, as required by RFC 3161 for TSA certificates.
-- * QC statement fields parsed from the QCStatements extension (OID 1.3.6.1.5.5.7.1.3)
--   per ETSI EN 319 412-5. NULL means the extension was absent or a certificate not yet reparsed.
ALTER TABLE "certificate"
    ADD COLUMN "extended_key_usage_critical" BOOLEAN,
    ADD COLUMN "qc_compliance"     BOOLEAN,
    ADD COLUMN "qc_sscd"           BOOLEAN,
    ADD COLUMN "qc_type"           TEXT,      -- serialized JSON array of QcType enum names
    ADD COLUMN "qc_cc_legislation" TEXT;      -- serialized JSON array of ISO 3166-1 alpha-2 codes
