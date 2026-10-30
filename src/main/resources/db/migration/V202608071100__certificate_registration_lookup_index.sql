-- Backs the registration-mode enrolment lookup (RA profile + normalized subject over REGISTERED,
-- non-archived placeholders), which runs on every unauthenticated initial enrolment. Partial index:
-- REGISTERED is a small subset, so the index stays tiny and the lookup does an index scan instead of
-- a sequential scan of the (potentially very large) certificate table.
CREATE INDEX "idx_certificate_registration_lookup"
    ON "certificate" ("ra_profile_uuid", "subject_dn_normalized")
    WHERE "state" = 'REGISTERED' AND "archived" = false;
