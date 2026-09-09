-- A failed challenge has to report why it failed (RFC 8555 section 8). Validation runs while the client is
-- accepting the challenge, but the client reads the reason back on a later request, so the reason is recorded
-- on the challenge row rather than held for the duration of the accepting request.
ALTER TABLE acme_challenge ADD COLUMN error_problem VARCHAR NULL DEFAULT NULL;
ALTER TABLE acme_challenge ADD COLUMN error_detail VARCHAR NULL DEFAULT NULL;
