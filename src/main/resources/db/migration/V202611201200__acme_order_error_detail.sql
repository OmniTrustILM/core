-- An invalid order reports why its certificate was not issued (RFC 8555 section 7.1.3). The reason is known when the
-- issuance fails, which may be long after the client finalized the order, so it is recorded on the order row.
ALTER TABLE acme_order ADD COLUMN error_detail VARCHAR NULL DEFAULT NULL;

-- The reason is recorded by the certificate the order requested, inside the transaction that fails the certificate.
CREATE INDEX idx_acme_order_certificate_ref ON acme_order (certificate_ref);
