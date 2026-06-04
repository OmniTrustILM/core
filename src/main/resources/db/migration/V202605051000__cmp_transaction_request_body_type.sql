-- Track the original CMP request body type on each cmp_transaction so that an inbound
-- pollReq message can be answered with the correct response body type (ip vs cp vs kup vs rp)
-- once an asynchronous operation (one where the authority provider connector returned
-- HTTP 202 Accepted) completes asynchronously.
--
-- Values are the small integers from BouncyCastle PKIBody.TYPE_* constants:
--   0  = ir  (TYPE_INIT_REQ)
--   2  = cr  (TYPE_CERT_REQ)
--   7  = kur (TYPE_KEY_UPDATE_REQ)
--   11 = rr  (TYPE_REVOCATION_REQ)
--
-- Nullable for backwards compatibility: rows created before this migration have NULL,
-- and the pollReq handler treats NULL as "use TYPE_CERT_REP" (the most common ir/cr response).
ALTER TABLE cmp_transaction
    ADD COLUMN IF NOT EXISTS original_request_body_type INTEGER;
