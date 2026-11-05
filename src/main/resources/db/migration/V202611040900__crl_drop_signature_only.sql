-- CRLs were stored once their signature verified, without a check of their issuer name, role, currency or number, so
-- a cached CRL may hide a revocation. Emptying the cache makes every CRL be downloaded again and checked before use.
TRUNCATE "crl_entry", "crl";
