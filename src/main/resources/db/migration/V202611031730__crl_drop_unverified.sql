-- CRLs were stored without a check of their signature, so a cached CRL may come from whoever could tamper with its
-- download. Emptying the cache makes every CRL be downloaded again and verified before it is used.
TRUNCATE "crl_entry", "crl";
