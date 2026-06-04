-- Uniqueness of proxy.code (lookups are by code) and supporting index on proxy.name for name-based queries.
alter table proxy
    add constraint proxy_code_unique unique (code);

create index idx_proxy_name on proxy (name);
