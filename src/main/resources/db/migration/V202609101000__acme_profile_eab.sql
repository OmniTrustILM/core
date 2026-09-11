ALTER TABLE acme_profile ADD COLUMN eab_secret_uuids UUID[];
ALTER TABLE acme_account ADD COLUMN eab_secret_uuid UUID;
