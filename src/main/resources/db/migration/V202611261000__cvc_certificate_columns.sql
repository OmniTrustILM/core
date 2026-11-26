ALTER TABLE certificate
    ADD COLUMN holder_reference VARCHAR,
    ADD COLUMN authority_reference VARCHAR,
    ADD COLUMN role VARCHAR,
    ADD COLUMN access_rights VARCHAR;

ALTER TABLE certificate_request
    ADD COLUMN holder_reference VARCHAR,
    ADD COLUMN authority_reference VARCHAR;
