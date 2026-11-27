ALTER TABLE certificate_request
    ADD COLUMN holder_reference VARCHAR,
    ADD COLUMN authority_reference VARCHAR,
    ADD COLUMN authenticated_by VARCHAR;
