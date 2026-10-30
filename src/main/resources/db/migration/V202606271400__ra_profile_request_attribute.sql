CREATE TABLE ra_profile_request_attribute (
    uuid UUID NOT NULL,
    ra_profile_uuid UUID NOT NULL,
    request_attributes TEXT NULL DEFAULT NULL,
    merge_mode VARCHAR(32) NULL DEFAULT NULL,
    external_csr_validation_strict BOOLEAN NULL DEFAULT NULL,
    PRIMARY KEY (uuid),
    CONSTRAINT uq_ra_profile_request_attribute_ra_profile UNIQUE (ra_profile_uuid)
);

ALTER TABLE ra_profile_request_attribute
    ADD CONSTRAINT ra_profile_request_attribute_to_ra_profile
    FOREIGN KEY (ra_profile_uuid)
    REFERENCES ra_profile
    ON UPDATE NO ACTION ON DELETE CASCADE;

CREATE TABLE ra_profile_value_source_binding (
    uuid UUID NOT NULL,
    ra_profile_uuid UUID NOT NULL,
    attribute_uuid VARCHAR(255) NULL DEFAULT NULL,
    attribute_name VARCHAR(255) NULL DEFAULT NULL,
    value_source_kind VARCHAR(64) NOT NULL,
    collection_ref VARCHAR(255) NULL DEFAULT NULL,
    params TEXT NULL DEFAULT NULL,
    PRIMARY KEY (uuid)
);

ALTER TABLE ra_profile_value_source_binding
    ADD CONSTRAINT ra_profile_value_source_binding_to_ra_profile
    FOREIGN KEY (ra_profile_uuid)
    REFERENCES ra_profile
    ON UPDATE NO ACTION ON DELETE CASCADE;

CREATE INDEX idx_ra_profile_value_source_binding_ra_profile
    ON ra_profile_value_source_binding (ra_profile_uuid);
