-- The renewal state of a certificate: at most one row, with a window when window_start is set, the refresh state of
-- the renewal information the certificate authority gives, and the state of its automatic renewal.
CREATE TABLE certificate_renewal_info
(
    uuid                       UUID                     NOT NULL PRIMARY KEY,
    certificate_uuid           UUID                     NOT NULL,
    window_start               TIMESTAMP WITH TIME ZONE NULL,
    window_end                 TIMESTAMP WITH TIME ZONE NULL,
    explanation_url            TEXT                     NULL,
    source                     TEXT                     NULL,
    updated_at                 TIMESTAMP WITH TIME ZONE NOT NULL,
    advanced                   BOOLEAN                  NOT NULL DEFAULT FALSE,
    next_refresh_at            TIMESTAMP WITH TIME ZONE NULL,
    refresh_attempt            INTEGER                  NOT NULL DEFAULT 0,
    refresh_unsupported        BOOLEAN                  NOT NULL DEFAULT FALSE,
    renew_at                   TIMESTAMP WITH TIME ZONE NULL,
    renew_started_at           TIMESTAMP WITH TIME ZONE NULL,
    renew_successor_uuid       UUID                     NULL,
    renew_attempt              INTEGER                  NOT NULL DEFAULT 0,
    renew_not_before           TIMESTAMP WITH TIME ZONE NULL,
    renew_blocked_reason       TEXT                     NULL,
    -- The trigger firing that started the automatic renewal in flight, so a later failure to place the renewed
    -- certificate in the locations of the old one can be added to that firing's history.
    renew_trigger_history_uuid UUID                     NULL,
    renew_execution_uuid       UUID                     NULL,
    CONSTRAINT uq_certificate_renewal_info_certificate UNIQUE (certificate_uuid),
    CONSTRAINT fk_certificate_renewal_info_certificate FOREIGN KEY (certificate_uuid)
        REFERENCES certificate (uuid) ON DELETE CASCADE,
    CONSTRAINT chk_certificate_renewal_info_window CHECK (
        (window_start IS NULL AND window_end IS NULL)
            OR (window_start IS NOT NULL AND window_end IS NOT NULL AND window_end > window_start))
);

CREATE INDEX idx_certificate_renewal_info_next_refresh_at ON certificate_renewal_info (next_refresh_at);

-- The automatic renewal of a certificate in each location that generates its own key.
CREATE TABLE certificate_renewal_location
(
    uuid             UUID                     NOT NULL PRIMARY KEY,
    certificate_uuid UUID                     NOT NULL,
    location_uuid    UUID                     NOT NULL,
    successor_uuid   UUID                     NULL,
    started_at       TIMESTAMP WITH TIME ZONE NULL,
    attempt          INTEGER                  NOT NULL DEFAULT 0,
    not_before       TIMESTAMP WITH TIME ZONE NULL,
    completed_at     TIMESTAMP WITH TIME ZONE NULL,
    CONSTRAINT uq_certificate_renewal_location UNIQUE (certificate_uuid, location_uuid),
    CONSTRAINT fk_certificate_renewal_location_certificate FOREIGN KEY (certificate_uuid)
        REFERENCES certificate (uuid) ON DELETE CASCADE,
    CONSTRAINT fk_certificate_renewal_location_location FOREIGN KEY (location_uuid)
        REFERENCES location (uuid) ON DELETE CASCADE
);

CREATE INDEX idx_certificate_renewal_location_location ON certificate_renewal_location (location_uuid);

ALTER TABLE ra_profile
    ADD COLUMN renewal_window_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN renewal_window_start_percent INTEGER NOT NULL DEFAULT 67,
    ADD COLUMN renewal_window_end_percent   INTEGER NOT NULL DEFAULT 80,
    ADD COLUMN renewal_use_authority_info   BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN auto_renewal_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN auto_renewal_max_attempts    INTEGER NOT NULL DEFAULT 5;

ALTER TABLE acme_profile
    ADD COLUMN renewal_info_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN renewal_info_retry_after INTEGER NOT NULL DEFAULT 21600;

-- The certificate an order replaces (RFC 9773): the identifier the client sent, and the certificate it named.
ALTER TABLE acme_order
    ADD COLUMN replaces_cert_id          TEXT NULL,
    ADD COLUMN replaces_certificate_uuid UUID NULL,
    ADD CONSTRAINT fk_acme_order_replaces_certificate FOREIGN KEY (replaces_certificate_uuid)
        REFERENCES certificate (uuid) ON DELETE SET NULL;

CREATE INDEX idx_acme_order_replaces_certificate ON acme_order (replaces_certificate_uuid);

CREATE INDEX certificate_serial_number_idx ON certificate (serial_number);
