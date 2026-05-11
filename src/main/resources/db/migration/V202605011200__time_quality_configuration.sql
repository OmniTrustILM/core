CREATE TABLE "time_quality_configuration" (
    "uuid"                        UUID         NOT NULL,
    "name"                        VARCHAR      NOT NULL,
    "accuracy"                    INTERVAL,
    "ntp_servers"                 TEXT[]       NOT NULL,
    "ntp_check_interval"          INTERVAL,
    "ntp_samples_per_server"      INTEGER,
    "ntp_check_timeout"           INTERVAL,
    "ntp_servers_min_reachable"   INTEGER,
    "max_clock_drift"             INTERVAL,
    "leap_second_guard"           BOOLEAN,
    "i_author"                    VARCHAR,
    "i_cre"                       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    "i_upd"                       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY ("uuid"),
    UNIQUE ("name")
);
