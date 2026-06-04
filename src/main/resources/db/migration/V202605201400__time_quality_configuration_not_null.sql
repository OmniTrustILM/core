ALTER TABLE "time_quality_configuration"
    ALTER COLUMN "accuracy"                  SET NOT NULL,
    ALTER COLUMN "ntp_check_interval"        SET NOT NULL,
    ALTER COLUMN "ntp_samples_per_server"    SET NOT NULL,
    ALTER COLUMN "ntp_check_timeout"         SET NOT NULL,
    ALTER COLUMN "ntp_servers_min_reachable" SET NOT NULL,
    ALTER COLUMN "max_clock_drift"           SET NOT NULL,
    ALTER COLUMN "leap_second_guard"         SET NOT NULL;
