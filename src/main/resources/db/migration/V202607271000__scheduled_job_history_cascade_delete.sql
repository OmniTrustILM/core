ALTER TABLE scheduled_job_history
    DROP CONSTRAINT scheduled_job_history_scheduled_job_uuid_fkey;
ALTER TABLE scheduled_job_history
    ADD CONSTRAINT fk_scheduled_job_history_scheduled_job
        FOREIGN KEY (scheduled_job_uuid) REFERENCES scheduled_job (uuid) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_scheduled_job_history_scheduled_job_uuid ON scheduled_job_history (scheduled_job_uuid);
