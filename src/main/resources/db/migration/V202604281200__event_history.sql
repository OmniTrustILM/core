-- Create event_history table
CREATE TABLE event_history (
    uuid         UUID         NOT NULL,
    event        TEXT         NOT NULL,
    resource     TEXT,
    resource_uuid UUID,
    started_at   TIMESTAMP  NOT NULL,
    finished_at  TIMESTAMP,
    status       TEXT,
    PRIMARY KEY (uuid)
);

-- Add event_history_uuid to trigger_history
ALTER TABLE trigger_history ADD COLUMN event_history_uuid UUID;
ALTER TABLE trigger_history ADD CONSTRAINT trigger_history_to_event_history_fk
    FOREIGN KEY (event_history_uuid) REFERENCES event_history(uuid) ON UPDATE CASCADE ON DELETE SET NULL;

-- Since both trigger_uuid and event are nullable, add column of object resource type to
-- trigger_history for resource derivation.
ALTER TABLE trigger_history ADD COLUMN object_resource TEXT;
UPDATE trigger_history th
SET object_resource = t.resource
FROM trigger t
WHERE th.trigger_uuid = t.uuid;

-- Change trigger FK: keep trigger_history when trigger is deleted (SET NULL instead of CASCADE)
ALTER TABLE trigger_history DROP CONSTRAINT trigger_history_trigger_uuid_fkey;
ALTER TABLE trigger_history ALTER COLUMN trigger_uuid DROP NOT NULL;
ALTER TABLE trigger_history ADD CONSTRAINT trigger_history_trigger_uuid_fkey
    FOREIGN KEY (trigger_uuid) REFERENCES trigger(uuid) ON UPDATE CASCADE ON DELETE SET NULL;

-- Migrate existing data: group trigger_history records into event_history sessions.
-- Records sharing the same (event, object_uuid) and triggered within 2 seconds of each other
-- are considered part of the same event firing.
CREATE TEMP TABLE temp_session_map AS
SELECT
    uuid                                                                                          AS th_uuid,
    event,
    object_uuid,
    trigger_association_uuid,
    triggered_at,
    SUM(new_session) OVER (PARTITION BY event, object_uuid ORDER BY triggered_at
        ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)                                        AS session_num
FROM (
    SELECT
        uuid,
        event,
        object_uuid,
        trigger_association_uuid,
        triggered_at,
        CASE
            WHEN LAG(triggered_at) OVER (PARTITION BY event, object_uuid ORDER BY triggered_at) IS NULL
                OR triggered_at - LAG(triggered_at) OVER (PARTITION BY event, object_uuid ORDER BY triggered_at) > INTERVAL '2 seconds'
            THEN 1
            ELSE 0
        END AS new_session
    FROM trigger_history
    WHERE event IS NOT NULL AND object_uuid IS NOT NULL
) t;

-- One event_history row per session; derive resource from trigger_association or trigger
CREATE TEMP TABLE temp_event_history AS
SELECT DISTINCT ON (event, object_uuid, session_num)
    gen_random_uuid()  AS uuid,
    tsm.event,
    ta.resource AS resource,
    ta.object_uuid as event_object_uuid,
    tsm.object_uuid as object_uuid,
    tsm.session_num,
    MIN(tsm.triggered_at) OVER (PARTITION BY tsm.event, tsm.object_uuid, tsm.session_num) AS started_at,
    MAX(tsm.triggered_at) OVER (PARTITION BY tsm.event, tsm.object_uuid, tsm.session_num) AS finished_at
FROM temp_session_map tsm
LEFT JOIN trigger_association ta ON ta.uuid = tsm.trigger_association_uuid
ORDER BY event, object_uuid, session_num, triggered_at;

INSERT INTO event_history (uuid, event, resource, resource_uuid, started_at, finished_at, status)
SELECT uuid, event, resource, event_object_uuid, started_at, finished_at, 'FINISHED'
FROM temp_event_history;

UPDATE trigger_history th
SET event_history_uuid = teh.uuid
FROM temp_session_map tsm
JOIN temp_event_history teh
    ON teh.event = tsm.event
    AND teh.object_uuid = tsm.object_uuid
    AND teh.session_num = tsm.session_num
WHERE th.uuid = tsm.th_uuid;

DROP TABLE temp_session_map;
DROP TABLE temp_event_history;
