UPDATE trigger_history th
SET actions_performed = false
WHERE th.actions_performed = true
  AND EXISTS (
    SELECT 1
    FROM trigger_history_record thr
    WHERE thr.trigger_history_uuid = th.uuid
);
