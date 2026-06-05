-- Backfill: before this fix, async notification send failures left actions_performed=true.
-- Any trigger_history with a record but actions_performed=true is such a victim; correct it.
UPDATE trigger_history th
SET actions_performed = false
WHERE th.actions_performed = true
  AND EXISTS (
    SELECT 1
    FROM trigger_history_record thr
    WHERE thr.trigger_history_uuid = th.uuid
);
