UPDATE trigger_history th SET actions_performed = false WHERE (SELECT COUNT(*) FROM trigger_history_record thr WHERE thr.trigger_history_uuid = th.uuid) > 0;
