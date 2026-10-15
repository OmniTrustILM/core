-- An audit row loads its operation from both the column and log_record through the current enum, so an operation
-- removed from it is rewritten to UNKNOWN.
UPDATE "audit_log"
   SET operation = 'UNKNOWN',
       log_record = jsonb_set(log_record, '{operation}', '"unknown"')
 WHERE operation = 'LIST_KEY_USAGES'
    OR log_record ->> 'operation' = 'listKeyUsages';
