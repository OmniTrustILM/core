-- An audit row loads its operation from both the column and log_record through the current enum, so rows of the
-- removed LIST_KEY_USAGES operation no longer load. They only recorded a read-only listing, so they are deleted.
DELETE FROM "audit_log"
 WHERE operation = 'LIST_KEY_USAGES'
    OR log_record ->> 'operation' = 'listKeyUsages';
