-- The column named a collection registry that was never built: no COLLECTION value-source type, no collection
-- resource, no endpoint to reference one. It is empty in the field — a row could only be written by a
-- request-attribute configuration update carrying a value-source binding, and the release that added this table
-- also rejected every such update, so no released version ever allowed one to exist.
ALTER TABLE ra_profile_value_source_binding DROP COLUMN collection_ref;
