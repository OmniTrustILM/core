-- The opt-out UNLISTABLE_TOKEN flag replaces the opt-in KEY_LIST flag. Hibernate decodes each name stored in
-- connector_interface.features into a FeatureFlag value, and KEY_LIST has none left. A connector records
-- UNLISTABLE_TOKEN when it advertises the flag on reconnect.
UPDATE connector_interface
SET features = array_remove(features, 'KEY_LIST')
WHERE 'KEY_LIST' = ANY (features);
