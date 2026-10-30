-- Mirrors properties.visible out of the stored definition document so projection, ordering and
-- filtering share one predicate. Absent in the document means visible, which is the column default.
ALTER TABLE attribute_definition ADD COLUMN visible BOOLEAN NOT NULL DEFAULT TRUE;

UPDATE attribute_definition
SET visible = FALSE
WHERE definition -> 'properties' ->> 'visible' = 'false';
