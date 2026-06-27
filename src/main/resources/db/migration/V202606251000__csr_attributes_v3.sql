-- Migrate the six built-in CSR attribute definitions from v2 to v3.

-- Add contentType to existing content items stored against CSR attribute definitions.
-- V3 content items carry an explicit contentType field; v2 items do not.
-- All CSR attributes have content type STRING.

UPDATE attribute_content_item aci
SET json = jsonb_set(aci.json, '{contentType}', '"string"', true)
FROM attribute_definition ad
WHERE aci.attribute_definition_uuid = ad.uuid
  AND ad.connector_uuid IS NULL
  AND ad.type = 'DATA'
  AND ad.attribute_uuid IN (
    '9abaeba0-973d-11ed-a8fc-0242ac120002',
    '9abaef60-973d-11ed-a8fc-0242ac120002',
    '9abaf0be-973d-11ed-a8fc-0242ac120002',
    '9abaf208-973d-11ed-a8fc-0242ac120002',
    '9abaf33e-973d-11ed-a8fc-0242ac120002',
    '9abaf488-973d-11ed-a8fc-0242ac120002'
  )
;
