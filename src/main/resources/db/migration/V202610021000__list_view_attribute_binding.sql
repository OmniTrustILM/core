-- Binds every stored attribute column, filter and ordering to the definitions that back its identifier in the view's
-- resource today, so an existing view keeps resolving exactly what it shows now. An entry whose definition is already
-- gone is bound to nothing and can no longer be claimed by a definition created later under the same name and content
-- type. A definition counts for a resource as the catalogue counts it: related to the resource, or holding content on
-- one of its objects. Each candidate definition is probed through the indexes on its content items and their object
-- mappings rather than by reading every mapping of the resource.
CREATE FUNCTION pg_temp.bind_list_view_entries(entries JSONB, view_resource VARCHAR) RETURNS JSONB AS $$
    SELECT COALESCE(jsonb_agg(
        CASE
            WHEN entry ->> 'fieldSource' IN ('custom', 'meta', 'data') THEN entry || jsonb_build_object(
                'attributeDefinitionUuids',
                COALESCE((
                    SELECT jsonb_agg(ad.uuid ORDER BY ad.uuid)
                    FROM attribute_definition ad
                    WHERE ad.type = upper(entry ->> 'fieldSource')
                      AND ad.name || '|' || ad.content_type = entry ->> 'fieldIdentifier'
                      AND (
                          EXISTS (
                              SELECT 1
                              FROM attribute_relation ar
                              WHERE ar.attribute_definition_uuid = ad.uuid AND ar.resource = view_resource
                          )
                          OR EXISTS (
                              SELECT 1
                              FROM attribute_content_item aci
                              JOIN attribute_content_2_object aco ON aco.attribute_content_item_uuid = aci.uuid
                              WHERE aci.attribute_definition_uuid = ad.uuid AND aco.object_type = view_resource
                          )
                      )
                ), '[]'::JSONB))
            ELSE entry
        END
        ORDER BY position), '[]'::JSONB)
    FROM jsonb_array_elements(entries) WITH ORDINALITY AS stored(entry, position)
$$ LANGUAGE SQL STABLE;

ALTER TABLE list_view ADD COLUMN sort_attribute_definition_uuids JSONB;

UPDATE list_view SET columns = pg_temp.bind_list_view_entries(columns, resource)
WHERE jsonb_typeof(columns) = 'array';

UPDATE list_view SET filters = pg_temp.bind_list_view_entries(filters, resource)
WHERE jsonb_typeof(filters) = 'array';

UPDATE list_view
SET sort_attribute_definition_uuids
    = pg_temp.bind_list_view_entries(jsonb_build_array(sort), resource) -> 0 -> 'attributeDefinitionUuids'
WHERE jsonb_typeof(sort) = 'object' AND sort ->> 'fieldSource' IN ('custom', 'meta', 'data');

DROP FUNCTION pg_temp.bind_list_view_entries(JSONB, VARCHAR);
