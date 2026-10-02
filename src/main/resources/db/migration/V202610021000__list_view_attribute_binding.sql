-- Binds every stored attribute column and filter to the definitions that back its identifier today, so an existing view
-- keeps resolving exactly what it shows now. An entry whose definition is already gone is bound to nothing and can no
-- longer be claimed by a definition created later under the same name and content type.
CREATE FUNCTION pg_temp.bind_list_view_entries(entries JSONB) RETURNS JSONB AS $$
    SELECT COALESCE(jsonb_agg(
        CASE
            WHEN entry ->> 'fieldSource' IN ('custom', 'meta', 'data') THEN entry || jsonb_build_object(
                'attributeDefinitionUuids',
                COALESCE((
                    SELECT jsonb_agg(ad.uuid ORDER BY ad.uuid)
                    FROM attribute_definition ad
                    WHERE ad.type = upper(entry ->> 'fieldSource')
                      AND ad.name || '|' || ad.content_type = entry ->> 'fieldIdentifier'
                ), '[]'::JSONB))
            ELSE entry
        END
        ORDER BY position), '[]'::JSONB)
    FROM jsonb_array_elements(entries) WITH ORDINALITY AS stored(entry, position)
$$ LANGUAGE SQL STABLE;

UPDATE list_view SET columns = pg_temp.bind_list_view_entries(columns) WHERE jsonb_typeof(columns) = 'array';

UPDATE list_view SET filters = pg_temp.bind_list_view_entries(filters) WHERE jsonb_typeof(filters) = 'array';

DROP FUNCTION pg_temp.bind_list_view_entries(JSONB);
