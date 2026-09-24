package com.otilm.core.util;

import org.hibernate.boot.model.FunctionContributions;
import org.hibernate.boot.model.FunctionContributor;
import org.hibernate.type.BasicType;
import org.hibernate.type.StandardBasicTypes;

public class PostgresFunctionContributor implements FunctionContributor {

    public static final String BIT_AND_FUNCTION = "bitand";
    public static final String JSONB_CONTAINS = "jsonb_contains";
    public static final String JSON_TEXT_ARRAY_CONTAINS = "json_text_array_contains";
    public static final String JSON_TEXT_ARRAY_CONTAINS_PATTERN = "CAST(?1 AS jsonb) @> CAST(?2 AS jsonb)";
    public static final String JSON_TEXT_ARRAY_LENGTH = "json_text_array_length";
    public static final String ARRAY_CONTAINS = "text_array_contains";
    public static final String ARRAY_ITEM_CONTAINS = "text_array_item_contains";

    /**
     * Scalar membership in a native array column, written as containment rather than as the equivalent
     * {@code CAST(?1 AS TEXT) = ANY(?2)}.
     *
     * <p>
     * The two answer the same question for the single non-null value this is ever called with -- every caller in
     * {@code FilterPredicatesBuilder} passes {@code value.toString()} as a literal -- but only containment can be
     * answered by a GIN index. PostgreSQL has no index path for {@code scalar = ANY(column)} at all, so the
     * {@code = ANY} form made every membership filter a sequential scan whatever index the column carried.
     *
     * <p>
     * The column is cast because the array columns are not all one type in every schema a query runs against: a
     * {@code List<String>} mapped with {@code SqlTypes.ARRAY} generates {@code varchar[]} unless the entity says
     * otherwise, which is what the entity-generated schema the integration suite builds holds for every array field
     * except {@code CryptoAsset.curve}. {@code @>} is not defined across {@code varchar[]} and {@code text[]}, so
     * without the cast those fields would fail there.
     *
     * <p>
     * Production is not that schema, and indexability does not turn on {@code columnDefinition}, which shapes only the
     * generated one. Every array column the migrations ship is already declared {@code TEXT[]} --
     * {@code custom_oid_entry.alt_codes}, {@code connector_interface.features},
     * {@code time_quality_configuration.ntp_servers} and {@code crypto_asset.curve} -- so there the cast is to the type
     * the column already has, PostgreSQL drops it, and a GIN index on any of the four is matched through this predicate
     * as the schema stands, with no type change needed. Pinned for the curve by
     * {@code CryptoAssetCurveMembershipMigrationITest}.
     *
     * <p>
     * One measured case where the two forms differ: for an array that holds a NULL element and does not hold the
     * searched value, {@code = ANY} yields SQL NULL where containment yields false. Under {@code EQUALS} both filter
     * the row out. Under {@code NOT_EQUALS} -- rendered as {@code column IS NULL OR NOT (...)} -- the old form dropped
     * such a row and this one keeps it. That is the correct answer, and it is a change to every field of this type, not
     * only the curve. No writer in this codebase produces an array holding a NULL element.
     */
    public static final String ARRAY_CONTAINS_PATTERN = "CAST(?2 AS TEXT[]) @> ARRAY[CAST(?1 AS TEXT)]";

    @Override
    public void contributeFunctions(FunctionContributions functionContributions) {
        BasicType<Integer> resultType = functionContributions
                .getTypeConfiguration()
                .getBasicTypeRegistry()
                .resolve(StandardBasicTypes.INTEGER);
        BasicType<Boolean> booleanType = functionContributions
                .getTypeConfiguration()
                .getBasicTypeRegistry()
                .resolve(StandardBasicTypes.BOOLEAN);
        functionContributions.getFunctionRegistry().registerPattern(BIT_AND_FUNCTION, "?1 & ?2", resultType);
        functionContributions
                .getFunctionRegistry()
                .registerPattern(JSONB_CONTAINS, "jsonb_contains(?1, ?2::jsonb)", booleanType);
        functionContributions
                .getFunctionRegistry()
                .registerPattern(JSON_TEXT_ARRAY_CONTAINS, JSON_TEXT_ARRAY_CONTAINS_PATTERN, booleanType);
        functionContributions
                .getFunctionRegistry()
                .registerPattern(JSON_TEXT_ARRAY_LENGTH, "jsonb_array_length(CAST(?1 AS jsonb))", resultType);
        functionContributions
                .getFunctionRegistry()
                .registerPattern(ARRAY_CONTAINS, ARRAY_CONTAINS_PATTERN, booleanType);
        // EXISTS over unnest(...) + LIKE — check substring match in any native text[] item
        functionContributions
                .getFunctionRegistry()
                .registerPattern(ARRAY_ITEM_CONTAINS,
                        "EXISTS (SELECT 1 FROM unnest(?2) AS item WHERE item LIKE '%' || CAST(?1 AS TEXT) || '%')",
                        booleanType);
    }
}
