package com.otilm.core.util;

import org.hibernate.boot.model.FunctionContributions;
import org.hibernate.boot.model.FunctionContributor;
import org.hibernate.type.BasicType;
import org.hibernate.type.StandardBasicTypes;

public class PostgresFunctionContributor implements FunctionContributor {

    public static final String BIT_AND_FUNCTION = "bitand";
    public static final String JSONB_CONTAINS = "jsonb_contains";
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
     * The column is cast because the array columns are not all one type: a {@code List<String>} mapped with
     * {@code SqlTypes.ARRAY} generates {@code varchar[]} unless the entity says otherwise, and {@code @>} is not
     * defined across {@code varchar[]} and {@code text[]}. On a {@code text[]} column the cast is to the type the
     * column already has, which PostgreSQL drops, so the index still matches -- pinned by
     * {@code CryptoAssetCurveMembershipMigrationITest}.
     *
     * <p>
     * That last part is what indexability rests on, and it is a property of the column rather than of the index: on a
     * {@code varchar[]} column the cast is a real one, and a GIN index there is never matched through it. An entity
     * earns the indexable type by declaring {@code columnDefinition = "TEXT[]"}, as {@code CryptoAsset.curve} does and
     * the other array-mapped fields do not -- so adding an array index to one of those would silently buy nothing until
     * its column type moves too.
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
                .registerPattern(ARRAY_CONTAINS, ARRAY_CONTAINS_PATTERN, booleanType);
        // EXISTS over unnest(...) + LIKE — check substring match in any native text[] item
        functionContributions
                .getFunctionRegistry()
                .registerPattern(ARRAY_ITEM_CONTAINS,
                        "EXISTS (SELECT 1 FROM unnest(?2) AS item WHERE item LIKE '%' || CAST(?1 AS TEXT) || '%')",
                        booleanType);
    }
}
