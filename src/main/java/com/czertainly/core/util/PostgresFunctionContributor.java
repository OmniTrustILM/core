package com.czertainly.core.util;

import org.hibernate.boot.model.FunctionContributions;
import org.hibernate.boot.model.FunctionContributor;
import org.hibernate.type.BasicType;
import org.hibernate.type.StandardBasicTypes;

public class PostgresFunctionContributor implements FunctionContributor {

    public static final String BIT_AND_FUNCTION = "bitand";
    public static final String JSONB_CONTAINS = "jsonb_contains";
    public static final String ARRAY_CONTAINS = "text_array_contains";

    @Override
    public void contributeFunctions(FunctionContributions functionContributions) {
        BasicType<Integer> resultType = functionContributions.getTypeConfiguration().getBasicTypeRegistry().resolve(StandardBasicTypes.INTEGER);
        BasicType<Boolean> booleanType = functionContributions.getTypeConfiguration().getBasicTypeRegistry().resolve(StandardBasicTypes.BOOLEAN);
        functionContributions.getFunctionRegistry().registerPattern(BIT_AND_FUNCTION,
                "?1 & ?2", resultType);
        functionContributions.getFunctionRegistry().registerPattern(JSONB_CONTAINS, "jsonb_contains(?1, ?2::jsonb)", booleanType);
        // CAST(?1 AS TEXT) = ANY(?2)  —  check scalar membership in a native text[] column
        functionContributions.getFunctionRegistry().registerPattern(ARRAY_CONTAINS, "CAST(?1 AS TEXT) = ANY(?2)", booleanType);
    }
}
