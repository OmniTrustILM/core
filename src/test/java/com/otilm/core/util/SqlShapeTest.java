package com.otilm.core.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The shape questions against statements as Hibernate renders them: grouping and ordering by select-list position, and
 * a subquery's row limit as a bind parameter.
 */
class SqlShapeTest {

    /** An attribute-sorted page as the grouped, per-row form rendered it. */
    private static final String GROUPED_SCALAR_PAGE = "select d1_0.uuid,min((select jsonb_extract_path_text(aci1_0.json,'data')"
            + " from core.attribute_content_2_object aco1_0 join core.attribute_content_item aci1_0"
            + " on aci1_0.uuid=aco1_0.attribute_content_item_uuid join core.attribute_definition ad1_0"
            + " on ad1_0.uuid=aci1_0.attribute_definition_uuid where ad1_0.type=? and ad1_0.content_type=?"
            + " and ad1_0.name=? and aco1_0.object_type=? and aco1_0.object_uuid=d1_0.uuid"
            + " and aci1_0.encrypted_data is null and ad1_0.visible and ad1_0.enabled"
            + " order by aci1_0.attribute_definition_uuid,aco1_0.item_order fetch first ? rows only))"
            + " from core.discovery d1_0 where 1=1 group by 1 order by 2,1 offset ? rows fetch first ? rows only";

    /** A page joining a key table that groups its own rows, while the outer query does not group. */
    private static final String KEY_TABLE_PAGE = "select d1_0.uuid from core.discovery d1_0 left join (select"
            + " aco1_0.object_uuid,min(jsonb_extract_path_text(aci1_0.json,'data'))"
            + " from core.attribute_content_2_object aco1_0 where aco1_0.object_type=? group by aco1_0.object_uuid)"
            + " d2_0(keyObject,keyValue) on d2_0.keyObject=d1_0.uuid where 1=1 order by d2_0.keyValue,d1_0.uuid"
            + " offset ? rows fetch first ? rows only";

    @Test
    void aGroupingByPositionIsAGroupingOfTheOuterQuery() {
        assertThat(SqlShape.groupsByRootUuid(GROUPED_SCALAR_PAGE)).isTrue();
    }

    @Test
    void aKeyTableGroupingItsOwnRowsDoesNotGroupTheOuterQuery() {
        assertThat(SqlShape.groupsByRootUuid(KEY_TABLE_PAGE)).isFalse();
    }

    @Test
    void aSubqueryLimitedToOneRowByABindParameterIsTheScalarForm() {
        assertThat(SqlShape.hasScalarSortSubquery(GROUPED_SCALAR_PAGE)).isTrue();
    }

    @Test
    void theOuterPageWindowIsNotAScalarSubquery() {
        assertThat(SqlShape.hasScalarSortSubquery(KEY_TABLE_PAGE)).isFalse();
    }

    @Test
    void aKeyTableIsADerivedJoin() {
        assertThat(SqlShape.hasDerivedJoin(KEY_TABLE_PAGE)).isTrue();
        assertThat(SqlShape.hasDerivedJoin(GROUPED_SCALAR_PAGE)).isFalse();
    }
}
