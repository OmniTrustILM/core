package com.otilm.core.attribute.engine;

import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CustomAttributeContentFilterTest {

    private static final UUID DEFINITION = UUID.randomUUID();

    @Test
    void anUnrestrictedCallerMayReadEveryDefinition() {
        assertThat(new CustomAttributeContentFilter(null, null).permits(DEFINITION)).isTrue();
    }

    @Test
    void anAllowListPermitsOnlyTheDefinitionsOnIt() {
        CustomAttributeContentFilter filter = new CustomAttributeContentFilter(List.of(DEFINITION), null);

        assertThat(filter.permits(DEFINITION)).isTrue();
        assertThat(filter.permits(UUID.randomUUID())).isFalse();
    }

    @Test
    void aForbidListWithholdsOnlyTheDefinitionsOnIt() {
        CustomAttributeContentFilter filter = new CustomAttributeContentFilter(null, List.of(DEFINITION));

        assertThat(filter.permits(DEFINITION)).isFalse();
        assertThat(filter.permits(UUID.randomUUID())).isTrue();
    }

    /** The shape an empty allow-list takes for the content queries, which must still permit nothing. */
    @Test
    void anEmptyAllowListPermitsNothingNotEvenANullUuid() {
        List<UUID> nothingAllowed = new ArrayList<>();
        nothingAllowed.add(null);
        CustomAttributeContentFilter filter = new CustomAttributeContentFilter(nothingAllowed, null);

        assertThat(filter.permits(DEFINITION)).isFalse();
        assertThat(filter.permits(null)).isFalse();
    }
}
