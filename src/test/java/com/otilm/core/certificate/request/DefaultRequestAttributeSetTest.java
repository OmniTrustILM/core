package com.otilm.core.certificate.request;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.attribute.CsrAttributes;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultRequestAttributeSetTest {

    @Test
    void seedDelegatesToCsrAttributes() {
        assertThat(DefaultRequestAttributeSet.seed())
                .hasSize(CsrAttributes.csrAttributesAsDataAttributesV3().size());
    }

    @Test
    void resolveSeedsFromCsrAttributesWhenStoredValueNull() {
        assertThat(DefaultRequestAttributeSet.resolve(null)).isNotEmpty();
    }

    @Test
    void resolveSeedsFromCsrAttributesWhenStoredValueBlank() {
        assertThat(DefaultRequestAttributeSet.resolve("   ")).isNotEmpty();
    }

    @Test
    void resolveParsesStoredValueWhenPresent() {
        // given: a stored serialized set distinct from the seed
        String stored = AttributeDefinitionUtils.serialize(DefaultRequestAttributeSet.seed());

        // when
        List<BaseAttribute> resolved = DefaultRequestAttributeSet.resolve(stored);

        // then
        assertThat(resolved).hasSize(DefaultRequestAttributeSet.seed().size());
    }
}
