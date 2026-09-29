package com.otilm.core.model;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SearchFieldObjectTest {

    @Test
    void aCopyCarriesEveryFieldAndChangesIndependently() {
        SearchFieldObject original = new SearchFieldObject("environment", AttributeContentType.STRING,
                AttributeType.CUSTOM);
        original.setLabel("Environment");
        original.setList(true);
        original.setMultiSelect(true);
        original.setProtectionLevel(ProtectionLevel.NONE);
        original.setVisible(false);
        original.setContentItems(List.of("production", "staging"));

        SearchFieldObject copy = original.copy();
        assertThat(copy).isEqualTo(original).isNotSameAs(original);

        copy.setVisible(true);
        copy.setContentItems(List.of("other"));
        assertThat(original.isVisible()).isFalse();
        assertThat(original.getContentItems()).containsExactly("production", "staging");
    }
}
