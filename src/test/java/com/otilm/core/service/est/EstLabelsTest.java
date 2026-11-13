package com.otilm.core.service.est;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class EstLabelsTest {

    @ParameterizedTest
    @ValueSource(strings = {"est-devices", "ra_1", "a.b~c"})
    void returnsTrue_whenNameIsUnreserved(String unreservedName) {
        // given — a name of unreserved characters only, neither a reserved label nor a dot segment

        // when
        boolean usable = EstLabels.isUsable(unreservedName);

        // then
        assertThat(usable).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"cacerts", "CACERTS", ".", "..", "a/b", "a b", "ä", ""})
    void returnsFalse_whenNameBreaksTheLabelRules(String unusableName) {
        // given — a reserved label, a dot segment, a name with a reserved character, or an empty name

        // when
        boolean usable = EstLabels.isUsable(unusableName);

        // then
        assertThat(usable).isFalse();
    }

    @Test
    void returnsFalse_whenNameIsNull() {
        // given — no name

        // when
        boolean usable = EstLabels.isUsable(null);

        // then
        assertThat(usable).isFalse();
    }
}
