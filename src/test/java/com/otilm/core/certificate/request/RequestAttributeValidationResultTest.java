package com.otilm.core.certificate.request;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RequestAttributeValidationResultTest {

    @Test
    void staysValid_whenOnlyWarningsAdded() {
        // given
        var result = new RequestAttributeValidationResult();

        // when
        result.addWarning("non-blocking note");

        // then
        assertThat(result.isValid()).isTrue();
        assertThat(result.hasErrors()).isFalse();
        assertThat(result.getWarnings()).containsExactly("non-blocking note");
    }

    @Test
    void becomesInvalid_whenErrorAdded() {
        // given
        var result = new RequestAttributeValidationResult();

        // when
        result.addError("Missing required mapped field: Common Name");

        // then
        assertThat(result.isValid()).isFalse();
        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors()).containsExactly("Missing required mapped field: Common Name");
    }

    @Test
    void lenientPolicy_isNeitherStrictNorWhitelist() {
        // given / when
        var policy = RequestAttributePolicy.lenient();

        // then
        assertThat(policy.strict()).isFalse();
        assertThat(policy.whitelist()).isFalse();
    }

    @Test
    void strictWhitelistPolicy_reportsBothFlags() {
        // given / when
        var policy = new RequestAttributePolicy(true, true);

        // then
        assertThat(policy.strict()).isTrue();
        assertThat(policy.whitelist()).isTrue();
    }
}
