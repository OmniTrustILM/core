package com.otilm.core.signing.tsa;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static com.otilm.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.assertj.core.api.Assertions.assertThat;

class EffectiveTimestampPolicyTest {

    private static final String REQUESTED_POLICY = "1.2.3.4.9";
    private static final String DEFAULT_POLICY = "1.2.3.4.5";

    @Test
    void prefersThePolicyTheRequestNames() {
        assertThat(EffectiveTimestampPolicy.resolve(aTspRequest().policy(REQUESTED_POLICY).build(), DEFAULT_POLICY))
                .contains(REQUESTED_POLICY);
    }

    @Test
    void fallsBackToTheProfileDefault_whenTheRequestNamesNoPolicy() {
        assertThat(EffectiveTimestampPolicy.resolve(aTspRequest().build(), DEFAULT_POLICY)).contains(DEFAULT_POLICY);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "   "})
    void resolvesToNothing_whenTheRequestNamesNoPolicyAndTheProfileConfiguresNoUsableDefault(String defaultPolicyId) {
        assertThat(EffectiveTimestampPolicy.resolve(aTspRequest().build(), defaultPolicyId)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    void fallsBackToTheProfileDefault_whenTheRequestNamesABlankPolicy(String requestedPolicy) {
        assertThat(EffectiveTimestampPolicy.resolve(aTspRequest().policy(requestedPolicy).build(), DEFAULT_POLICY))
                .contains(DEFAULT_POLICY);
    }

    @Test
    void resolvesTheRequestedPolicy_whenTheProfileConfiguresNoDefault() {
        assertThat(EffectiveTimestampPolicy.resolve(aTspRequest().policy(REQUESTED_POLICY).build(), null))
                .contains(REQUESTED_POLICY);
    }
}
