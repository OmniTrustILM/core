package com.czertainly.core.signing.record;

import com.czertainly.core.model.signing.SigningRecordPolicyModel;
import com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.aSigningRecordPolicy;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Named.named;

class SigningRecordPolicyTest {

    @Test
    void hasAnyRecordableContent_returnsFalse_whenNothingIsRecorded() {
        // given
        SigningRecordPolicyModel recordsNothing = SigningRecordPolicyModelBuilder.notRecording().build();

        // when
        boolean hasRecordableContent = SigningRecordPolicy.hasAnyRecordableContent(recordsNothing);

        // then
        assertFalse(hasRecordableContent);
    }

    private static Stream<Arguments> singleRecordFlagPolicies() {
        return Stream.of(
                Arguments.of(named("recordRequestMetadata", aSigningRecordPolicy().recordRequestMetadata(true).build())),
                Arguments.of(named("recordSignature", aSigningRecordPolicy().recordSignature(true).build())),
                Arguments.of(named("recordSignedDocument", aSigningRecordPolicy().recordSignedDocument(true).build())),
                Arguments.of(named("recordDtbs", aSigningRecordPolicy().recordDtbs(true).build())));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("singleRecordFlagPolicies")
    void hasAnyRecordableContent_returnsTrue_whenAnySingleRecordFlagIsSet(
            SigningRecordPolicyModel policyWithSingleFlag) {
        // when
        boolean hasRecordableContent = SigningRecordPolicy.hasAnyRecordableContent(policyWithSingleFlag);

        // then
        assertTrue(hasRecordableContent);
    }

    @Test
    void hasAnyRecordableContent_returnsTrue_whenEverythingIsRecorded() {
        // given
        SigningRecordPolicyModel recordsEverything = SigningRecordPolicyModelBuilder.recordingEverything().build();

        // when
        boolean hasRecordableContent = SigningRecordPolicy.hasAnyRecordableContent(recordsEverything);

        // then
        assertTrue(hasRecordableContent);
    }
}
