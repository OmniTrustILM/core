package com.czertainly.core.signing.tsa.validator;

import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import org.bouncycastle.asn1.x509.Extensions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.czertainly.core.model.signing.workflow.ManagedTimestampingWorkflowBuilder.aManagedTimestampingWorkflow;
import static com.czertainly.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class TspRequestValidatorTest {

    private final TspRequestValidator validator = new TspRequestValidator();

    // ── extensions ────────────────────────────────────────────────────────────

    @Test
    void validate_throwsUnacceptedExtension_whenRequestContainsExtensions() {
        // given — extensions are not supported; any non-null Extensions value triggers the check
        var workflow = aManagedTimestampingWorkflow().build();
        var request = aTspRequest()
                .requestExtensions(mock(Extensions.class))
                .build();

        // when / then
        var exception = assertThrows(TspRequestValidationException.class,
                () -> validator.validate(workflow, request));
        assertEquals(TspFailureInfo.UNACCEPTED_EXTENSION, exception.getFailureInfo());
    }

    @Test
    void validate_doesNotThrow_whenRequestHasNoExtensions() throws Exception {
        // given
        var workflow = aManagedTimestampingWorkflow().build();
        var request = aTspRequest()
                .requestExtensions(null)
                .build();

        // when / then
        assertDoesNotThrow(() -> validator.validate(workflow, request));
    }

    // ── hash algorithm ────────────────────────────────────────────────────────

    @Test
    void validate_throwsBadAlg_whenHashAlgorithmNotInAllowedList() {
        // given
        var workflow = aManagedTimestampingWorkflow()
                .allowedDigestAlgorithms(List.of(DigestAlgorithm.SHA_512))
                .build();
        var request = aTspRequest()
                .hashAlgorithm(DigestAlgorithm.SHA_256)
                .build();

        // when / then
        var exception = assertThrows(TspRequestValidationException.class,
                () -> validator.validate(workflow, request));
        assertEquals(TspFailureInfo.BAD_ALG, exception.getFailureInfo());
    }

    @Test
    void validate_doesNotThrow_whenHashAlgorithmIsInAllowedList() {
        // given
        var workflow = aManagedTimestampingWorkflow()
                .allowedDigestAlgorithms(List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_512))
                .build();
        var request = aTspRequest()
                .hashAlgorithm(DigestAlgorithm.SHA_256)
                .build();

        // when / then
        assertDoesNotThrow(() -> validator.validate(workflow, request));
    }

    @Test
    void validate_doesNotThrow_whenAllowedAlgorithmsListIsEmpty() {
        // given — an empty list means no restriction; any algorithm is accepted
        var workflow = aManagedTimestampingWorkflow()
                .allowedDigestAlgorithms(List.of())
                .build();
        var request = aTspRequest()
                .hashAlgorithm(DigestAlgorithm.SHA_256)
                .build();

        // when / then
        assertDoesNotThrow(() -> validator.validate(workflow, request));
    }

    // ── policy ────────────────────────────────────────────────────────────────

    @Test
    void validate_throwsUnacceptedPolicy_whenRequestedPolicyNotInAllowedList() {
        // given
        var workflow = aManagedTimestampingWorkflow()
                .allowedPolicyIds(List.of("1.2.3.4.1"))
                .build();
        var request = aTspRequest()
                .policy("1.2.3.4.5")
                .build();

        // when / then
        var exception = assertThrows(TspRequestValidationException.class,
                () -> validator.validate(workflow, request));
        assertEquals(TspFailureInfo.UNACCEPTED_POLICY, exception.getFailureInfo());
    }

    @Test
    void validate_doesNotThrow_whenRequestedPolicyIsInAllowedList() {
        // given
        var workflow = aManagedTimestampingWorkflow()
                .allowedPolicyIds(List.of("1.2.3.4.5", "1.2.3.4.1"))
                .build();
        var request = aTspRequest()
                .policy("1.2.3.4.5")
                .build();

        // when / then
        assertDoesNotThrow(() -> validator.validate(workflow, request));
    }

    @Test
    void validate_doesNotThrow_whenRequestContainsNoPolicyAndAllowedListIsNonEmpty() {
        // given — a client did not request a specific policy, so any profile policy applies
        var workflow = aManagedTimestampingWorkflow()
                .allowedPolicyIds(List.of("1.2.3.4.5"))
                .build();
        var request = aTspRequest()
                .build(); // no policy → Optional.empty()

        // when / then
        assertDoesNotThrow(() -> validator.validate(workflow, request));
    }

    @Test
    void validate_doesNotThrow_whenAllowedPolicyListIsEmpty() {
        // given — an empty allowed list means no restriction; any requested policy is accepted
        var workflow = aManagedTimestampingWorkflow()
                .allowedPolicyIds(List.of())
                .build();
        var request = aTspRequest()
                .policy("1.2.3.4.5")
                .build();

        // when / then
        assertDoesNotThrow(() -> validator.validate(workflow, request));
    }
}
