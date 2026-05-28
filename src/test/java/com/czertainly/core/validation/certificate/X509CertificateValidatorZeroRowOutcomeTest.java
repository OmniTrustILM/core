package com.czertainly.core.validation.certificate;

import com.czertainly.api.model.core.certificate.CertificateState;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullSource;

import static com.czertainly.core.validation.certificate.X509CertificateValidator.ZeroRowOutcome.INTENT_ALREADY_SATISFIED;
import static com.czertainly.core.validation.certificate.X509CertificateValidator.ZeroRowOutcome.STATE_DIVERGENCE;
import static com.czertainly.core.validation.certificate.X509CertificateValidator.classifyZeroRowOutcome;
import static org.junit.jupiter.api.Assertions.assertEquals;

class X509CertificateValidatorZeroRowOutcomeTest {

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"REVOKED", "PENDING_REVOKE"})
    void revokeIntentAlreadyFulfilledByConcurrentPath(CertificateState observed) {
        assertEquals(INTENT_ALREADY_SATISFIED, classifyZeroRowOutcome(observed));
    }

    @ParameterizedTest
    @NullSource // findStateByUuid returns Optional.empty() if the row was deleted concurrently.
    @EnumSource(value = CertificateState.class, mode = EnumSource.Mode.EXCLUDE, names = {"REVOKED", "PENDING_REVOKE"})
    void anyOtherObservedStateIsDivergence(CertificateState observed) {
        assertEquals(STATE_DIVERGENCE, classifyZeroRowOutcome(observed));
    }
}
