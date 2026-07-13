package com.otilm.core.events.handlers;

import com.otilm.api.model.common.events.data.CertificateRegisteredEventData;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CertificateRegisteredEventHandlerTest {

    private final CertificateRegistrationAuthorizationRepository authorizationRepository =
            mock(CertificateRegistrationAuthorizationRepository.class);
    private final RegistrationChallengeStore challengeStore = mock(RegistrationChallengeStore.class);
    private final CertificateRegisteredEventHandler handler = new CertificateRegisteredEventHandler(
            mock(CertificateRepository.class), mock(CertificateTriggerEvaluator.class), challengeStore, authorizationRepository);

    @Test
    void getEventDataResolvesCredentialAndDeadlineAndKeepsCredentialOutOfToString() {
        UUID certUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setUuid(certUuid);
        certificate.setSubjectDn("CN=device-7");

        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(certUuid);
        authorization.setExpiresAt(OffsetDateTime.parse("2026-08-01T00:00:00Z"));
        when(authorizationRepository.findByCertificateUuid(certUuid)).thenReturn(Optional.of(authorization));
        when(challengeStore.resolvePlaintext(authorization)).thenReturn("s3cret-challenge");

        CertificateRegisteredEventData data = (CertificateRegisteredEventData) handler.getEventData(certificate, null);

        assertEquals("s3cret-challenge", data.getCredential(), "credential is recovered for external delivery");
        assertNotNull(data.getIssuanceDeadline(), "issuance deadline comes from the authorization");
        assertEquals("CN=device-7", data.getSubjectDn());
        assertFalse(data.toString().contains("s3cret-challenge"), "credential must not leak via the event-data toString");
    }

    @Test
    void getEventDataWithoutAuthorizationLeavesCredentialNull() {
        UUID certUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setUuid(certUuid);
        when(authorizationRepository.findByCertificateUuid(certUuid)).thenReturn(Optional.empty());

        CertificateRegisteredEventData data = (CertificateRegisteredEventData) handler.getEventData(certificate, null);

        assertNull(data.getCredential());
        assertNull(data.getIssuanceDeadline());
    }
}
