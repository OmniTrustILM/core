package com.otilm.core.events.handlers;

import com.otilm.api.exception.EventException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.writer.PendingNotificationWriter;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class CertificateNotCompliantEventHandlerTest {

    private final PendingNotificationWriter writer = mock(PendingNotificationWriter.class);

    private CertificateNotCompliantEventHandler handler() {
        CertificateRepository repository = mock(CertificateRepository.class);
        CertificateNotCompliantEventHandler handler = new CertificateNotCompliantEventHandler(repository,
                mock(CertificateTriggerEvaluator.class));
        handler.setPendingNotificationWriter(writer);
        return handler;
    }

    @Test
    void transitionStartsANewEpisodeBeforeTriggersRun() {
        UUID certificateUuid = UUID.randomUUID();

        // The certificate cannot be loaded, so handling stops right after the reset.
        assertThrows(EventException.class, () -> handler()
                .handleEvent(CertificateNotCompliantEventHandler.constructEventMessages(certificateUuid)));

        verify(writer)
                .deleteForObjectAndEvent(Resource.CERTIFICATE, certificateUuid,
                        ResourceEvent.CERTIFICATE_NOT_COMPLIANT);
    }

    @Test
    void reminderForACertificateThatRecoveredIsDropped() throws Exception {
        UUID certificateUuid = UUID.randomUUID();
        Certificate recovered = new Certificate();
        recovered.setComplianceStatus(ComplianceStatus.OK);
        CertificateRepository repository = mock(CertificateRepository.class);
        when(repository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.of(recovered));
        CertificateNotCompliantEventHandler handler = new CertificateNotCompliantEventHandler(repository,
                mock(CertificateTriggerEvaluator.class));
        handler.setPendingNotificationWriter(writer);

        assertDoesNotThrow(() -> handler
                .handleEvent(CertificateNotCompliantEventHandler.constructReminderEventMessage(certificateUuid)));

        verifyNoInteractions(writer);
    }

    @Test
    void reminderForAMissingCertificateIsDropped() {
        assertDoesNotThrow(() -> handler()
                .handleEvent(CertificateNotCompliantEventHandler.constructReminderEventMessage(UUID.randomUUID())));

        verifyNoInteractions(writer);
    }
}
