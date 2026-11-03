package com.otilm.core.events.handlers;

import com.otilm.api.exception.EventException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.workflows.TriggerAssociationRepository;
import com.otilm.core.evaluator.CertificateTriggerEvaluator;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.ComplianceInternalService;
import com.otilm.core.service.writer.PendingNotificationWriter;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateNotCompliantEventHandlerTest {

    @Mock
    private PendingNotificationWriter pendingNotificationWriter;
    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private CertificateTriggerEvaluator triggerEvaluator;
    @Mock
    private ComplianceInternalService complianceService;
    @Mock
    private TriggerAssociationRepository triggerAssociationRepository;

    private CertificateNotCompliantEventHandler handler;

    @BeforeEach
    void createHandler() {
        handler = new CertificateNotCompliantEventHandler(certificateRepository, triggerEvaluator);
        handler.setPendingNotificationWriter(pendingNotificationWriter);
        handler.setComplianceService(complianceService);
        handler.setTriggerAssociationRepository(triggerAssociationRepository);
    }

    @Test
    void resetsPendingNotifications_whenHandlingATransition() {
        // given
        UUID certificateUuid = UUID.randomUUID();
        EventMessage transition = CertificateNotCompliantEventHandler.constructEventMessages(certificateUuid);

        // when
        ThrowingCallable handleTransition = () -> handler.handleEvent(transition);

        // then
        assertThatThrownBy(handleTransition).isInstanceOf(EventException.class);
        verify(pendingNotificationWriter)
                .deleteForObjectAndEvent(Resource.CERTIFICATE, certificateUuid,
                        ResourceEvent.CERTIFICATE_NOT_COMPLIANT);
    }

    @Test
    void runsTriggersWithoutReset_whenCertificateIsStillNotCompliant() throws Exception {
        // given
        UUID certificateUuid = UUID.randomUUID();
        when(certificateRepository.findByUuid(any(SecuredUUID.class)))
                .thenReturn(Optional
                        .of(aCertificate()
                                .withUuid(certificateUuid)
                                .withComplianceStatus(ComplianceStatus.NOK)
                                .build()));
        EventMessage reminder = CertificateNotCompliantEventHandler.constructReminderEventMessage(certificateUuid);

        // when
        handler.handleEvent(reminder);

        // then
        verify(triggerAssociationRepository)
                .findAllByEventAndResourceAndObjectUuidOrderByTriggerOrderAsc(
                        eq(ResourceEvent.CERTIFICATE_NOT_COMPLIANT), isNull(), isNull());
        verifyNoInteractions(pendingNotificationWriter);
    }

    @Test
    void dropsReminder_whenCertificateHasRecovered() throws Exception {
        // given
        UUID certificateUuid = UUID.randomUUID();
        when(certificateRepository.findByUuid(any(SecuredUUID.class)))
                .thenReturn(Optional
                        .of(aCertificate()
                                .withUuid(certificateUuid)
                                .withComplianceStatus(ComplianceStatus.OK)
                                .build()));
        EventMessage reminder = CertificateNotCompliantEventHandler.constructReminderEventMessage(certificateUuid);

        // when
        handler.handleEvent(reminder);

        // then
        verifyNoInteractions(pendingNotificationWriter, triggerAssociationRepository);
    }

    @Test
    void dropsReminder_whenCertificateDoesNotExist() throws Exception {
        // given
        UUID missingCertificateUuid = UUID.randomUUID();
        when(certificateRepository.findByUuid(any(SecuredUUID.class))).thenReturn(Optional.empty());
        EventMessage reminder = CertificateNotCompliantEventHandler
                .constructReminderEventMessage(missingCertificateUuid);

        // when
        handler.handleEvent(reminder);

        // then
        verifyNoInteractions(pendingNotificationWriter, triggerAssociationRepository);
    }
}
