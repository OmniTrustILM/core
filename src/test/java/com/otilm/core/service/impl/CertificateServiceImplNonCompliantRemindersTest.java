package com.otilm.core.service.impl;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.events.handlers.CertificateNotCompliantEventHandler;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.EventMessage;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateServiceImplNonCompliantRemindersTest {

    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private EventProducer eventProducer;

    private CertificateServiceImpl service;

    @BeforeEach
    void createService() {
        service = new CertificateServiceImpl();
        service.setCertificateRepository(certificateRepository);
        service.setEventProducer(eventProducer);
    }

    @Test
    void raisesReminderEventPerCertificate_whenCertificatesAreDue() {
        // given
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();
        when(certificateRepository.findNonCompliantCertificatesWithReminders(any(OffsetDateTime.class)))
                .thenReturn(List.of(first, second));

        // when
        int handled = service.handleNonCompliantCertificatesReminders();

        // then
        ArgumentCaptor<EventMessage> messages = ArgumentCaptor.forClass(EventMessage.class);
        verify(eventProducer, times(2)).produceMessage(messages.capture());
        assertThat(handled).isEqualTo(2);
        assertThat(messages.getAllValues()).allSatisfy(message -> {
            assertThat(message.getEvent()).isEqualTo(ResourceEvent.CERTIFICATE_NOT_COMPLIANT);
            assertThat(message.getResource()).isEqualTo(Resource.CERTIFICATE);
            assertThat(message.getData())
                    .isEqualTo(CertificateNotCompliantEventHandler.constructReminderEventMessage(first).getData());
        });
        assertThat(messages.getAllValues().stream().map(EventMessage::getObjectUuid)).containsExactly(first, second);
    }

    @Test
    void raisesNothing_whenNoCertificateIsDue() {
        // given
        when(certificateRepository.findNonCompliantCertificatesWithReminders(any(OffsetDateTime.class)))
                .thenReturn(List.of());

        // when
        int handled = service.handleNonCompliantCertificatesReminders();

        // then
        assertThat(handled).isZero();
        verifyNoInteractions(eventProducer);
    }
}
