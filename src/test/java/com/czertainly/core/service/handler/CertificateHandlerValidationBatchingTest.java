package com.czertainly.core.service.handler;

import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.events.transaction.CertificateValidationEvent;
import com.czertainly.core.messaging.jms.producers.ValidationProducer;
import com.czertainly.core.messaging.model.ValidationMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class CertificateHandlerValidationBatchingTest {

    private static final int BATCH_SIZE = 10;

    @Mock
    private ValidationProducer validationProducer;

    private CertificateHandler handler;

    @BeforeEach
    void setUp() {
        handler = new CertificateHandler();
        handler.setValidationBatchSize(BATCH_SIZE);
        handler.setValidationProducer(validationProducer);
    }

    @Test
    void singleBatch_whenListSizeExactlyBatchSize() {
        List<UUID> uuids = uuids(BATCH_SIZE);
        handler.handleCertificateValidationEvent(new CertificateValidationEvent(uuids));

        ArgumentCaptor<ValidationMessage> captor = ArgumentCaptor.forClass(ValidationMessage.class);
        verify(validationProducer, times(1)).produceMessage(captor.capture());
        assertThat(captor.getValue().getUuids()).hasSize(BATCH_SIZE);
    }

    @Test
    void twoBatches_whenListSizeExceedsBatchSizeByOne() {
        List<UUID> uuids = uuids(BATCH_SIZE + 1);
        handler.handleCertificateValidationEvent(new CertificateValidationEvent(uuids));

        ArgumentCaptor<ValidationMessage> captor = ArgumentCaptor.forClass(ValidationMessage.class);
        verify(validationProducer, times(2)).produceMessage(captor.capture());
        List<ValidationMessage> batches = captor.getAllValues();
        assertThat(batches.get(0).getUuids()).hasSize(BATCH_SIZE);
        assertThat(batches.get(1).getUuids()).hasSize(1);
        assertThat(batches.get(0).getUuids()).doesNotContainAnyElementsOf(batches.get(1).getUuids());
    }

    @Test
    void correctBatchCount_forArbitraryListSize() {
        List<UUID> uuids = uuids(2 * BATCH_SIZE + 5);
        handler.handleCertificateValidationEvent(new CertificateValidationEvent(uuids));

        ArgumentCaptor<ValidationMessage> captor = ArgumentCaptor.forClass(ValidationMessage.class);
        verify(validationProducer, times(3)).produceMessage(captor.capture());
        List<ValidationMessage> batches = captor.getAllValues();
        assertThat(batches.get(0).getUuids()).hasSize(BATCH_SIZE);
        assertThat(batches.get(1).getUuids()).hasSize(BATCH_SIZE);
        assertThat(batches.get(2).getUuids()).hasSize(5);
    }

    @Test
    void discoveryAndLocationFieldsPropagatedToEveryBatch() {
        UUID discoveryUuid = UUID.randomUUID();
        UUID locationUuid = UUID.randomUUID();
        CertificateValidationEvent event = new CertificateValidationEvent(
                uuids(BATCH_SIZE + 1), discoveryUuid, "disc", locationUuid, "loc");
        handler.handleCertificateValidationEvent(event);

        ArgumentCaptor<ValidationMessage> captor = ArgumentCaptor.forClass(ValidationMessage.class);
        verify(validationProducer, times(2)).produceMessage(captor.capture());
        for (ValidationMessage msg : captor.getAllValues()) {
            assertThat(msg.getResource()).isEqualTo(Resource.CERTIFICATE);
            assertThat(msg.getDiscoveryUuid()).isEqualTo(discoveryUuid);
            assertThat(msg.getDiscoveryName()).isEqualTo("disc");
            assertThat(msg.getLocationUuid()).isEqualTo(locationUuid);
            assertThat(msg.getLocationName()).isEqualTo("loc");
        }
    }

    @Test
    void setBatchSize_throwsOnZeroOrNegative() {
        assertThatThrownBy(() -> handler.setValidationBatchSize(0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> handler.setValidationBatchSize(-1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static List<UUID> uuids(int count) {
        List<UUID> list = new ArrayList<>(count);
        for (int i = 0; i < count; i++) list.add(UUID.randomUUID());
        return list;
    }
}
