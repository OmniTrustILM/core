package com.czertainly.core.messaging.jms.listeners.timequality;

import com.czertainly.api.model.messaging.timequality.TimeQualityConfigRequest;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.messaging.jms.producers.TimeQualityConfigurationProducer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TimeQualityConfigRequestListenerTest {

    @Mock TimeQualityConfigurationRepository repository;
    @Mock TimeQualityConfigurationProducer producer;

    @InjectMocks TimeQualityConfigRequestListener listener;

    @Test
    void processMessage_publishesSnapshotOfAllStoredConfigs() {
        TimeQualityConfiguration config = new TimeQualityConfiguration();
        config.setName("my-profile");
        when(repository.findAll()).thenReturn(List.of(config));

        UUID correlationId = UUID.randomUUID();
        TimeQualityConfigRequest request = new TimeQualityConfigRequest();
        request.setCorrelationId(correlationId);
        request.setRequestedAt(Instant.now());

        listener.processMessage(request);

        verify(producer).publishSnapshot(List.of(config), correlationId);
    }

    @Test
    void processMessage_withEmptyDb_publishesEmptySnapshot() {
        when(repository.findAll()).thenReturn(List.of());

        TimeQualityConfigRequest request = new TimeQualityConfigRequest();
        request.setCorrelationId(null);
        request.setRequestedAt(Instant.now());

        listener.processMessage(request);

        verify(producer).publishSnapshot(List.of(), null);
    }
}
