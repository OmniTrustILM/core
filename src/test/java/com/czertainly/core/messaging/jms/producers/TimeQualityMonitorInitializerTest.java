package com.czertainly.core.messaging.jms.producers;

import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TimeQualityMonitorInitializerTest {

    @Mock TimeQualityConfigurationRepository repository;
    @Mock TimeQualityConfigurationProducer producer;

    @InjectMocks TimeQualityMonitorInitializer initializer;

    @Test
    void onApplicationReady_publishesSnapshotOfAllConfigs() {
        TimeQualityConfiguration config = new TimeQualityConfiguration();
        config.setName("test");
        when(repository.findAll()).thenReturn(List.of(config));

        initializer.onApplicationReady();

        verify(producer).publishSnapshot(List.of(config), null);
    }

    @Test
    void onConfigChanged_republishesSnapshot() {
        when(repository.findAll()).thenReturn(List.of());

        initializer.onConfigChanged();

        verify(producer).publishSnapshot(List.of(), null);
    }
}
