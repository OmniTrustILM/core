package com.czertainly.core.messaging.jms.producers;

import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.messaging.model.TimeQualityConfigChangedEvent;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@AllArgsConstructor
@Slf4j
public class TimeQualityMonitorInitializer {

    private final TimeQualityConfigurationRepository timeQualityConfigurationRepository;
    private final TimeQualityConfigurationProducer timeQualityConfigurationProducer;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        log.info("Broadcasting initial time quality configuration snapshot to Monitor");
        timeQualityConfigurationProducer.publishSnapshot(timeQualityConfigurationRepository.findAll(), null);
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, classes = TimeQualityConfigChangedEvent.class)
    public void onConfigChanged() {
        timeQualityConfigurationProducer.publishSnapshot(timeQualityConfigurationRepository.findAll(), null);
    }
}
