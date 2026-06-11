package com.otilm.core.messaging.jms.listeners.timequality;

import com.otilm.api.model.messaging.timequality.TimeQualityConfigRequest;
import com.otilm.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.otilm.core.messaging.jms.listeners.MessageProcessor;
import com.otilm.core.messaging.jms.producers.TimeQualityConfigurationProducer;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
@Slf4j
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@ConditionalOnProperty(name = "messaging.time-quality.enabled", havingValue = "true")
@AllArgsConstructor
public class TimeQualityConfigRequestListener implements MessageProcessor<TimeQualityConfigRequest> {

    private final TimeQualityConfigurationRepository timeQualityConfigurationRepository;
    private final TimeQualityConfigurationProducer timeQualityConfigurationProducer;

    @Override
    public void processMessage(TimeQualityConfigRequest message) {
        log.debug("Received time quality config request (requestedAt={})", message.getRequestedAt());
        timeQualityConfigurationProducer.publishSnapshot(timeQualityConfigurationRepository.findAll(), message.getCorrelationId());
    }
}
