package com.czertainly.core.messaging.jms.listeners.timequality;

import com.czertainly.api.model.messaging.timequality.TimeQualityConfigRequest;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import com.czertainly.core.messaging.jms.producers.TimeQualityConfigurationProducer;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
@Slf4j
@Transactional(propagation = Propagation.NOT_SUPPORTED)
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
