package com.czertainly.core.messaging.jms.listeners.timequality;

import com.czertainly.api.model.messaging.timequality.TimeQualityResultMessage;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.messaging.jms.listeners.MessageProcessor;
import com.czertainly.core.signing.tsa.timequality.NtpServerResult;
import com.czertainly.core.signing.tsa.timequality.TimeQualityRegister;
import com.czertainly.core.signing.tsa.timequality.TimeQualityResult;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@Slf4j
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@AllArgsConstructor
public class TimeQualityResultListener implements MessageProcessor<TimeQualityResultMessage> {

    private final TimeQualityConfigurationRepository timeQualityConfigurationRepository;
    private final TimeQualityRegister timeQualityRegister;

    @Override
    public void processMessage(TimeQualityResultMessage message) {
        if (!timeQualityConfigurationRepository.existsById(message.getConfigurationId())) {
            log.warn("Received time quality result for unknown configuration ID={}, dropping", message.getConfigurationId());
            return;
        }

        log.debug("Received time quality result for configuration ID={}", message.getConfigurationId());
        timeQualityRegister.update(toRecord(message));
    }

    private TimeQualityResult toRecord(TimeQualityResultMessage message) {
        var servers = message.getMeasurements() != null
                ? message.getMeasurements().stream()
                        .map(m -> new NtpServerResult(m.getHost(), m.isReachable(), m.getOffsetMs(), m.getRttMs(), m.getStratum(), m.getPrecisionMs()))
                        .toList()
                : List.<NtpServerResult>of();
        return new TimeQualityResult(
                message.getConfigurationId(),
                message.getName(),
                message.getTimestamp(),
                message.getStatus(),
                message.getMeasuredDriftMs(),
                message.getReachableServers(),
                message.getReason(),
                message.getLeapSecondWarning(),
                servers);
    }
}
