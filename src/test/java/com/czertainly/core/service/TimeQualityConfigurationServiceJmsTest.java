package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.czertainly.core.dao.entity.signing.TimeQualityConfiguration;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.messaging.model.TimeQualityConfigChangedEvent;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.event.ApplicationEvents;
import org.springframework.test.context.event.RecordApplicationEvents;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@RecordApplicationEvents
class TimeQualityConfigurationServiceJmsTest extends BaseSpringBootTest {

    @Autowired ApplicationEvents applicationEvents;
    @Autowired TimeQualityConfigurationService service;
    @Autowired TimeQualityConfigurationRepository repository;

    private TimeQualityConfigurationRequestDto buildRequest(String name) {
        TimeQualityConfigurationRequestDto r = new TimeQualityConfigurationRequestDto();
        r.setName(name);
        r.setAccuracy(Duration.ofSeconds(1));
        r.setNtpServers(List.of("pool.ntp.org"));
        r.setNtpCheckInterval(Duration.ofSeconds(30));
        r.setNtpSamplesPerServer(4);
        r.setNtpCheckTimeout(Duration.ofSeconds(5));
        r.setNtpServersMinReachable(1);
        r.setMaxClockDrift(Duration.ofSeconds(1));
        r.setLeapSecondGuard(true);
        return r;
    }

    @BeforeEach
    void clearEvents() {
        applicationEvents.clear();
    }

    @Test
    void createTimeQualityConfiguration_firesConfigChangedEvent() throws AlreadyExistException, AttributeException, NotFoundException {
        service.createTimeQualityConfiguration(buildRequest("jms-create-test"));

        assertThat(applicationEvents.stream(TimeQualityConfigChangedEvent.class).count())
                .isGreaterThanOrEqualTo(1);
    }

    @Test
    void updateTimeQualityConfiguration_firesConfigChangedEvent() throws AlreadyExistException, AttributeException, NotFoundException {
        var created = service.createTimeQualityConfiguration(buildRequest("jms-update-test"));
        applicationEvents.clear();

        service.updateTimeQualityConfiguration(SecuredUUID.fromString(created.getUuid()), buildRequest("jms-update-test-renamed"));

        assertThat(applicationEvents.stream(TimeQualityConfigChangedEvent.class).count())
                .isGreaterThanOrEqualTo(1);
    }

    @Test
    void deleteTimeQualityConfiguration_firesConfigChangedEvent() throws AlreadyExistException, AttributeException, NotFoundException {
        var created = service.createTimeQualityConfiguration(buildRequest("jms-delete-test"));
        applicationEvents.clear();

        service.deleteTimeQualityConfiguration(SecuredUUID.fromString(created.getUuid()));

        assertThat(applicationEvents.stream(TimeQualityConfigChangedEvent.class).count())
                .isGreaterThanOrEqualTo(1);
    }
}
