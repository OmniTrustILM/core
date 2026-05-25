package com.czertainly.core.messaging.jms.configuration;

import com.czertainly.core.service.handler.authority.CertificateOperation;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StatusPollPropertiesTest {

    @Test
    void scheduleForFallsBackToDefaultsWhenKindNotOverridden() {
        StatusPollProperties.PollSchedule defaults = new StatusPollProperties.PollSchedule(
                List.of(Duration.ofSeconds(1)), 10);
        StatusPollProperties props = new StatusPollProperties(defaults, Map.of());
        assertEquals(defaults, props.scheduleFor(CertificateOperation.ISSUE));
    }

    @Test
    void scheduleForUsesByKindWhenPresent() {
        StatusPollProperties.PollSchedule defaults = new StatusPollProperties.PollSchedule(
                List.of(Duration.ofSeconds(1)), 10);
        StatusPollProperties.PollSchedule register = new StatusPollProperties.PollSchedule(
                List.of(Duration.ofSeconds(5)), 50);
        StatusPollProperties props = new StatusPollProperties(
                defaults, Map.of(CertificateOperation.REGISTER, register));
        assertEquals(register, props.scheduleFor(CertificateOperation.REGISTER));
        assertEquals(defaults, props.scheduleFor(CertificateOperation.ISSUE));
    }

    @Test
    void delayForReturnsCorrectDurationByAttempt() {
        StatusPollProperties.PollSchedule s = new StatusPollProperties.PollSchedule(
                List.of(Duration.ofSeconds(1), Duration.ofSeconds(3)), 10);
        assertEquals(Duration.ofSeconds(1), s.delayFor(1));
        assertEquals(Duration.ofSeconds(3), s.delayFor(2));
        assertEquals(Duration.ofSeconds(3), s.delayFor(99));  // plateau at last
    }

    @Test
    void delayForClampsZeroAttemptToFirstEntry() {
        StatusPollProperties.PollSchedule s = new StatusPollProperties.PollSchedule(
                List.of(Duration.ofSeconds(1), Duration.ofSeconds(3)), 10);
        assertEquals(Duration.ofSeconds(1), s.delayFor(0));
    }
}
