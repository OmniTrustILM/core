package com.czertainly.core.messaging.jms.listeners.timequality;

import com.czertainly.api.model.messaging.timequality.LeapSecondWarning;
import com.czertainly.api.model.messaging.timequality.NtpServerMeasurementResult;
import com.czertainly.api.model.messaging.timequality.TimeQualityResultMessage;
import com.czertainly.api.model.messaging.timequality.TimeQualityStatus;
import com.czertainly.core.dao.repository.signing.TimeQualityConfigurationRepository;
import com.czertainly.core.signing.tsa.timequality.TimeQualityRegister;
import com.czertainly.core.signing.tsa.timequality.TimeQualityResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TimeQualityResultListenerTest {

    @Mock TimeQualityConfigurationRepository repository;
    @Mock TimeQualityRegister register;

    @InjectMocks TimeQualityResultListener listener;

    @Test
    void processMessage_withKnownId_updatesRegister() {
        UUID id = UUID.randomUUID();
        when(repository.existsById(id)).thenReturn(true);

        listener.processMessage(buildMessage(id, "known", TimeQualityStatus.OK));

        ArgumentCaptor<TimeQualityResult> captor = ArgumentCaptor.forClass(TimeQualityResult.class);
        verify(register).update(captor.capture());
        assertThat(captor.getValue().name()).isEqualTo("known");
        assertThat(captor.getValue().status()).isEqualTo(TimeQualityStatus.OK);
    }

    @Test
    void processMessage_withUnknownId_dropsMessage() {
        UUID id = UUID.randomUUID();
        when(repository.existsById(id)).thenReturn(false);

        listener.processMessage(buildMessage(id, "unknown", TimeQualityStatus.OK));

        verifyNoInteractions(register);
    }

    @Test
    void processMessage_withDegradedStatus_registersCorrectStatus() {
        UUID id = UUID.randomUUID();
        when(repository.existsById(id)).thenReturn(true);

        listener.processMessage(buildMessage(id, "degraded", TimeQualityStatus.DEGRADED));

        ArgumentCaptor<TimeQualityResult> captor = ArgumentCaptor.forClass(TimeQualityResult.class);
        verify(register).update(captor.capture());
        assertThat(captor.getValue().status()).isEqualTo(TimeQualityStatus.DEGRADED);
    }

    private TimeQualityResultMessage buildMessage(UUID id, String name, TimeQualityStatus status) {
        NtpServerMeasurementResult server = new NtpServerMeasurementResult();
        server.setHost("pool.ntp.org");
        server.setReachable(true);
        server.setOffsetMs(0.0);
        server.setRttMs(1.0);
        server.setStratum(2);
        server.setPrecisionMs(0.1);

        TimeQualityResultMessage msg = new TimeQualityResultMessage();
        msg.setConfigurationId(id);
        msg.setName(name);
        msg.setTimestamp(Instant.now());
        msg.setStatus(status);
        msg.setMeasuredDriftMs(0.0);
        msg.setReachableServers(1);
        msg.setLeapSecondWarning(LeapSecondWarning.NONE);
        msg.setMeasurements(List.of(server));
        return msg;
    }
}
