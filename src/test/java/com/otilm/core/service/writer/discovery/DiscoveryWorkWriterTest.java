package com.otilm.core.service.writer.discovery;

import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class DiscoveryWorkWriterTest {

    @Mock
    private DiscoveryWorkRepository workRepository;

    private DiscoveryWorkWriter writer;

    private static final UUID RUN_UUID = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        writer = new DiscoveryWorkWriter(workRepository);
    }

    @Test
    void schedule_delegatesToReArmingUpsert() {
        OffsetDateTime due = OffsetDateTime.now();

        writer.schedule(RUN_UUID, DiscoveryWorkType.STATUS, due);

        verify(workRepository).schedule(any(UUID.class), eq(RUN_UUID), eq("STATUS"), eq(due));
    }

    @Test
    void reschedule_delegatesToRepository() {
        OffsetDateTime next = OffsetDateTime.now();

        writer.reschedule(RUN_UUID, DiscoveryWorkType.DRAIN, 4, next);

        verify(workRepository).reschedule(RUN_UUID, DiscoveryWorkType.DRAIN, 4, next);
    }

    @Test
    void resetAttempt_delegatesToRepository() {
        writer.resetAttempt(RUN_UUID, DiscoveryWorkType.STATUS, 6);

        verify(workRepository).resetAttemptTo(RUN_UUID, DiscoveryWorkType.STATUS, 6);
    }

    @Test
    void deleteForRun_delegatesToRepository() {
        writer.deleteForRun(RUN_UUID);

        verify(workRepository).deleteByDiscoveryUuid(RUN_UUID);
    }
}
