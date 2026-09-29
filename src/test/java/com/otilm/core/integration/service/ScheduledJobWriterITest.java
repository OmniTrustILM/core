package com.otilm.core.integration.service;

import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.service.writer.scheduler.ScheduledJobWriter;
import com.otilm.core.tasks.CryptoAssetPqcSweepTask;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The skip writer against a real database: in place, one row however often the job skips, and a vanished job reported.
 */
class ScheduledJobWriterITest extends BaseSpringBootTest {

    private static final String NOTHING_TO_DO = "No stale cryptographic asset to re-evaluate";

    @Autowired
    private ScheduledJobWriter writer;

    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;

    private ScheduledJob scheduledJob;

    @BeforeEach
    void setUp() {
        scheduledJob = new ScheduledJob();
        scheduledJob.setJobName(CryptoAssetPqcSweepTask.NAME);
        scheduledJob.setJobClassName(CryptoAssetPqcSweepTask.class.getName());
        scheduledJob.setCronExpression("0 30 * ? * *");
        scheduledJob.setEnabled(true);
        scheduledJob.setOneTime(false);
        scheduledJob.setSystem(true);
        scheduledJobsRepository.save(scheduledJob);
    }

    @Test
    void recordSkipped_writesTheSkipOnTheJob() {
        OffsetDateTime before = OffsetDateTime.now().minusSeconds(1);

        writer.recordSkipped(scheduledJob.getUuid(), NOTHING_TO_DO);

        ScheduledJob stored = scheduledJobsRepository.findById(scheduledJob.getUuid()).orElseThrow();
        assertNotNull(stored.getLastSkippedAt());
        assertTrue(stored.getLastSkippedAt().isAfter(before));
        assertEquals(NOTHING_TO_DO, stored.getLastSkipReason());
    }

    @Test
    void recordSkipped_overwritesThePreviousSkipRatherThanAddingARow() {
        writer.recordSkipped(scheduledJob.getUuid(), NOTHING_TO_DO);
        OffsetDateTime first = scheduledJobsRepository
                .findById(scheduledJob.getUuid())
                .orElseThrow()
                .getLastSkippedAt();

        writer.recordSkipped(scheduledJob.getUuid(), "The CBOM repository answered 503 Service Unavailable");

        ScheduledJob stored = scheduledJobsRepository.findById(scheduledJob.getUuid()).orElseThrow();
        assertEquals("The CBOM repository answered 503 Service Unavailable", stored.getLastSkipReason());
        assertTrue(!stored.getLastSkippedAt().isBefore(first));
        assertEquals(1, scheduledJobsRepository.count());
    }

    @Test
    void recordSkipped_reportsAVanishedJob() {
        UUID gone = UUID.randomUUID();

        assertThrows(IllegalStateException.class, () -> writer.recordSkipped(gone, NOTHING_TO_DO));
    }
}
