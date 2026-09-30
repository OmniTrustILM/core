package com.otilm.core.integration.service;

import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.repository.ScheduledJobHistoryRepository;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.service.SchedulerInternalService;
import com.otilm.core.service.writer.scheduler.ScheduledJobWriter;
import com.otilm.core.tasks.CryptoAssetPqcSweepTask;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The skip writer against a real database: in place, one row however often the job skips, and a vanished job reported;
 * and a declined run from the scheduler's trigger to the skip on the job.
 */
class ScheduledJobWriterITest extends BaseSpringBootTest {

    private static final String NOTHING_TO_DO = "No stale cryptographic asset to re-evaluate";

    @Autowired
    private ScheduledJobWriter writer;

    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;

    @Autowired
    private ScheduledJobHistoryRepository scheduledJobHistoryRepository;

    @Autowired
    private SchedulerInternalService schedulerService;

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
    }

    /**
     * Enable, disable and update save the job they read before the call to the scheduler. A skip recorded in between
     * must survive that save: reverted on a job that is then paused, it would read as a job the scheduler fired and
     * core never ran.
     */
    @Test
    void recordSkipped_survivesASaveOfACopyReadBeforeIt() {
        ScheduledJob readBeforeTheSkip = scheduledJobsRepository.findById(scheduledJob.getUuid()).orElseThrow();

        writer.recordSkipped(scheduledJob.getUuid(), NOTHING_TO_DO);
        readBeforeTheSkip.setEnabled(false);
        scheduledJobsRepository.save(readBeforeTheSkip);

        ScheduledJob stored = scheduledJobsRepository.findById(scheduledJob.getUuid()).orElseThrow();
        assertFalse(stored.isEnabled());
        assertNotNull(stored.getLastSkippedAt());
        assertEquals(NOTHING_TO_DO, stored.getLastSkipReason());
    }

    @Test
    void recordSkipped_reportsAVanishedJob() {
        UUID gone = UUID.randomUUID();

        assertThrows(IllegalStateException.class, () -> writer.recordSkipped(gone, NOTHING_TO_DO));
    }

    /**
     * A declined run end to end, as the scheduler triggers it: the PQC sweep on an empty estate finds nothing and
     * declines. Its STARTED row is gone once the run returns, and the skip is on the job.
     */
    @Test
    void aDeclinedRunLeavesNoHistoryRowAndItsSkipOnTheJob() throws Exception {
        schedulerService.runScheduledJob(CryptoAssetPqcSweepTask.NAME);

        assertFalse(scheduledJobHistoryRepository.existsByScheduledJobUuid(scheduledJob.getUuid()));
        ScheduledJob stored = scheduledJobsRepository.findById(scheduledJob.getUuid()).orElseThrow();
        assertNotNull(stored.getLastSkippedAt());
        assertEquals(NOTHING_TO_DO, stored.getLastSkipReason());
    }
}
