package com.otilm.core.integration.cbom;

import com.otilm.api.model.core.cbom.CbomSyncSkipState;
import com.otilm.core.cbom.sync.CbomSyncSkipRetentionSweeper;
import com.otilm.core.dao.entity.cbom.CbomSyncSkip;
import com.otilm.core.dao.repository.cbom.CbomSyncSkipRepository;
import com.otilm.core.model.cbom.CbomHeaderCounts;
import com.otilm.core.service.writer.cbom.CbomSyncSkipWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The retention sweep against real PostgreSQL: which rows the cutoff selects, and that a backlog larger than one batch
 * is removed batch by batch. The loop's cap and its lock gate are proved on a mocked writer in the unit test.
 */
class CbomSyncSkipRetentionSweeperITest extends BaseSpringBootTest {

    @Autowired
    private CbomSyncSkipRetentionSweeper sweeper;
    @Autowired
    private CbomSyncSkipWriter skipWriter;
    @Autowired
    private CbomSyncSkipRepository skipRepository;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * Age is the last attempt, not the first failure: a written-off document the repository keeps offering is still
     * being failed on, and stays listed; one the repository no longer lists expires.
     */
    @Test
    void onlyWrittenOffRowsWhoseLastAttemptIsOlderThanTheRetentionAreRemoved() {
        OffsetDateTime now = OffsetDateTime.now().truncatedTo(ChronoUnit.MICROS);
        CbomSyncSkip stale = skipWriter
                .recordAttempt("urn:uuid:stale", 1, "reason", CbomHeaderCounts.ZERO, now.minusDays(91), 1);
        CbomSyncSkip recent = skipWriter
                .recordAttempt("urn:uuid:recent", 1, "reason", CbomHeaderCounts.ZERO, now.minusDays(89), 1);
        CbomSyncSkip oldButRetrying = skipWriter
                .recordAttempt("urn:uuid:retrying", 1, "reason", CbomHeaderCounts.ZERO, now.minusDays(400), 5);
        CbomSyncSkip failedAgainToday = skipWriter
                .recordAttempt("urn:uuid:offered-again", 1, "reason", CbomHeaderCounts.ZERO, now.minusDays(400), 1);
        skipWriter.recordAttempt("urn:uuid:offered-again", 1, "reason again", CbomHeaderCounts.ZERO, now, 1);
        assertThat(stale.getState()).isEqualTo(CbomSyncSkipState.PERMANENTLY_SKIPPED);
        assertThat(oldButRetrying.getState()).isEqualTo(CbomSyncSkipState.RETRYING);

        CbomSyncSkipRetentionSweeper.SweepOutcome outcome = sweeper.sweep(90);

        assertThat(outcome.ran()).isTrue();
        assertThat(outcome.aborted()).isFalse();
        assertThat(outcome.deleted()).isEqualTo(1);
        assertThat(skipRepository.findAll())
                .extracting(CbomSyncSkip::getUuid)
                .containsExactlyInAnyOrder(recent.getUuid(), oldButRetrying.getUuid(), failedAgainToday.getUuid());
    }

    @Test
    void aBacklogLargerThanOneBatchIsRemovedBatchByBatch() {
        int rows = CbomSyncSkipRetentionSweeper.BATCH_SIZE * 2 + 3;
        OffsetDateTime stale = OffsetDateTime.now().minusDays(120);
        List<Object[]> values = new ArrayList<>();
        for (int i = 0; i < rows; i++) {
            values.add(new Object[]{UUID.randomUUID(), "urn:uuid:bulk-" + i, stale, stale});
        }
        jdbcTemplate
                .batchUpdate("INSERT INTO " + dbSchema + ".cbom_sync_skip (uuid, serial_number, version, reason, "
                        + "attempts, first_skipped_at, last_attempt_at, state, algorithms_count, certificates_count, "
                        + "protocols_count, crypto_material_count, total_assets_count) "
                        + "VALUES (?, ?, 1, 'reason', 4, ?, ?, 'PERMANENTLY_SKIPPED', 0, 0, 0, 0, 0)", values);
        assertThat(skipRepository.count()).isEqualTo(rows);

        CbomSyncSkipRetentionSweeper.SweepOutcome outcome = sweeper.sweep(90);

        assertThat(outcome.deleted()).isEqualTo(rows);
        assertThat(outcome.batches()).isEqualTo(3);
        assertThat(outcome.capped()).isFalse();
        assertThat(skipRepository.count()).isZero();
    }

    /**
     * The sweep picks its victims, then deletes them: in between, an operator's retry or a run's fresh failure can move
     * a row out of scope. The delete claims what it picked, so a row another transaction holds is skipped rather than
     * waited for and then deleted under the change -- which would swallow a retry the database had accepted.
     *
     * <p>
     * The sweep runs on its own thread with a deadline, because the regression this guards against does not fail the
     * statement: it blocks on the row lock until the other transaction commits.
     */
    @Test
    void aRowAConcurrentWriterHoldsIsSkippedRatherThanDeletedUnderIt() throws Exception {
        OffsetDateTime longAgo = OffsetDateTime.now().truncatedTo(ChronoUnit.MICROS).minusDays(200);
        CbomSyncSkip contended = skipWriter
                .recordAttempt("urn:uuid:contended", 1, "reason", CbomHeaderCounts.ZERO, longAgo, 1);
        skipWriter.recordAttempt("urn:uuid:free", 1, "reason", CbomHeaderCounts.ZERO, longAgo, 1);
        assertThat(contended.getState()).isEqualTo(CbomSyncSkipState.PERMANENTLY_SKIPPED);

        ExecutorService sweepThread = Executors.newSingleThreadExecutor();
        try (Connection retry = Objects.requireNonNull(jdbcTemplate.getDataSource()).getConnection()) {
            retry.setAutoCommit(false);
            try {
                try (PreparedStatement update = retry
                        .prepareStatement("UPDATE " + dbSchema + ".cbom_sync_skip"
                                + " SET state = 'RETRYING', attempts = 0 WHERE uuid = ?")) {
                    update.setObject(1, contended.getUuid());
                    assertThat(update.executeUpdate()).isEqualTo(1);
                }

                CbomSyncSkipRetentionSweeper.SweepOutcome outcome = sweepThread
                        .submit(() -> sweeper.sweep(90))
                        .get(30, TimeUnit.SECONDS);

                assertThat(outcome.aborted()).isFalse();
                assertThat(outcome.deleted()).isEqualTo(1);
            } finally {
                retry.commit();
            }
        } finally {
            sweepThread.shutdown();
        }

        assertThat(skipRepository.findAll())
                .extracting(CbomSyncSkip::getSerialNumber)
                .containsExactly("urn:uuid:contended");
        assertThat(skipRepository.findAll().getFirst().getState()).isEqualTo(CbomSyncSkipState.RETRYING);
    }
}
