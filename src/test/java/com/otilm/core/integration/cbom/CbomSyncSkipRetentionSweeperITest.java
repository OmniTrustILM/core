package com.otilm.core.integration.cbom;

import com.otilm.api.model.core.cbom.CbomSyncSkipState;
import com.otilm.core.cbom.sync.CbomSyncSkipRetentionSweeper;
import com.otilm.core.dao.entity.cbom.CbomSyncSkip;
import com.otilm.core.dao.repository.cbom.CbomSyncSkipRepository;
import com.otilm.core.model.cbom.CbomHeaderCounts;
import com.otilm.core.service.writer.cbom.CbomSyncSkipWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
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
}
