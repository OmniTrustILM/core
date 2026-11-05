package com.otilm.core.integration.discovery;

import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.DiscoveryWork;
import com.otilm.core.dao.repository.DiscoveryWorkRepository;
import com.otilm.core.messaging.jms.listeners.discovery.DiscoveryWorkClaimer;
import com.otilm.core.messaging.model.DiscoveryWorkMessage;
import com.otilm.core.model.discovery.DiscoveryWorkType;
import com.otilm.core.service.writer.discovery.DiscoveryWorkLease;
import com.otilm.core.service.writer.discovery.DiscoveryWorkTick;
import com.otilm.core.service.writer.discovery.DiscoveryWorkWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.DiscoveryRunSeeder;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The lease a tick holds on its agenda row, against the real PostgreSQL container: which messages are admitted, and
 * which writes a tick's token still allows. Not {@code @Transactional}: the claimer and the lease commit their own
 * transactions, so seeded data must be committed too.
 */
class DiscoveryWorkLeaseITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryWorkLease lease;
    @Autowired
    private DiscoveryWorkClaimer claimer;
    @Autowired
    private DiscoveryWorkWriter workWriter;
    @Autowired
    private DiscoveryWorkRepository workRepository;
    @Autowired
    private DiscoveryRunSeeder runSeeder;
    @Autowired
    private DataSource testDataSource;

    @Test
    void refusesATick_whenAReclaimReplacedItsToken() {
        // given
        UUID runUuid = seedDueDrainRow();
        DiscoveryWorkMessage firstClaim = claimOne();
        expireLease(runUuid, DiscoveryWorkType.DRAIN);
        DiscoveryWorkMessage reclaim = claimOne();

        // when
        Optional<DiscoveryWorkTick> admitted = lease.admit(firstClaim);

        // then
        assertThat(admitted).isEmpty();
        assertThat(lease.admit(reclaim)).as("the newer claim still holds the row").isPresent();
    }

    @Test
    void refusesASecondCopyOfAMessage_whenTheFirstCopyWasAdmitted() {
        // given
        seedDueDrainRow();
        DiscoveryWorkMessage deliveredTwice = claimOne();
        lease.admit(deliveredTwice).orElseThrow();

        // when
        Optional<DiscoveryWorkTick> secondCopy = lease.admit(deliveredTwice);

        // then
        assertThat(secondCopy).isEmpty();
    }

    @Test
    void refusesATokenlessTick_whenTheRowHoldsALiveLease() {
        // given
        UUID runUuid = seedDueDrainRow();
        claimOne();
        var fromAnOlderCore = new DiscoveryWorkMessage(runUuid, DiscoveryWorkType.DRAIN, 0, null);

        // when
        Optional<DiscoveryWorkTick> admitted = lease.admit(fromAnOlderCore);

        // then
        assertThat(admitted).isEmpty();
    }

    @Test
    void admitsATokenlessTickUnderANewToken_whenTheRowIsUnleased() {
        // given
        UUID runUuid = seedDueDrainRow();
        var fromAnOlderCore = new DiscoveryWorkMessage(runUuid, DiscoveryWorkType.DRAIN, 0, null);

        // when
        Optional<DiscoveryWorkTick> admitted = lease.admit(fromAnOlderCore);

        // then
        assertThat(admitted).isPresent();
        assertThat(admitted.get().token()).isNotNull().isEqualTo(readDrainRow(runUuid).getLeaseToken());
    }

    @Test
    void changesNothing_whenATickWhoseTokenWasReplacedReschedules() {
        // given
        UUID runUuid = seedDueDrainRow();
        DiscoveryWorkTick outlivedTick = lease.admit(claimOne()).orElseThrow();
        expireLease(runUuid, DiscoveryWorkType.DRAIN);
        DiscoveryWorkMessage reclaim = claimOne();
        DiscoveryWork afterReclaim = readDrainRow(runUuid);

        // when
        outlivedTick.reschedule(42, OffsetDateTime.now(ZoneOffset.UTC).plusDays(1));

        // then
        DiscoveryWork row = readDrainRow(runUuid);
        assertThat(row.getLeaseToken()).isEqualTo(reclaim.leaseToken());
        assertThat(row.getAttempt()).isEqualTo(afterReclaim.getAttempt());
        assertThat(row.getNextDueAt().toInstant()).isEqualTo(afterReclaim.getNextDueAt().toInstant());
    }

    @Test
    void clearsTheLease_whenATickReschedules() {
        // given
        UUID runUuid = seedDueDrainRow();
        DiscoveryWorkTick tick = lease.admit(claimOne()).orElseThrow();
        var nextAttempt = 2;
        var nextDueAt = OffsetDateTime.now(ZoneOffset.UTC).plusSeconds(5).truncatedTo(ChronoUnit.MICROS);

        // when
        tick.reschedule(nextAttempt, nextDueAt);

        // then
        DiscoveryWork row = readDrainRow(runUuid);
        assertThat(row.getLeaseToken()).isNull();
        assertThat(row.getLeaseExpiresAt()).isNull();
        assertThat(row.getAttempt()).isEqualTo(nextAttempt);
        assertThat(row.getNextDueAt().toInstant()).isEqualTo(nextDueAt.toInstant());
    }

    @Test
    void extendsTheLease_whenATickRenews() {
        // given
        UUID runUuid = seedDueDrainRow();
        DiscoveryWorkTick tick = lease.admit(claimOne()).orElseThrow();
        var almostOver = OffsetDateTime.now(ZoneOffset.UTC).plusSeconds(5);
        setLeaseExpiry(runUuid, DiscoveryWorkType.DRAIN, almostOver);

        // when
        tick.renew();

        // then
        assertThat(readDrainRow(runUuid).getLeaseExpiresAt()).isAfter(almostOver.plusMinutes(1));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** A committed v2 run with one DRAIN row, already due. */
    private UUID seedDueDrainRow() {
        UUID runUuid = runSeeder.seedV2Run(DiscoveryStatus.IN_PROGRESS).getUuid();
        workWriter.schedule(runUuid, DiscoveryWorkType.DRAIN, OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(1));
        return runUuid;
    }

    private DiscoveryWorkMessage claimOne() {
        List<DiscoveryWorkMessage> claimed = claimer.claimDueBatch(10, OffsetDateTime.now(ZoneOffset.UTC));
        assertThat(claimed).hasSize(1);
        return claimed.get(0);
    }

    private DiscoveryWork readDrainRow(UUID runUuid) {
        return workRepository
                .findAll()
                .stream()
                .filter(row -> row.getDiscoveryUuid().equals(runUuid) && row.getWorkType() == DiscoveryWorkType.DRAIN)
                .findFirst()
                .orElseThrow();
    }

    /** Stands in for the lease running out while its tick stalled: the row's due time is already past. */
    private void expireLease(UUID runUuid, DiscoveryWorkType workType) {
        OffsetDateTime past = OffsetDateTime.now(ZoneOffset.UTC).minusSeconds(1);
        new JdbcTemplate(testDataSource)
                .update("UPDATE " + dbSchema + ".discovery_work SET lease_expires_at = ?, next_due_at = ? "
                        + "WHERE discovery_uuid = ? AND work_type = ?", past, past, runUuid, workType.name());
    }

    private void setLeaseExpiry(UUID runUuid, DiscoveryWorkType workType, OffsetDateTime expiresAt) {
        new JdbcTemplate(testDataSource)
                .update("UPDATE " + dbSchema + ".discovery_work SET lease_expires_at = ? "
                        + "WHERE discovery_uuid = ? AND work_type = ?", expiresAt, runUuid, workType.name());
    }
}
