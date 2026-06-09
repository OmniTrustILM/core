package com.czertainly.core.signing.record;

import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.service.writer.signingrecord.SigningRecordWriter;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.util.UUID;

import static com.czertainly.core.signing.record.SigningRecordOutboxBuilder.aSigningRecordOutboxRow;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real-database behaviour of {@link SigningRecordOutboxDrainer}: the native {@code SKIP LOCKED} claim
 * query, batch-size limiting against a real {@code LIMIT}, real duplicate-key idempotency on crash
 * recovery, poison handling, and field fidelity of the outbox -> signing_record copy. The branch logic
 * (metrics, failure isolation, mixed batches) is covered over mocks in
 * {@link SigningRecordOutboxDrainerUnitTest}.
 *
 * <p>The periodic trigger ({@link SigningRecordOutboxDrainScheduler}) is left disabled here — the default
 * test profile keeps {@code scheduled-tasks.enabled=false} — so every test drives {@code drainOnce()}
 * explicitly and the intermediate row counts stay deterministic.
 */
@TestPropertySource(properties = {
        "signing-record.outbox.max-batch-size=2",
        "signing-record.outbox.poison-threshold=3"
})
class SigningRecordOutboxDrainerTest extends BaseSpringBootTest {

    private static final int MAX_BATCH_SIZE = 2;
    private static final int POISON_THRESHOLD = 3;

    @Autowired
    private SigningRecordOutboxDrainer drainer;
    @Autowired
    private SigningProfileRepository profileRepo;
    @Autowired
    private SigningProfileVersionRepository profileVersionRepo;
    @Autowired
    private SigningRecordOutboxRepository outboxRepo;
    @Autowired
    private SigningRecordRepository recordRepo;

    private SigningProfile signingProfile;
    private UUID signingProfileUuid;

    @BeforeEach
    void seedSigningProfile() {
        signingProfile = persistSigningProfile();
        signingProfileUuid = signingProfile.getUuid();
    }

    @Test
    void drainOnce_movesAFullBatchFromOutboxIntoTheSigningRecordTable() {
        // given
        persistOutboxRows(MAX_BATCH_SIZE);

        // when
        drainer.drainOnce();

        // then
        assertEquals(0, outboxRepo.count());
        assertEquals(MAX_BATCH_SIZE, recordRepo.count());
    }

    @Test
    void drainOnce_drainsAllDrainableRowsAcrossMultipleBatchesInOneRun() {
        // given more rows than a single batch
        var rowsExceedingOneBatch = MAX_BATCH_SIZE + 1;
        persistOutboxRows(rowsExceedingOneBatch);

        // when (the lock holder loops batches until the outbox is exhausted)
        drainer.drainOnce();

        // then the whole backlog is drained in one run
        assertEquals(0, outboxRepo.count());
        assertEquals(rowsExceedingOneBatch, recordRepo.count());
    }

    @Test
    void drainOnce_isIdempotent_whenSigningRecordAlreadyExistsFromAnEarlierCrash() {
        // given a row whose signing_record was written before the crash but never deleted from the outbox
        var row = persistOutboxRow(aSigningRecordOutboxRow());
        persistMatchingSigningRecord(row);

        // when
        drainer.drainOnce();

        // then the real duplicate-key insert is swallowed and the outbox row is still removed
        assertEquals(0, outboxRepo.count());
        assertEquals(1, recordRepo.count());
    }

    @Test
    void drainOnce_leavesPoisonRowInOutbox_andDoesNotCreateARecord() {
        // given
        var poisonRow = persistOutboxRow(aSigningRecordOutboxRow().withAttempts(POISON_THRESHOLD));

        // when
        drainer.drainOnce();

        // then
        assertTrue(outboxRepo.findById(poisonRow.getUuid()).isPresent());
        assertEquals(0, recordRepo.count());
    }

    /**
     * Per-row isolation: an unpersistable row (here a {@code signing_profile_uuid} with no matching
     * signing_profile, so its copy into {@code signing_record} violates the FK) has its attempt recorded in
     * its own transaction on every run and eventually crosses the poison threshold, instead of livelocking
     * the drainer. The fix is {@link SigningRecordWriter}: each row is copied with an immediate
     * {@code saveAndFlush} in its own transaction, so the failure surfaces synchronously and
     * {@code recordFailure} commits independently of the rolled-back copy.
     */
    @Test
    void drainOnce_escalatesAnUnpersistableRowToPoison_insteadOfRetryingItForever() {
        // given a row whose signing_profile_uuid has no matching signing_profile (e.g. the profile was
        // deleted); its copy into signing_record will violate the FK
        var wedged = persistOutboxRowReferencingMissingProfile(Instant.parse("2026-01-01T00:00:00Z"));

        // when the drainer runs more times than the poison threshold
        for (int run = 0; run < POISON_THRESHOLD + 2; run++) {
            drainer.drainOnce();
        }

        // then nothing is drained, the row is still in the outbox, and its attempts have advanced to (and
        // are capped at) the poison threshold -- it is now recognised as poison rather than retried forever
        assertEquals(0, recordRepo.count());
        assertTrue(outboxRepo.findById(wedged.getUuid()).isPresent());
        assertEquals(POISON_THRESHOLD, outboxRepo.findById(wedged.getUuid()).orElseThrow().getAttempts());
    }

    /**
     * The other face of per-row isolation: a healthy row sharing a claimed batch with an unpersistable one
     * is drained and committed on its own, because each row is copied in its own transaction rather than the
     * whole batch sharing one.
     */
    @Test
    void drainOnce_drainsAHealthyRow_whenItSharesABatchWithAnUnpersistableRow() {
        // given a healthy row batched with an unpersistable one; MAX_BATCH_SIZE == 2, so both are claimed
        var healthy = persistOutboxRow(aSigningRecordOutboxRow().withSigningTime(Instant.parse("2026-01-01T00:00:00Z")));
        var unpersistable = persistOutboxRowReferencingMissingProfile(Instant.parse("2026-01-02T00:00:00Z"));

        // when
        drainer.drainOnce();

        // then the healthy row is drained and removed, while only the unpersistable row remains in the outbox
        assertEquals(1, recordRepo.count());
        assertTrue(recordRepo.findById(healthy.getUuid()).isPresent());
        assertTrue(outboxRepo.findById(healthy.getUuid()).isEmpty());
        assertEquals(1, outboxRepo.count());
        assertTrue(outboxRepo.findById(unpersistable.getUuid()).isPresent());
    }

    @Test
    void drainOnce_drainsRowOneAttemptBelowThePoisonThreshold() {
        // given
        persistOutboxRow(aSigningRecordOutboxRow().withAttempts(POISON_THRESHOLD - 1));

        // when
        drainer.drainOnce();

        // then
        assertEquals(0, outboxRepo.count());
        assertEquals(1, recordRepo.count());
    }

    @Test
    void drainOnce_preservesAllRecordFieldsThroughTheOutbox() {
        // given
        var dtbs = new byte[]{7, 8, 9};
        var requestMetadata = "{\"correlationId\":\"req-99\"}";
        persistProfileVersion(signingProfile, 4);
        var row = persistOutboxRow(aSigningRecordOutboxRow()
                .withName("audit-record-2026")
                .withSigningProfileVersion(4)
                .withSignatureValue(new byte[]{1, 2, 3})
                .withSignedDocument(new byte[]{4, 5, 6})
                .withDtbs(dtbs)
                .withRequestMetadataJson(requestMetadata));

        // when
        drainer.drainOnce();

        // then
        SigningRecord persisted = recordRepo.findById(row.getUuid()).orElseThrow();
        assertEquals("audit-record-2026", persisted.getName());
        assertEquals(signingProfileUuid, persisted.getSigningProfileUuid());
        assertEquals(4, persisted.getSigningProfileVersion());
        assertEquals(row.getSigningTime(), persisted.getSigningTime());
        assertArrayEquals(new byte[]{1, 2, 3}, persisted.getSignatureValue());
        assertArrayEquals(new byte[]{4, 5, 6}, persisted.getSignedDocument());
        assertArrayEquals(dtbs, persisted.getDtbs());
        // jsonb may re-render whitespace, so compare the payload ignoring it
        assertEquals(requestMetadata.replaceAll("\\s", ""),
                persisted.getRequestMetadataJson().replaceAll("\\s", ""));
    }

    private SigningProfile persistSigningProfile() {
        SigningProfile profile = new SigningProfile();
        profile.setName("drainer-profile-" + System.nanoTime());
        profile.setSigningScheme(SigningScheme.MANAGED);
        profile.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        profile.setLatestVersion(1);
        profile = profileRepo.saveAndFlush(profile);
        persistProfileVersion(profile, 1);
        return profile;
    }

    /**
     * Persists the {@code signing_profile_version} row a record references by ({@code signing_profile_uuid},
     * {@code signing_profile_version}). The composite FK {@code fk_signing_record_profile_version} requires the
     * referenced version row to exist before any {@link SigningRecord} carrying that pair can be inserted.
     */
    private void persistProfileVersion(SigningProfile profile, int version) {
        SigningProfileVersion profileVersion = new SigningProfileVersion();
        profileVersion.setSigningProfile(profile);
        profileVersion.setVersion(version);
        profileVersion.setSigningScheme(SigningScheme.MANAGED);
        profileVersion.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        profileVersionRepo.saveAndFlush(profileVersion);
    }

    private void persistOutboxRows(int count) {
        for (int i = 0; i < count; i++) {
            persistOutboxRow(aSigningRecordOutboxRow());
        }
    }

    private SigningRecordOutbox persistOutboxRow(SigningRecordOutboxBuilder builder) {
        return outboxRepo.saveAndFlush(builder.withSigningProfileUuid(signingProfileUuid).build());
    }

    /**
     * Persists an outbox row pointing at a signing_profile that does not exist. The outbox table has no FK,
     * so this persists fine; it only fails when the drainer copies it into signing_record, which does carry
     * the FK to signing_profile.
     */
    private SigningRecordOutbox persistOutboxRowReferencingMissingProfile(Instant signingTime) {
        return outboxRepo.saveAndFlush(aSigningRecordOutboxRow()
                .withSigningProfileUuid(UUID.randomUUID())
                .withSigningTime(signingTime)
                .build());
    }


    private void persistMatchingSigningRecord(SigningRecordOutbox row) {
        SigningRecord signingRecord = new SigningRecord();
        signingRecord.setUuid(row.getUuid());
        signingRecord.setSigningProfileUuid(row.getSigningProfileUuid());
        signingRecord.setSigningProfileVersion(row.getSigningProfileVersion());
        signingRecord.setSigningTime(row.getSigningTime());
        recordRepo.saveAndFlush(signingRecord);
    }
}
