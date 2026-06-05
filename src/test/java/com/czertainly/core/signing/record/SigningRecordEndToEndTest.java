package com.czertainly.core.signing.record;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.entity.signing.SigningRecordOutbox;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.SigningRecordService;
import com.czertainly.core.util.BaseSpringBootTest;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.util.List;

import static com.czertainly.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.czertainly.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static com.czertainly.core.util.SearchRequestDtoBuilder.aSearchRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * End-to-end test of the signing-record persistence paths over a real Postgres, one per
 * {@link SigningRecordPersistenceMode}: a write goes through the {@link SigningRecordWriterFactory}-selected
 * writer and ends up as a {@code signing_record} row, by whichever route the mode dictates. Each writer, the
 * outbox drainer and the best-effort flusher are pinned in isolation elsewhere
 * ({@code ImmediateSigningRecordWriterTest}, {@code OutboxSigningRecordWriterTest},
 * {@code SigningRecordOutboxDrainerTest}, {@code BestEffortSigningRecordWriterTest}); what these tests alone
 * prove is that the factory routes each mode to the right writer, the mode's stages chain into one persisted
 * record, and the mode's lifecycle counters advance:
 *
 * <ul>
 *     <li>{@code IMMEDIATE} — persisted synchronously, never staged.</li>
 *     <li>{@code DEFERRED_DURABLE} — staged in {@code signing_record_outbox}, then moved by the
 *         {@link SigningRecordOutboxDrainer}.</li>
 *     <li>{@code BEST_EFFORT} — queued in memory, then persisted by the background
 *         {@link SigningRecordBestEffortFlusher} thread.</li>
 * </ul>
 */
class SigningRecordEndToEndTest extends BaseSpringBootTest {

    private static final Duration FLUSH_DEADLINE = Duration.ofSeconds(10);

    @Autowired
    private SigningRecordWriterFactory factory;
    @Autowired
    private SigningRecordOutboxDrainer drainer;
    @Autowired
    private SigningProfileRepository profileRepo;
    @Autowired
    private SigningProfileVersionRepository versionRepo;
    @Autowired
    private SigningRecordOutboxRepository outboxRepo;
    @Autowired
    private SigningRecordRepository recordRepo;
    @Autowired
    private MeterRegistry registry;
    @Autowired
    private SigningRecordService signingRecordService;

    @Test
    void deferredDurableProfile_stagesWriteInOutbox_thenDrainsIntoSigningRecord_advancingBothCounters()
            throws NotFoundException {
        // given a profile whose persistence mode routes writes through the durable outbox
        var deferredDurable = SigningRecordPersistenceMode.DEFERRED_DURABLE;
        SigningProfileVersion version = insertSigningProfile(deferredDurable);
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(version.getSigningProfileUuid())
                .recordPolicy(recordingEverything().build())
                .build();
        double createdBefore = counterValue("signing_record.created.total", "mode", deferredDurable.name());
        double drainedBefore = counterValue("signing_record.outbox.drained.total");

        // when the record is written through the factory-selected writer
        factory.writerFor(version).record(aSigningRecordInput().signingProfile(recordingProfile).build());

        // then it is staged in the outbox for that profile, not yet visible through the service
        assertRecordInOutbox();
        assertNoRecordExistsInFinalRecordTable();

        // when the outbox is drained
        drainer.drainOnce();

        // then the staged record has moved into signing_record, is now selectable through the service, and
        // both lifecycle counters advanced by one
        assertEquals(0, outboxRepo.count());
        assertRecordExists();
        assertEquals(createdBefore + 1, counterValue("signing_record.created.total", "mode", deferredDurable.name()));
        assertEquals(drainedBefore + 1, counterValue("signing_record.outbox.drained.total"));
    }

    @Test
    void immediateProfile_persistsWriteStraightIntoSigningRecord_withoutStaging_advancingCreatedCounter()
            throws NotFoundException {
        // given a profile whose persistence mode persists writes synchronously
        var immediate = SigningRecordPersistenceMode.IMMEDIATE;
        SigningProfileVersion version = insertSigningProfile(immediate);
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(version.getSigningProfileUuid())
                .recordPolicy(recordingEverything().build())
                .build();
        double createdBefore = counterValue("signing_record.created.total", "mode", immediate.name());

        // when the record is written through the factory-selected writer
        factory.writerFor(version).record(aSigningRecordInput().signingProfile(recordingProfile).build());

        // then it is selectable through the service straight away, never staged in the outbox, and the counter advanced
        assertRecordExists();
        assertEquals(0, outboxRepo.count());
        assertEquals(createdBefore + 1, counterValue("signing_record.created.total", "mode", immediate.name()));
    }

    @Test
    void bestEffortProfile_queuesWrite_thenBackgroundFlusherPersistsIt_advancingQueuedThenCreatedCounter()
            throws NotFoundException {
        // given a profile whose persistence mode routes writes through the in-memory best-effort queue
        var bestEffort = SigningRecordPersistenceMode.BEST_EFFORT;
        SigningProfileVersion version = insertSigningProfile(bestEffort);
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(version.getSigningProfileUuid())
                .recordPolicy(recordingEverything().build())
                .build();
        double queuedBefore = counterValue("signing_record.queued.total", "mode", bestEffort.name());
        double createdBefore = counterValue("signing_record.created.total", "mode", bestEffort.name());

        // when the record is written through the factory-selected writer
        factory.writerFor(version).record(aSigningRecordInput().signingProfile(recordingProfile).build());

        // then it is admitted to the queue straight away, before any persistence
        assertEquals(queuedBefore + 1, counterValue("signing_record.queued.total", "mode", bestEffort.name()));

        // and the background flusher eventually persists it, making it selectable through the service and
        // advancing the created counter
        Awaitility.await().atMost(FLUSH_DEADLINE).until(() -> recordRepo.count() == 1);
        assertRecordExists();
        assertEquals(createdBefore + 1, counterValue("signing_record.created.total", "mode", bestEffort.name()));
    }

    /**
     * Asserts that exactly one signing record is reachable through {@link SigningRecordService}, both in the
     * list and when fetched by its own uuid — proving the persisted row is visible through the read path
     * operators use, not just present in the table. With the database isolated per test, that single record is
     * the one this test wrote.
     */
    private void assertRecordExists() throws NotFoundException {
        List<SigningRecordListDto> listed = signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems();
        assertEquals(1, listed.size());
        String recordUuid = listed.getFirst().getUuid();
        SigningRecordDto record = signingRecordService.getSigningRecord(SecuredUUID.fromString(recordUuid));
        assertEquals(recordUuid, record.getUuid());
    }

    private void assertNoRecordExistsInFinalRecordTable() {
        assertEquals(0, signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems().size());
    }

    private void assertRecordInOutbox() {
        List<SigningRecordOutbox> staged = outboxRepo.findAll();
        assertEquals(1, staged.size());
    }

    private double counterValue(String name, String... tags) {
        Counter counter = registry.find(name).tags(tags).counter();
        return counter == null ? 0.0 : counter.count();
    }

    /**
     * Persists the {@code signing_profile} the drained record's FK points at, plus its version-1 row carrying
     * the persistence mode (now a versioned field). Only the persistence mode drives this test (it selects the
     * writer), so the scheme and workflow columns get unremarkable valid values. Returns the version, which the
     * factory now routes on.
     */
    private SigningProfileVersion insertSigningProfile(SigningRecordPersistenceMode persistenceMode) {
        SigningProfile profile = new SigningProfile();
        profile.setName("e2e-" + persistenceMode.name());
        profile.setSigningScheme(SigningScheme.MANAGED);
        profile.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        profile.setLatestVersion(1);
        profile = profileRepo.saveAndFlush(profile);

        SigningProfileVersion version = new SigningProfileVersion();
        version.setSigningProfile(profile);
        version.setVersion(1);
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        version.setPersistenceMode(persistenceMode);
        return versionRepo.saveAndFlush(version);
    }
}
