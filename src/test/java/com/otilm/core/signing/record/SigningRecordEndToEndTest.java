package com.otilm.core.signing.record;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.SigningRecordService;
import com.otilm.core.util.BaseSpringBootTest;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.util.List;

import static com.otilm.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.otilm.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static com.otilm.core.util.SearchRequestDtoBuilder.aSearchRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * End-to-end test of the signing-record persistence paths over a real Postgres, one per
 * {@link SigningRecordPersistenceMode}: a write goes through the {@link SigningRecordStrategyFactory}-selected
 * strategy and ends up as a {@code signing_record} row, by whichever route the mode dictates. Each strategy, the
 * outbox drainer and the best-effort flusher are pinned in isolation elsewhere
 * ({@code ImmediateSigningRecordStrategyTest}, {@code DeferredDurableSigningRecordStrategyTest},
 * {@code SigningRecordOutboxDrainerTest}, {@code BestEffortSigningRecordStrategyTest}); what these tests alone
 * prove is that the factory routes each mode to the right strategy, the mode's stages chain into one persisted
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
    private SigningRecordStrategyFactory factory;
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
    void deferredDurableProfile_stagesWriteInOutbox_thenDrainsIntoSigningRecord_advancingIntakeThenPersistCounters()
            throws NotFoundException {
        // given a profile whose persistence mode routes writes through the durable outbox
        var deferredDurable = SigningRecordPersistenceMode.DEFERRED_DURABLE;
        SigningProfileVersion version = insertSigningProfile(deferredDurable);
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(version.getSigningProfileUuid())
                .recordPolicy(recordingEverything().build())
                .build();
        double intakeBefore = counterValue("signing_record.intake", "mode", deferredDurable.name());
        double persistBefore = counterValue("signing_record.persist", "mode", deferredDurable.name());

        // when the record is written through the factory-selected writer
        factory.strategyFor(version).recordSigning(aSigningRecordInput().signingProfile(recordingProfile).build());

        // then it is accepted at intake and staged in the outbox, not yet persisted into signing_record
        assertRecordInOutbox();
        assertNoRecordExistsInFinalRecordTable();
        assertEquals(intakeBefore + 1, counterValue("signing_record.intake", "mode", deferredDurable.name()));

        // when the outbox is drained
        drainer.drainOnce();

        // then the staged record has moved into signing_record, is now selectable through the service, and the
        // stage-2 persist counter advanced by one
        assertEquals(0, outboxRepo.count());
        assertRecordExists();
        assertEquals(persistBefore + 1, counterValue("signing_record.persist", "mode", deferredDurable.name()));
    }

    @Test
    void immediateProfile_persistsWriteStraightIntoSigningRecord_withoutStaging_advancingPersistCounter()
            throws NotFoundException {
        // given a profile whose persistence mode persists writes synchronously
        var immediate = SigningRecordPersistenceMode.IMMEDIATE;
        SigningProfileVersion version = insertSigningProfile(immediate);
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(version.getSigningProfileUuid())
                .recordPolicy(recordingEverything().build())
                .build();
        double persistBefore = counterValue("signing_record.persist", "mode", immediate.name());

        // when the record is written through the factory-selected writer
        factory.strategyFor(version).recordSigning(aSigningRecordInput().signingProfile(recordingProfile).build());

        // then it is selectable through the service straight away, never staged in the outbox, and the counter advanced
        assertRecordExists();
        assertEquals(0, outboxRepo.count());
        assertEquals(persistBefore + 1, counterValue("signing_record.persist", "mode", immediate.name()));
    }

    @Test
    void bestEffortProfile_queuesWrite_thenBackgroundFlusherPersistsIt_advancingIntakeThenPersistCounter()
            throws NotFoundException {
        // given a profile whose persistence mode routes writes through the in-memory best-effort queue
        var bestEffort = SigningRecordPersistenceMode.BEST_EFFORT;
        SigningProfileVersion version = insertSigningProfile(bestEffort);
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(version.getSigningProfileUuid())
                .recordPolicy(recordingEverything().build())
                .build();
        double intakeBefore = counterValue("signing_record.intake", "mode", bestEffort.name());
        double persistBefore = counterValue("signing_record.persist", "mode", bestEffort.name());

        // when the record is written through the factory-selected writer
        factory.strategyFor(version).recordSigning(aSigningRecordInput().signingProfile(recordingProfile).build());

        // then it is admitted at intake straight away, before any persistence
        assertEquals(intakeBefore + 1, counterValue("signing_record.intake", "mode", bestEffort.name()));

        // and the background flusher eventually persists it, making it selectable through the service and
        // advancing the stage-2 persist counter
        Awaitility.await().atMost(FLUSH_DEADLINE).until(() -> recordRepo.count() == 1);
        assertRecordExists();
        assertEquals(persistBefore + 1, counterValue("signing_record.persist", "mode", bestEffort.name()));
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
        SigningRecordDto signingRecord = signingRecordService.getSigningRecord(SecuredUUID.fromString(recordUuid));
        assertEquals(recordUuid, signingRecord.getUuid());
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
