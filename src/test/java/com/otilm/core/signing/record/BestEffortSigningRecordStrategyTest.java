package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static com.otilm.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.otilm.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Integration test for {@link BestEffortSigningRecordStrategy} over a real Postgres via {@link BaseSpringBootTest},
 * exercising the genuine async pipeline: {@link BestEffortSigningRecordStrategy#recordSigning} enqueues, and the real
 * background {@link SigningRecordBestEffortFlusher} thread drains the queue and persists a batch into
 * {@code signing_record} through the writer. The strategy's branch logic (policy gating, queue dispatch,
 * metrics, failure isolation, mapping field-fidelity over a captor) is pinned against mocks in
 * {@link BestEffortSigningRecordStrategyUnitTest}, and the queue's eviction/blocking/batching mechanics against
 * the real queue in BestEffortSigningRecordQueueTest. What only a real database can prove lives here: a queued
 * record survives the flusher's real transactional {@code saveAll} (including the {@code signing_profile}
 * foreign key) and reads back field-for-field — through the jsonb and {@code byte[]} columns a mocked repository
 * would only echo.
 */
class BestEffortSigningRecordStrategyTest extends BaseSpringBootTest {

    private static final Duration FLUSH_DEADLINE = Duration.ofSeconds(10);

    @Autowired
    private BestEffortSigningRecordStrategy strategy;
    @Autowired
    private SigningRecordRepository recordRepo;
    @Autowired
    private SigningProfileRepository profileRepo;
    @Autowired
    private SigningProfileVersionRepository profileVersionRepo;

    @Test
    void record_recordingEverything_roundTripsEveryFieldThroughPostgres() throws JsonProcessingException {
        // given
        SigningProfile persistedProfile = insertSigningProfile("round-trip-profile");
        insertProfileVersion(persistedProfile, 7);
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(persistedProfile.getUuid())
                .version(7)
                .recordPolicy(recordingEverything().build())
                .build();

        // when
        strategy.recordSigning(aSigningRecordInput()
                .signingProfile(recordingProfile)
                .displayName("round-trip-record")
                .signingTime(Instant.parse("2026-03-04T05:06:07Z"))
                .requestMetadataJson("{ \"alg\": \"ES256\" }")
                .signature("the-signature".getBytes(UTF_8))
                .signedDocument("the-signed-document".getBytes(UTF_8))
                .dtbs("the-data-to-be-signed".getBytes(UTF_8))
                .build());

        // then
        SigningRecord signingRecord = awaitSinglePersistedRecord();
        assertEquals("round-trip-record", signingRecord.getName());
        assertEquals(persistedProfile.getUuid(), signingRecord.getSigningProfileUuid());
        assertEquals(7, signingRecord.getSigningProfileVersion());
        assertEquals(Instant.parse("2026-03-04T05:06:07Z"), signingRecord.getSigningTime());
        assertSameJson("{ \"alg\": \"ES256\" }", signingRecord.getRequestMetadataJson()); // jsonb re-renders whitespace
        assertArrayEquals("the-signature".getBytes(UTF_8), signingRecord.getSignatureValue());
        assertArrayEquals("the-signed-document".getBytes(UTF_8), signingRecord.getSignedDocument());
        assertArrayEquals("the-data-to-be-signed".getBytes(UTF_8), signingRecord.getDtbs());
    }

    @Test
    void record_manyRecordableInputs_eventuallyPersistsThemAll() {
        // given
        var recordedCount = 5;
        SigningProfile persistedProfile = insertSigningProfile("batched-profile");
        insertProfileVersion(persistedProfile, 1);
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(persistedProfile.getUuid())
                .recordPolicy(recordingEverything().build())
                .build();

        // when
        for (int i = 0; i < recordedCount; i++) {
            strategy.recordSigning(aSigningRecordInput()
                    .signingProfile(recordingProfile)
                    .displayName("batched-record-" + i)
                    .build());
        }

        // then
        Awaitility.await().atMost(FLUSH_DEADLINE).until(() -> recordRepo.count() == recordedCount);
    }

    private SigningRecord awaitSinglePersistedRecord() {
        Awaitility.await().atMost(FLUSH_DEADLINE).until(() -> recordRepo.count() == 1);
        List<SigningRecord> persisted = recordRepo.findAll();
        return persisted.getFirst();
    }

    /**
     * Persists the {@code signing_profile} row a record's {@code signing_profile_uuid} foreign key must reference.
     * The profile's model fields are irrelevant to the strategy (it reads only uuid, version and record policy),
     * so this fills the NOT NULL columns with unremarkable values.
     */
    private SigningProfile insertSigningProfile(String name) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setSigningScheme(SigningScheme.DELEGATED);
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setLatestVersion(1);
        return profileRepo.saveAndFlush(profile);
    }

    /**
     * Persists the {@code signing_profile_version} row a record's {@code (signing_profile_uuid, signing_profile_version)}
     * foreign key must reference. The version's policy fields are irrelevant to the strategy (the record policy comes
     * from the in-memory model), so this fills only the NOT NULL columns.
     */
    private void insertProfileVersion(SigningProfile profile, int version) {
        SigningProfileVersion profileVersion = new SigningProfileVersion();
        profileVersion.setSigningProfile(profile);
        profileVersion.setVersion(version);
        profileVersion.setSigningScheme(SigningScheme.DELEGATED);
        profileVersion.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profileVersionRepo.saveAndFlush(profileVersion);
    }

    private void assertSameJson(String expected, String actual) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        assertEquals(mapper.readTree(expected), mapper.readTree(actual));
    }
}
