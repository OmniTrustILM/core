package com.czertainly.core.service.writer.signingrecord;

import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.signing.record.SigningRecordBestEffortFlusher;
import com.czertainly.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static com.czertainly.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.czertainly.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Integration test for {@link BestEffortSigningRecordWriter} over a real Postgres via {@link BaseSpringBootTest},
 * exercising the genuine async pipeline: {@link BestEffortSigningRecordWriter#record} enqueues, and the real
 * background {@link SigningRecordBestEffortFlusher} thread drains the queue and persists a batch into
 * {@code signing_record}. The writer's branch logic (policy gating, queue dispatch, metrics, failure isolation,
 * mapping field-fidelity over a captor) is pinned against mocks in {@link BestEffortSigningRecordWriterUnitTest},
 * and the queue's eviction/blocking/batching mechanics against the real queue in
 * BestEffortSigningRecordQueueTest. What only a real database can prove lives here: a queued record
 * survives the flusher's real transactional {@code saveAll} (including the {@code signing_profile} foreign key)
 * and reads back field-for-field — through the jsonb and {@code byte[]} columns a mocked repository would only echo.
 */
class BestEffortSigningRecordWriterTest extends BaseSpringBootTest {

    private static final Duration FLUSH_DEADLINE = Duration.ofSeconds(10);

    @Autowired
    private BestEffortSigningRecordWriter writer;
    @Autowired
    private SigningRecordRepository recordRepo;
    @Autowired
    private SigningProfileRepository profileRepo;

    @Test
    void record_recordingEverything_roundTripsEveryFieldThroughPostgres() throws JsonProcessingException {
        // given
        SigningProfile persistedProfile = insertSigningProfile("round-trip-profile");
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(persistedProfile.getUuid())
                .version(7)
                .recordPolicy(recordingEverything().build())
                .build();

        // when
        writer.record(aSigningRecordInput()
                .signingProfile(recordingProfile)
                .displayName("round-trip-record")
                .signingTime(Instant.parse("2026-03-04T05:06:07Z"))
                .requestMetadataJson("{ \"alg\": \"ES256\" }")
                .signature("the-signature".getBytes(UTF_8))
                .signedDocument("the-signed-document".getBytes(UTF_8))
                .dtbs("the-data-to-be-signed".getBytes(UTF_8))
                .build());

        // then
        SigningRecord record = awaitSinglePersistedRecord();
        assertEquals("round-trip-record", record.getName());
        assertEquals(persistedProfile.getUuid(), record.getSigningProfileUuid());
        assertEquals(7, record.getSigningProfileVersion());
        assertEquals(Instant.parse("2026-03-04T05:06:07Z"), record.getSigningTime());
        assertSameJson("{ \"alg\": \"ES256\" }", record.getRequestMetadataJson()); // jsonb re-renders whitespace
        assertArrayEquals("the-signature".getBytes(UTF_8), record.getSignatureValue());
        assertArrayEquals("the-signed-document".getBytes(UTF_8), record.getSignedDocument());
        assertArrayEquals("the-data-to-be-signed".getBytes(UTF_8), record.getDtbs());
    }

    @Test
    void record_manyRecordableInputs_eventuallyPersistsThemAll() {
        // given
        var recordedCount = 5;
        SigningProfile persistedProfile = insertSigningProfile("batched-profile");
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(persistedProfile.getUuid())
                .recordPolicy(recordingEverything().build())
                .build();

        // when
        for (int i = 0; i < recordedCount; i++) {
            writer.record(aSigningRecordInput()
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
     * The profile's model fields are irrelevant to the writer (it reads only uuid, version and record policy),
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

    private void assertSameJson(String expected, String actual) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        assertEquals(mapper.readTree(expected), mapper.readTree(actual));
    }
}
