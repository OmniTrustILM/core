package com.otilm.core.signing.record;

import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningRecordOutbox;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningRecordOutboxRepository;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.List;

import static com.otilm.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.notRecording;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingDisabled;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.otilm.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Integration test for {@link DeferredDurableSigningRecordStrategy} over a real Postgres via
 * {@link BaseSpringBootTest}. The strategy's branch logic (policy gating, metrics, failure counting,
 * propagation) is pinned over mocks in {@link DeferredDurableSigningRecordStrategyUnitTest}; what only a real
 * database can prove lives here: a recorded input lands as a row in {@code signing_record_outbox} (the staging
 * table the {@link SigningRecordOutboxDrainer} later moves) and <em>not</em> in {@code signing_record}, reads
 * back field-for-field through the jsonb and {@code byte[]} columns a mocked writer would only echo, and a
 * constraint violation propagates to the caller leaving nothing staged.
 */
class DeferredDurableSigningRecordStrategyTest extends BaseSpringBootTest {

    @Autowired
    private DeferredDurableSigningRecordStrategy strategy;
    @Autowired
    private SigningProfileRepository profileRepo;
    @Autowired
    private SigningRecordOutboxRepository outboxRepo;
    @Autowired
    private SigningRecordRepository recordRepo;

    @Test
    void record_recordingEverything_stagesRowInOutboxOnly_andRoundTripsEveryField() throws JsonProcessingException {
        // given
        SigningProfile persistedProfile = insertSigningProfile("round-trip-profile");
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

        // then the row is staged into the outbox, never directly into signing_record
        assertEquals(0, recordRepo.count());
        SigningRecordOutbox staged = singleStagedRow();
        assertEquals("round-trip-record", staged.getName());
        assertEquals(persistedProfile.getUuid(), staged.getSigningProfileUuid());
        assertEquals(7, staged.getSigningProfileVersion());
        assertEquals(Instant.parse("2026-03-04T05:06:07Z"), staged.getSigningTime());
        assertSameJson("{ \"alg\": \"ES256\" }", staged.getRequestMetadataJson()); // jsonb re-renders whitespace
        assertArrayEquals("the-signature".getBytes(UTF_8), staged.getSignatureValue());
        assertArrayEquals("the-signed-document".getBytes(UTF_8), staged.getSignedDocument());
        assertArrayEquals("the-data-to-be-signed".getBytes(UTF_8), staged.getDtbs());
        assertEquals(0, staged.getAttempts());
    }

    @Test
    void record_recordingDisabled_stagesNothing() {
        // given
        SigningProfileModel<?, ?> recordingDisabledProfile = aSigningProfile()
                .recordPolicy(recordingDisabled().build())
                .build();

        // when
        strategy.recordSigning(aSigningRecordInput().signingProfile(recordingDisabledProfile).build());

        // then
        assertEquals(0, outboxRepo.count());
        assertEquals(0, recordRepo.count());
    }

    @Test
    void record_stagesMetadataOnlyOutboxRow_whenRecordingEnabledButNoContentSelected() {
        // given
        SigningProfileModel<?, ?> metadataOnlyProfile = aSigningProfile()
                .recordPolicy(notRecording().build())
                .build();

        // when
        strategy.recordSigning(aSigningRecordInput()
                .signingProfile(metadataOnlyProfile)
                .displayName("metadata-only-record")
                .build());

        // then the row is staged with intrinsic metadata only; the optional content columns stay null
        assertEquals(0, recordRepo.count());
        SigningRecordOutbox staged = singleStagedRow();
        assertEquals("metadata-only-record", staged.getName());
        assertEquals(metadataOnlyProfile.uuid(), staged.getSigningProfileUuid());
        assertNotNull(staged.getSigningTime());
        assertEquals("alice", staged.getRequestedByUsername());
        assertNull(staged.getRequestMetadataJson());
        assertNull(staged.getSignatureValue());
        assertNull(staged.getSignedDocument());
        assertNull(staged.getDtbs());
    }

    @Test
    void record_propagatesConstraintViolation_andStagesNothing() {
        // given a recordable input whose NOT NULL signing_time is missing — the insert fails at commit
        SigningProfile persistedProfile = insertSigningProfile("violation-profile");
        Instant missingSigningTime = null;
        SigningProfileModel<?, ?> recordingProfile = aSigningProfile()
                .uuid(persistedProfile.getUuid())
                .recordPolicy(recordingEverything().build())
                .build();

        // when
        Executable signingRecord = () -> strategy.recordSigning(aSigningRecordInput()
                .signingProfile(recordingProfile)
                .signingTime(missingSigningTime)
                .build());

        // then the violation surfaces to the caller and the outbox stays empty
        assertThrows(Exception.class, signingRecord);
        assertEquals(0, outboxRepo.count());
        assertEquals(0, recordRepo.count());
    }

    private SigningRecordOutbox singleStagedRow() {
        List<SigningRecordOutbox> staged = outboxRepo.findAll();
        assertEquals(1, staged.size());
        return staged.getFirst();
    }

    /**
     * Persists the {@code signing_profile} row referenced by a staged record's {@code signing_profile_uuid}.
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

    private void assertSameJson(String expected, String actual) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        assertEquals(mapper.readTree(expected), mapper.readTree(actual));
    }
}
