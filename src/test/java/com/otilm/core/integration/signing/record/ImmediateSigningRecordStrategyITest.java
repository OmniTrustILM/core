package com.otilm.core.integration.signing.record;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.SigningRecordExternalService;
import com.otilm.core.signing.record.ImmediateSigningRecordStrategy;
import com.otilm.core.signing.record.SigningRecordInput;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordInputSources;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.notRecording;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingDisabled;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.otilm.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static com.otilm.core.signing.record.SigningRecordInputSources.recordOne;
import static com.otilm.core.util.builders.SearchRequestDtoBuilder.aSearchRequest;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Integration test for {@link ImmediateSigningRecordStrategy} over a real Postgres via {@link BaseSpringBootTest}. The
 * strategy's branch logic is pinned over mocks in {@link ImmediateSigningRecordStrategyUnitTest}; what only a real
 * database can prove lives here: a recorded input lands directly in {@code signing_record} and reads back
 * field-for-field through the jsonb and {@code byte[]} columns a mocked writer would only echo.
 */
class ImmediateSigningRecordStrategyITest extends BaseSpringBootTest {

    @Autowired
    private ImmediateSigningRecordStrategy strategy;

    @Autowired
    private SigningRecordExternalService signingRecordService;

    @Autowired
    private SigningProfileRepository profileRepo;

    @Autowired
    private SigningProfileVersionRepository versionRepo;

    @Autowired
    private SigningRecordRepository recordRepo;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Test
    void persistsAllRecordableContent_whenEveryToggleEnabled() throws NotFoundException, JsonProcessingException {
        // given
        SigningProfile persistedProfile = insertSigningProfile("immediate-profile");
        SigningProfileModel<?, ?> signingProfile = aSigningProfile()
                .withUuid(persistedProfile.getUuid())
                .withRecordPolicy(recordingEverything().build())
                .build();
        SigningRecordInput input = aSigningRecordInput()
                .signingProfile(signingProfile)
                .requestMetadataJson("{ \"foo\": \"bar\" }")
                .signature("the-signature".getBytes(UTF_8))
                .signedDocument("the-signed-document".getBytes(UTF_8))
                .dtbs("the-data-to-be-signed".getBytes(UTF_8))
                .build();

        // when
        recordOne(strategy, input);

        // then
        List<SigningRecordListDto> all = signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems();
        assertEquals(1, all.size());

        SigningRecordDto signingRecord = signingRecordService
                .getSigningRecord(SecuredUUID.fromString(all.getFirst().getUuid()));
        assertSameJson("{ \"foo\": \"bar\" }", signingRecord.getRequestMetadataJson()); // jsonb re-renders whitespace
        assertEquals("the-signature", new String(signingRecord.getSignatureValue(), UTF_8));
        assertEquals("the-signed-document", new String(signingRecord.getSignedDocument(), UTF_8));
        assertEquals("the-data-to-be-signed", new String(signingRecord.getDtbs(), UTF_8));
    }

    @Test
    void recordingDisabledIsNoOp() {
        // given
        SigningProfileModel<?, ?> signingProfile = aSigningProfile()
                .withRecordPolicy(recordingDisabled().build())
                .build();
        SigningRecordInput input = aSigningRecordInput().signingProfile(signingProfile).build();

        // when
        recordOne(strategy, input);

        // then
        List<SigningRecordListDto> all = signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems();
        assertEquals(0, all.size());
    }

    @Test
    void recordsMetadataOnly_whenRecordingEnabledButNoContentSelected() throws NotFoundException {
        // given
        SigningProfile persistedProfile = insertSigningProfile("metadata-only-profile");
        SigningProfileModel<?, ?> signingProfile = aSigningProfile()
                .withUuid(persistedProfile.getUuid())
                .withRecordPolicy(notRecording().build())
                .build();
        SigningRecordInput input = aSigningRecordInput().signingProfile(signingProfile).build();

        // when
        recordOne(strategy, input);

        // then
        List<SigningRecordListDto> all = signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems();
        assertEquals(1, all.size());

        SigningRecordDto signingRecord = signingRecordService
                .getSigningRecord(SecuredUUID.fromString(all.getFirst().getUuid()));
        assertNotNull(signingRecord.getSigningTime());
        assertEquals("alice", signingRecord.getRequestedBy().getName());
        assertNull(signingRecord.getRequestMetadataJson());
        assertNull(signingRecord.getSignatureValue());
        assertNull(signingRecord.getSignedDocument());
        assertNull(signingRecord.getDtbs());
    }

    @Test
    void insertsEveryRecordUnderItsReference_whenRecordingABatch() {
        // given
        SigningProfileModel<?, ?> recordingProfile = persistRecordingProfile("immediate-batch-profile");
        List<SigningRecordInputSource> batch = List
                .of(recordableSource(recordingProfile), recordableSource(recordingProfile),
                        recordableSource(recordingProfile));

        // when
        List<UUID> references = strategy.record(recordingProfile, batch);

        // then
        assertThat(recordRepo.findAll())
                .extracting(SigningRecord::getUuid)
                .containsExactlyInAnyOrderElementsOf(references);
    }

    @Test
    void insertsNothing_whenOneRecordOfTheBatchViolatesAConstraint() {
        // given
        SigningProfileModel<?, ?> recordingProfile = persistRecordingProfile("immediate-violation-profile");
        List<SigningRecordInputSource> batch = List
                .of(recordableSource(recordingProfile), recordableSource(recordingProfile),
                        sourceWithoutSigningTime(recordingProfile));

        // when
        ThrowingCallable recordBatch = () -> strategy.record(recordingProfile, batch);

        // then
        assertThatThrownBy(recordBatch).isInstanceOf(RuntimeException.class);
        assertThat(recordRepo.count()).isZero();
    }

    @Test
    void raisesTheViolationBeforeTheCallerCommits_whenRecordingABatchInsideTheCallersTransaction() {
        // given
        SigningProfileModel<?, ?> recordingProfile = persistRecordingProfile("immediate-caller-tx-profile");
        List<SigningRecordInputSource> batch = List
                .of(recordableSource(recordingProfile), sourceWithoutSigningTime(recordingProfile));

        // when
        Throwable raisedByTheBatch = new TransactionTemplate(transactionManager).execute(callersTransaction -> {
            callersTransaction.setRollbackOnly();
            return catchThrowable(() -> strategy.record(recordingProfile, batch));
        });

        // then
        assertThat(raisedByTheBatch).isNotNull();
    }

    /**
     * Persists the {@code signing_profile} row referenced by a record's {@code signing_profile_uuid}. The profile's
     * model fields are irrelevant to the strategy (it reads only uuid, version and record policy), so this fills the
     * NOT NULL columns with unremarkable values.
     */
    private SigningProfile insertSigningProfile(String name) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setSigningScheme(SigningScheme.DELEGATED);
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setLatestVersion(1);
        profile = profileRepo.saveAndFlush(profile);

        SigningProfileVersion version = new SigningProfileVersion();
        version.setSigningProfile(profile);
        version.setVersion(1);
        version.setSigningScheme(SigningScheme.DELEGATED);
        version.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        versionRepo.saveAndFlush(version);

        return profile;
    }

    private SigningProfileModel<?, ?> persistRecordingProfile(String name) {
        SigningProfile persistedProfile = insertSigningProfile(name);
        return aSigningProfile()
                .withUuid(persistedProfile.getUuid())
                .withRecordPolicy(recordingEverything().build())
                .build();
    }

    private static SigningRecordInputSource recordableSource(SigningProfileModel<?, ?> signingProfile) {
        return SigningRecordInputSources.of(aSigningRecordInput().signingProfile(signingProfile).build());
    }

    private static SigningRecordInputSource sourceWithoutSigningTime(SigningProfileModel<?, ?> signingProfile) {
        Instant missingSigningTime = null;
        return SigningRecordInputSources
                .of(aSigningRecordInput().signingProfile(signingProfile).signingTime(missingSigningTime).build());
    }

    private void assertSameJson(String expected, String actual) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        assertEquals(mapper.readTree(expected), mapper.readTree(actual));
    }
}
