package com.czertainly.core.signing.record;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordDto;
import com.czertainly.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.SigningRecordService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static com.czertainly.core.model.signing.SigningProfileModelBuilder.aSigningProfile;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.notRecording;
import static com.czertainly.core.model.signing.SigningRecordPolicyModelBuilder.recordingEverything;
import static com.czertainly.core.signing.record.SigningRecordInputBuilder.aSigningRecordInput;
import static com.czertainly.core.util.SearchRequestDtoBuilder.aSearchRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Integration test for {@link ImmediateSigningRecordStrategy} over a real Postgres via {@link BaseSpringBootTest}.
 * The strategy's branch logic is pinned over mocks in {@link ImmediateSigningRecordStrategyUnitTest}; what only
 * a real database can prove lives here: a recorded input lands directly in {@code signing_record} and reads
 * back field-for-field through the jsonb and {@code byte[]} columns a mocked writer would only echo.
 */
class ImmediateSigningRecordStrategyTest extends BaseSpringBootTest {

    @Autowired
    private ImmediateSigningRecordStrategy strategy;

    @Autowired
    private SigningRecordService signingRecordService;

    @Autowired
    private SigningProfileRepository profileRepo;

    @Test
    void persistsAllRecordableContent_whenEveryToggleEnabled() throws NotFoundException, JsonProcessingException {
        // given
        SigningProfile persistedProfile = insertSigningProfile("immediate-profile");
        SigningProfileModel<?, ?> signingProfile = aSigningProfile()
                .uuid(persistedProfile.getUuid())
                .recordPolicy(recordingEverything().build())
                .build();
        SigningRecordInput input = aSigningRecordInput()
                .signingProfile(signingProfile)
                .requestMetadataJson("{ \"foo\": \"bar\" }")
                .signature("the-signature".getBytes(UTF_8))
                .signedDocument("the-signed-document".getBytes(UTF_8))
                .dtbs("the-data-to-be-signed".getBytes(UTF_8))
                .build();

        // when
        strategy.record(input);

        // then
        List<SigningRecordListDto> all = signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems();
        assertEquals(1, all.size());

        SigningRecordDto record = signingRecordService
                .getSigningRecord(SecuredUUID.fromString(all.getFirst().getUuid()));
        assertSameJson("{ \"foo\": \"bar\" }", record.getRequestMetadataJson()); // jsonb re-renders whitespace
        assertEquals("the-signature", new String(record.getSignatureValue(), UTF_8));
        assertEquals("the-signed-document", new String(record.getSignedDocument(), UTF_8));
        assertEquals("the-data-to-be-signed", new String(record.getDtbs(), UTF_8));
    }

    @Test
    void noToggleEnabledIsNoOp() {
        // given
        SigningProfileModel<?, ?> signingProfile = aSigningProfile()
                .recordPolicy(notRecording().build())
                .build();
        SigningRecordInput input = aSigningRecordInput().signingProfile(signingProfile).build();

        // when
        strategy.record(input);

        // then
        List<SigningRecordListDto> all = signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems();
        assertEquals(0, all.size());
    }

    /**
     * Persists the {@code signing_profile} row referenced by a record's {@code signing_profile_uuid}.
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
