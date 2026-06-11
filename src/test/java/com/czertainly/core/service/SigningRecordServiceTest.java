package com.czertainly.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.entity.signing.SigningRecord;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.SigningRecordRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.builders.SearchRequestDtoBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningRecordServiceTest extends BaseSpringBootTest {

    private static final String ALPHA_PROFILE = "alpha-profile";
    private static final String BETA_PROFILE = "beta-profile";
    private static final int VERSION_1 = 1;
    private static final int VERSION_2 = 2;
    private static final String ALPHA_RECORD_V1 = "alpha-record-v1";
    private static final String ALPHA_RECORD_V2 = "alpha-record-v2";
    private static final String BETA_RECORD_V1 = "beta-record-v1";

    @Autowired
    private SigningRecordService signingRecordService;
    @Autowired
    private SigningRecordRepository signingRecordRepository;
    @Autowired
    private SigningProfileRepository signingProfileRepository;
    @Autowired
    private SigningProfileVersionRepository signingProfileVersionRepository;

    private SigningProfile alphaProfile;
    private SigningProfile betaProfile;
    private SigningRecord alphaRecordV1;

    /**
     * Two profiles with three signing-profile versions between them, and one record per version:
     * alpha-profile has versions 1 and 2 (records {@value ALPHA_RECORD_V1}, {@value ALPHA_RECORD_V2}),
     * beta-profile has version 1 (record {@value BETA_RECORD_V1}). This lets the list/filter/existence
     * assertions span multiple names, profiles, and versions.
     */
    @BeforeEach
    void seedRecordsAcrossProfilesAndVersions() {
        alphaProfile = insertProfile(ALPHA_PROFILE);
        insertProfileVersion(alphaProfile, VERSION_1);
        insertProfileVersion(alphaProfile, VERSION_2);
        betaProfile = insertProfile(BETA_PROFILE);
        insertProfileVersion(betaProfile, VERSION_1);

        alphaRecordV1 = aRecord(alphaProfile, VERSION_1)
                .withName(ALPHA_RECORD_V1)
                .withSignatureValue("alpha-v1-signature".getBytes())
                .withDtbs("alpha-v1-dtbs".getBytes())
                .withSignedDocument("alpha-v1-signed-document".getBytes())
                .withRequestMetadataJson("{\"alg\":\"SHA256\"}")
                .withRequestedByUuid(UUID.fromString("99999999-9999-9999-9999-999999999999"))
                .withRequestedByUsername("alice")
                .withSignedDocumentRetrievedAt(Instant.now().truncatedTo(ChronoUnit.MILLIS))
                .insert();
        aRecord(alphaProfile, VERSION_2).withName(ALPHA_RECORD_V2).insert();
        aRecord(betaProfile, VERSION_1).withName(BETA_RECORD_V1).insert();
    }

    // ──────────────────────────────────────────────────────────────────────────
    // getSearchableFieldInformation
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void getSearchableFieldInformation_exposesSigningRecordPropertyFields() {
        // when
        List<SearchFieldDataByGroupDto> groups = signingRecordService.getSearchableFieldInformation();

        // then
        List<String> identifiers = groups.stream()
                .flatMap(g -> g.getSearchFieldData().stream())
                .map(SearchFieldDataDto::getFieldIdentifier)
                .toList();
        assertTrue(identifiers.contains(FilterField.SIGNING_RECORD_NAME.name()));
        assertTrue(identifiers.contains(FilterField.SIGNING_RECORD_SIGNING_PROFILE.name()));
        assertTrue(identifiers.contains(FilterField.SIGNING_RECORD_SIGNING_PROFILE_VERSION.name()));
        assertTrue(identifiers.contains(FilterField.SIGNING_RECORD_SIGNING_TIME.name()));
        assertTrue(identifiers.contains(FilterField.SIGNING_RECORD_SIGNED_DOCUMENT_RETRIEVED_AT.name()));
        assertTrue(identifiers.contains(FilterField.SIGNING_RECORD_CREATED.name()));
    }

    @Test
    void getSearchableFieldInformation_signingProfileDropdownContainsExistingProfileNames() {
        // when
        List<SearchFieldDataByGroupDto> groups = signingRecordService.getSearchableFieldInformation();

        // then
        SearchFieldDataDto profileField = groups.stream()
                .flatMap(g -> g.getSearchFieldData().stream())
                .filter(f -> f.getFieldIdentifier().equals(FilterField.SIGNING_RECORD_SIGNING_PROFILE.name()))
                .findFirst()
                .orElseThrow();
        List<?> dropdownValues = (List<?>) profileField.getValue();
        assertTrue(dropdownValues.contains(ALPHA_PROFILE));
        assertTrue(dropdownValues.contains(BETA_PROFILE));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // listSigningRecords
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void listSigningRecords_returnsAllRecordsAcrossProfilesAndVersions() {
        // given: profiles create in setup method

        // when
        PaginationResponseDto<SigningRecordListDto> response =
                signingRecordService.listSigningRecords(SearchRequestDtoBuilder.all(), SecurityFilter.create());

        // then
        assertEquals(3, response.getTotalItems());
        List<String> names = response.getItems().stream().map(SigningRecordListDto::getName).toList();
        assertTrue(names.contains(ALPHA_RECORD_V1));
        assertTrue(names.contains(ALPHA_RECORD_V2));
        assertTrue(names.contains(BETA_RECORD_V1));
    }

    @Test
    void listSigningRecords_filtersByName() {
        // given
        SearchRequestDto onlyAlphaV1 = SearchRequestDtoBuilder.aSearchRequest()
                .withPropertyFilter(FilterField.SIGNING_RECORD_NAME.name(), FilterConditionOperator.EQUALS, ALPHA_RECORD_V1)
                .build();

        // when
        PaginationResponseDto<SigningRecordListDto> response =
                signingRecordService.listSigningRecords(onlyAlphaV1, SecurityFilter.create());

        // then
        assertEquals(1, response.getTotalItems());
        assertEquals(ALPHA_RECORD_V1, response.getItems().getFirst().getName());
    }

    @Test
    void listSigningRecords_filtersBySigningProfile() {
        // given
        SearchRequestDto onlyAlphaProfile = SearchRequestDtoBuilder.aSearchRequest()
                .withPropertyFilter(FilterField.SIGNING_RECORD_SIGNING_PROFILE.name(), FilterConditionOperator.EQUALS, ALPHA_PROFILE)
                .build();

        // when
        PaginationResponseDto<SigningRecordListDto> response =
                signingRecordService.listSigningRecords(onlyAlphaProfile, SecurityFilter.create());

        // then
        assertEquals(2, response.getTotalItems());
        List<String> names = response.getItems().stream().map(SigningRecordListDto::getName).toList();
        assertTrue(names.contains(ALPHA_RECORD_V1));
        assertTrue(names.contains(ALPHA_RECORD_V2));
    }

    @Test
    void listSigningRecords_filtersBySigningProfileVersion() {
        // given
        SearchRequestDto onlyVersion2 = SearchRequestDtoBuilder.aSearchRequest()
                .withPropertyFilter(FilterField.SIGNING_RECORD_SIGNING_PROFILE_VERSION.name(), FilterConditionOperator.EQUALS, VERSION_2)
                .build();

        // when
        PaginationResponseDto<SigningRecordListDto> response =
                signingRecordService.listSigningRecords(onlyVersion2, SecurityFilter.create());

        // then
        assertEquals(1, response.getTotalItems());
        assertEquals(ALPHA_RECORD_V2, response.getItems().getFirst().getName());
    }

    @Test
    void listSigningRecords_paginatesResults() {
        // given
        SearchRequestDto firstPageOfTwo = SearchRequestDtoBuilder.aSearchRequest()
                .withPageNumber(1)
                .withItemsPerPage(2)
                .build();

        // when
        PaginationResponseDto<SigningRecordListDto> response =
                signingRecordService.listSigningRecords(firstPageOfTwo, SecurityFilter.create());

        // then
        assertEquals(3, response.getTotalItems());
        assertEquals(2, response.getItems().size());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // listSigningRecordsForProfile
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void listSigningRecordsForProfile_restrictsResultsToTheGivenProfile() {
        // given
        UUID alphaProfileUuid = alphaProfile.getUuid();

        // when
        PaginationResponseDto<SigningRecordListDto> response =
                signingRecordService.listSigningRecordsForProfile(alphaProfileUuid, SearchRequestDtoBuilder.all(), SecurityFilter.create());

        // then
        assertEquals(2, response.getTotalItems());
        List<String> names = response.getItems().stream().map(SigningRecordListDto::getName).toList();
        assertTrue(names.contains(ALPHA_RECORD_V1));
        assertTrue(names.contains(ALPHA_RECORD_V2));
        assertFalse(names.contains(BETA_RECORD_V1));
    }

    @Test
    void listSigningRecordsForProfile_honorsAdditionalFiltersWithinTheProfileScope() {
        // given
        UUID alphaProfileUuid = alphaProfile.getUuid();
        SearchRequestDto onlyVersion2 = SearchRequestDtoBuilder.aSearchRequest()
                .withPropertyFilter(FilterField.SIGNING_RECORD_SIGNING_PROFILE_VERSION.name(), FilterConditionOperator.EQUALS, VERSION_2)
                .build();

        // when
        PaginationResponseDto<SigningRecordListDto> response =
                signingRecordService.listSigningRecordsForProfile(alphaProfileUuid, onlyVersion2, SecurityFilter.create());

        // then
        assertEquals(1, response.getTotalItems());
        assertEquals(ALPHA_RECORD_V2, response.getItems().getFirst().getName());
    }

    @Test
    void listSigningRecordsForProfile_filterCannotWidenScopeToAnotherProfile() {
        // given: scope to alpha but ask for beta records — the profile scope is an AND, not overridable
        UUID alphaProfileUuid = alphaProfile.getUuid();
        SearchRequestDto onlyBetaProfile = SearchRequestDtoBuilder.aSearchRequest()
                .withPropertyFilter(FilterField.SIGNING_RECORD_SIGNING_PROFILE.name(), FilterConditionOperator.EQUALS, BETA_PROFILE)
                .build();

        // when
        PaginationResponseDto<SigningRecordListDto> response =
                signingRecordService.listSigningRecordsForProfile(alphaProfileUuid, onlyBetaProfile, SecurityFilter.create());

        // then
        assertEquals(0, response.getTotalItems());
        assertTrue(response.getItems().isEmpty());
    }

    @Test
    void listSigningRecordsForProfile_paginatesWithinTheProfileScope() {
        // given
        UUID alphaProfileUuid = alphaProfile.getUuid();
        SearchRequestDto firstPageOfOne = SearchRequestDtoBuilder.aSearchRequest()
                .withPageNumber(1)
                .withItemsPerPage(1)
                .build();

        // when
        PaginationResponseDto<SigningRecordListDto> response =
                signingRecordService.listSigningRecordsForProfile(alphaProfileUuid, firstPageOfOne, SecurityFilter.create());

        // then
        assertEquals(2, response.getTotalItems());
        assertEquals(1, response.getItems().size());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // getSigningRecord
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void getSigningRecord_returnsRecordDetailWithAllProperties() throws NotFoundException {
        // when
        SigningRecordDto dto = signingRecordService.getSigningRecord(SecuredUUID.fromUUID(alphaRecordV1.getUuid()));

        // then
        assertEquals(alphaRecordV1.getUuid().toString(), dto.getUuid());
        assertEquals(ALPHA_RECORD_V1, dto.getName());
        assertEquals(alphaRecordV1.getSigningTime(), dto.getSigningTime());
        assertArrayEquals(alphaRecordV1.getSignatureValue(), dto.getSignatureValue());
        assertArrayEquals(alphaRecordV1.getDtbs(), dto.getDtbs());
        assertArrayEquals(alphaRecordV1.getSignedDocument(), dto.getSignedDocument());
        // requestMetadataJson is stored in a JSONB column, which re-serializes (normalizes whitespace),
        // so assert on content rather than byte-exact equality
        assertTrue(dto.getRequestMetadataJson().contains("\"alg\""));
        assertTrue(dto.getRequestMetadataJson().contains("SHA256"));
        assertEquals(alphaRecordV1.getRequestedByUuid().toString(), dto.getRequestedBy().getUuid());
        assertEquals(alphaRecordV1.getRequestedByUsername(), dto.getRequestedBy().getName());
        assertEquals(alphaRecordV1.getSignedDocumentRetrievedAt(), dto.getSignedDocumentRetrievedAt());
        assertNotNull(dto.getCreatedAt());
    }

    @Test
    void getSigningRecord_throwsNotFoundException_whenRecordMissing() {
        // given
        SecuredUUID nonExistentUuid = SecuredUUID.fromUUID(UUID.randomUUID());

        // when
        Executable get = () -> signingRecordService.getSigningRecord(nonExistentUuid);

        // then
        assertThrows(NotFoundException.class, get);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // deleteSigningRecord
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void deleteSigningRecord_removesOnlyTheTargetedRecord() throws NotFoundException {
        // when
        signingRecordService.deleteSigningRecord(SecuredUUID.fromUUID(alphaRecordV1.getUuid()));

        // then
        assertFalse(signingRecordRepository.existsById(alphaRecordV1.getUuid()));
        assertEquals(2, signingRecordRepository.count());
    }

    @Test
    void deleteSigningRecord_throwsNotFoundException_whenRecordMissing() {
        // given
        SecuredUUID nonExistentUuid = SecuredUUID.fromUUID(UUID.randomUUID());

        // when
        Executable delete = () -> signingRecordService.deleteSigningRecord(nonExistentUuid);

        // then
        assertThrows(NotFoundException.class, delete);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // bulkDeleteSigningRecords
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void bulkDeleteSigningRecords_deletesAllAndReportsNoFailures() {
        // given
        List<SecuredUUID> allRecords = signingRecordRepository.findAll().stream()
                .map(r -> SecuredUUID.fromUUID(r.getUuid()))
                .toList();

        // when
        List<BulkActionMessageDto> messages = signingRecordService.bulkDeleteSigningRecords(allRecords);

        // then
        assertTrue(messages.isEmpty());
        assertEquals(0, signingRecordRepository.count());
    }

    @Test
    void bulkDeleteSigningRecords_reportsFailureForMissingRecordButDeletesExisting() {
        // given
        SecuredUUID existingUuid = SecuredUUID.fromUUID(alphaRecordV1.getUuid());
        SecuredUUID missingUuid = SecuredUUID.fromUUID(UUID.randomUUID());

        // when
        List<BulkActionMessageDto> messages = signingRecordService.bulkDeleteSigningRecords(List.of(existingUuid, missingUuid));

        // then
        assertFalse(signingRecordRepository.existsById(alphaRecordV1.getUuid()));
        assertEquals(1, messages.size());
        assertEquals(missingUuid.toString(), messages.getFirst().getUuid());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // doesSigningRecordExistInternal
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void doesSigningRecordExist_trueForProfileVersionThatHasRecords() {
        // when
        boolean exists = signingRecordService.doesSigningRecordExistInternal(alphaProfile.getUuid(), VERSION_2);

        // then
        assertTrue(exists);
    }

    @Test
    void doesSigningRecordExist_falseForProfileVersionWithoutRecords() {
        // given
        var versionWithoutRecords = 3;

        // when
        boolean exists = signingRecordService.doesSigningRecordExistInternal(alphaProfile.getUuid(), versionWithoutRecords);

        // then
        assertFalse(exists);
    }

    @Test
    void doesSigningRecordExist_isScopedToTheProfile() {
        // beta-profile has no version-2 record even though alpha-profile does
        // when
        boolean exists = signingRecordService.doesSigningRecordExistInternal(betaProfile.getUuid(), VERSION_2);

        // then
        assertFalse(exists);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Fixtures
    // ──────────────────────────────────────────────────────────────────────────

    private SigningProfile insertProfile(String name) {
        SigningProfile profile = new SigningProfile();
        profile.setName(name);
        profile.setEnabled(false);
        profile.setSigningScheme(SigningScheme.DELEGATED);
        profile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        profile.setLatestVersion(1);
        return signingProfileRepository.saveAndFlush(profile);
    }

    private void insertProfileVersion(SigningProfile profile, int version) {
        SigningProfileVersion profileVersion = new SigningProfileVersion();
        profileVersion.setSigningProfile(profile);
        profileVersion.setVersion(version);
        profileVersion.setSigningScheme(SigningScheme.DELEGATED);
        profileVersion.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        signingProfileVersionRepository.saveAndFlush(profileVersion);
    }

    private RecordBuilder aRecord(SigningProfile profile, int version) {
        return new RecordBuilder(profile, version);
    }

    /**
     * Builds a {@link SigningRecord} with valid, unremarkable defaults; tests override only the fields
     * whose values drive the assertion under test.
     */
    private final class RecordBuilder {
        private final SigningProfile profile;
        private final int version;
        private String name = "signing-record-" + UUID.randomUUID();
        private Instant signingTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        private byte[] signatureValue = null;
        private byte[] dtbs = null;
        private byte[] signedDocument = null;
        private String requestMetadataJson = null;
        private UUID requestedByUuid = null;
        private String requestedByUsername = null;
        private Instant signedDocumentRetrievedAt = null;

        private RecordBuilder(SigningProfile profile, int version) {
            this.profile = profile;
            this.version = version;
        }

        private RecordBuilder withName(String name) {
            this.name = name;
            return this;
        }

        private RecordBuilder withSignatureValue(byte[] signatureValue) {
            this.signatureValue = signatureValue;
            return this;
        }

        private RecordBuilder withDtbs(byte[] dtbs) {
            this.dtbs = dtbs;
            return this;
        }

        private RecordBuilder withSignedDocument(byte[] signedDocument) {
            this.signedDocument = signedDocument;
            return this;
        }

        private RecordBuilder withRequestMetadataJson(String requestMetadataJson) {
            this.requestMetadataJson = requestMetadataJson;
            return this;
        }

        private RecordBuilder withRequestedByUuid(UUID requestedByUuid) {
            this.requestedByUuid = requestedByUuid;
            return this;
        }

        private RecordBuilder withRequestedByUsername(String requestedByUsername) {
            this.requestedByUsername = requestedByUsername;
            return this;
        }

        private RecordBuilder withSignedDocumentRetrievedAt(Instant signedDocumentRetrievedAt) {
            this.signedDocumentRetrievedAt = signedDocumentRetrievedAt;
            return this;
        }

        private SigningRecord insert() {
            SigningRecord signingRecord = new SigningRecord();
            signingRecord.setSigningProfileUuid(profile.getUuid());
            signingRecord.setSigningProfileVersion(version);
            signingRecord.setName(name);
            signingRecord.setSigningTime(signingTime);
            signingRecord.setSignatureValue(signatureValue);
            signingRecord.setDtbs(dtbs);
            signingRecord.setSignedDocument(signedDocument);
            signingRecord.setRequestMetadataJson(requestMetadataJson);
            signingRecord.setRequestedByUuid(requestedByUuid);
            signingRecord.setRequestedByUsername(requestedByUsername);
            signingRecord.setSignedDocumentRetrievedAt(signedDocumentRetrievedAt);
            return signingRecordRepository.saveAndFlush(signingRecord);
        }
    }
}
