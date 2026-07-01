package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.v2.ConnectorExternalService;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.SearchRequestDtoBuilder;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.SignerConnectorMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV2ConnectorRequest;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequest;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequestFromExistingProfile;
import static com.otilm.core.util.builders.SigningRecordEntityBuilder.aSigningRecord;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives {@link SigningRecordExternalService} end to end: signing profiles are created through {@link SigningProfileService}
 * against a live {@link SignerConnectorMock}, signing records are persisted through {@link SigningRecordWriter}, and
 * every assertion reads back through the service under test. Nothing touches a repository directly.
 */
class SigningRecordServiceTest extends BaseSpringBootTest {

    private static final String ALPHA_PROFILE = "alpha-profile";
    private static final String BETA_PROFILE = "beta-profile";
    private static final int VERSION_1 = 1;
    private static final int VERSION_2 = 2;
    private static final String ALPHA_RECORD_V1 = "alpha-record-v1";
    private static final String ALPHA_RECORD_V2 = "alpha-record-v2";
    private static final String BETA_RECORD_V1 = "beta-record-v1";

    @Autowired
    private SigningRecordExternalService signingRecordService;

    @Autowired
    private SigningRecordInternalService signingRecordInternalService;

    @Autowired
    private SigningProfileService signingProfileService;

    @Autowired
    private SigningRecordWriter signingRecordWriter;

    @Autowired
    private ConnectorExternalService connectorService;

    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    private SignerConnectorMock signerConnectorMock;
    private ConnectorDetailDto signerConnector;
    private SigningProfileDto defaultProfile;

    @BeforeEach
    void setUp() throws Exception {
        signerConnectorMock = connectorMockFactory.startSigner();
        signerConnector = connectorService.createConnector(
                aV2ConnectorRequest()
                        .withName("signer")
                        .withUrl(signerConnectorMock.getUrl())
                        .build()
        );
        defaultProfile = createSigningProfile("default-profile");
    }

    @AfterEach
    void tearDown() {
        signerConnectorMock.stop();
    }

    @Nested
    class SearchableFieldsTests {

        @Test
        void returnsSinglePropertyGroupWithEverySigningRecordField() {
            // when
            List<SearchFieldDataByGroupDto> groups = signingRecordService.getSearchableFieldInformation();

            // then
            assertEquals(1, groups.stream()
                    .filter(g -> g.getFilterFieldSource() == FilterFieldSource.PROPERTY)
                    .count());
            assertEquals(FilterField.getEnumsForResource(Resource.SIGNING_RECORD).size(), propertyFieldsOf(groups).size());
        }

        @Test
        void exposesExpectedPropertyFieldIdentifiers() {
            // when
            List<SearchFieldDataByGroupDto> groups = signingRecordService.getSearchableFieldInformation();

            // then
            List<String> identifiers = propertyFieldsOf(groups).stream()
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
        void signingProfileDropdownContainsExistingProfileNames() {
            // when
            List<SearchFieldDataByGroupDto> groups = signingRecordService.getSearchableFieldInformation();

            // then
            SearchFieldDataDto signingProfileField = propertyFieldsOf(groups).stream()
                    .filter(f -> f.getFieldIdentifier().equals(FilterField.SIGNING_RECORD_SIGNING_PROFILE.name()))
                    .findFirst()
                    .orElseThrow();
            assertTrue(((List<?>) signingProfileField.getValue()).contains(defaultProfile.getName()));
        }

        private List<SearchFieldDataDto> propertyFieldsOf(List<SearchFieldDataByGroupDto> groups) {
            return groups.stream()
                    .filter(g -> g.getFilterFieldSource() == FilterFieldSource.PROPERTY)
                    .map(SearchFieldDataByGroupDto::getSearchFieldData)
                    .flatMap(List::stream)
                    .toList();
        }
    }

    @Nested
    class ListTests {

        @Test
        void returnsEmptyList_whenNoRecordsExist() {
            // given no records seeded

            // when
            PaginationResponseDto<SigningRecordListDto> response =
                    signingRecordService.listSigningRecords(SearchRequestDtoBuilder.all(), SecurityFilter.create());

            // then
            assertEquals(0, response.getTotalItems());
            assertTrue(response.getItems().isEmpty());
        }

        @Test
        void returnsAllRecordsAcrossProfilesAndVersions() throws Exception {
            // given
            seedRecordsAcrossProfilesAndVersions();

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
        void filtersByName() throws Exception {
            // given
            seedRecordsAcrossProfilesAndVersions();
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
        void filtersBySigningProfile() throws Exception {
            // given
            seedRecordsAcrossProfilesAndVersions();
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
        void filtersBySigningProfileVersion() throws Exception {
            // given
            seedRecordsAcrossProfilesAndVersions();
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
        void paginatesResults() throws Exception {
            // given
            seedRecordsAcrossProfilesAndVersions();
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
    }

    @Nested
    class ListByProfileTests {

        @Test
        void returnsOnlyRecordsForRequestedSigningProfile() throws Exception {
            // given
            SigningProfileDto targetProfile = createSigningProfile(ALPHA_PROFILE);
            insertRecord(targetProfile, VERSION_1, ALPHA_RECORD_V1);
            insertRecord(defaultProfile, VERSION_1, "other-record-v1");

            // when
            PaginationResponseDto<SigningRecordListDto> response = signingRecordService.listSigningRecordsForProfile(
                    UUID.fromString(targetProfile.getUuid()), SearchRequestDtoBuilder.all(), SecurityFilter.create());

            // then
            assertEquals(1, response.getTotalItems());
            assertEquals(ALPHA_RECORD_V1, response.getItems().getFirst().getName());
        }

        @Test
        void returnsEmptyList_whenNoRecordsForProfile() throws Exception {
            // given
            SigningProfileDto profileWithNoRecords = createSigningProfile("profile-with-no-records");

            // when
            PaginationResponseDto<SigningRecordListDto> response = signingRecordService.listSigningRecordsForProfile(
                    UUID.fromString(profileWithNoRecords.getUuid()), SearchRequestDtoBuilder.all(), SecurityFilter.create());

            // then
            assertTrue(response.getItems().isEmpty());
        }

        @Test
        void listSigningRecordsForProfile_honorsAdditionalFiltersWithinTheProfileScope() throws Exception {
            // given
            SigningProfileDto targetProfile = createSigningProfile(ALPHA_PROFILE);
            insertRecord(targetProfile, VERSION_1, ALPHA_RECORD_V1);
            bumpToNextVersion(targetProfile);
            insertRecord(targetProfile, VERSION_2, ALPHA_RECORD_V2);
            SearchRequestDto onlyVersion2 = SearchRequestDtoBuilder.aSearchRequest()
                    .withPropertyFilter(FilterField.SIGNING_RECORD_SIGNING_PROFILE_VERSION.name(), FilterConditionOperator.EQUALS, VERSION_2)
                    .build();

            // when
            PaginationResponseDto<SigningRecordListDto> response =
                    signingRecordService.listSigningRecordsForProfile(UUID.fromString(targetProfile.getUuid()), onlyVersion2, SecurityFilter.create());

            // then
            assertEquals(1, response.getTotalItems());
            assertEquals(ALPHA_RECORD_V2, response.getItems().getFirst().getName());
        }

        @Test
        void listSigningRecordsForProfile_filterCannotWidenScopeToAnotherProfile() throws Exception {
            // given: scope to alpha but ask for beta records — the profile scope is an AND, not overridable
            SigningProfileDto alphaProfile = createSigningProfile(ALPHA_PROFILE);
            SigningProfileDto betaProfile = createSigningProfile(BETA_PROFILE);
            insertRecord(alphaProfile, VERSION_1, ALPHA_RECORD_V1);
            insertRecord(betaProfile, VERSION_1, BETA_RECORD_V1);
            SearchRequestDto onlyBetaProfile = SearchRequestDtoBuilder.aSearchRequest()
                    .withPropertyFilter(FilterField.SIGNING_RECORD_SIGNING_PROFILE.name(), FilterConditionOperator.EQUALS, BETA_PROFILE)
                    .build();

            // when
            PaginationResponseDto<SigningRecordListDto> response =
                    signingRecordService.listSigningRecordsForProfile(UUID.fromString(alphaProfile.getUuid()),
                            onlyBetaProfile,
                            SecurityFilter.create());

            // then
            assertEquals(0, response.getTotalItems());
            assertTrue(response.getItems().isEmpty());
        }

        @Test
        void listSigningRecordsForProfile_paginatesWithinTheProfileScope() throws Exception {
            // given
            SigningProfileDto alphaProfile = createSigningProfile(ALPHA_PROFILE);
            insertRecord(alphaProfile, VERSION_1, ALPHA_RECORD_V1);
            bumpToNextVersion(alphaProfile);
            insertRecord(alphaProfile, VERSION_2, ALPHA_RECORD_V2);
            SearchRequestDto firstPageOfOne = SearchRequestDtoBuilder.aSearchRequest()
                    .withPageNumber(1)
                    .withItemsPerPage(1)
                    .build();

            // when
            PaginationResponseDto<SigningRecordListDto> response =
                    signingRecordService.listSigningRecordsForProfile(UUID.fromString(alphaProfile.getUuid()), firstPageOfOne,
                            SecurityFilter.create());

            // then
            assertEquals(2, response.getTotalItems());
            assertEquals(1, response.getItems().size());
        }
    }

    @Nested
    class GetTests {

        @Test
        void returnsRecordDetailWithAllProperties() throws NotFoundException {
            // given
            var signingTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);
            var retrievedAt = Instant.now().truncatedTo(ChronoUnit.MILLIS);
            var requestedByUuid = UUID.fromString("99999999-9999-9999-9999-999999999999");
            var requestedByUsername = "alice";
            SigningRecord signingRecord = aSigningRecord()
                    .withSigningProfile(defaultProfile)
                    .withName(ALPHA_RECORD_V1)
                    .withSigningTime(signingTime)
                    .withSignatureValue("alpha-v1-signature".getBytes())
                    .withDtbs("alpha-v1-dtbs".getBytes())
                    .withSignedDocument("alpha-v1-signed-document".getBytes())
                    .withRequestMetadataJson("{\"alg\":\"SHA256\"}")
                    .withRequestedByUuid(requestedByUuid)
                    .withRequestedByUsername(requestedByUsername)
                    .withSignedDocumentRetrievedAt(retrievedAt)
                    .build();
            signingRecordWriter.insert(signingRecord);

            // when
            SigningRecordDto dto = signingRecordService.getSigningRecord(SecuredUUID.fromUUID(signingRecord.getUuid()));

            // then
            assertEquals(signingRecord.getUuid().toString(), dto.getUuid());
            assertEquals(ALPHA_RECORD_V1, dto.getName());
            assertEquals(signingTime, dto.getSigningTime());
            assertArrayEquals(signingRecord.getSignatureValue(), dto.getSignatureValue());
            assertArrayEquals(signingRecord.getDtbs(), dto.getDtbs());
            assertArrayEquals(signingRecord.getSignedDocument(), dto.getSignedDocument());
            // requestMetadataJson is stored in a JSONB column, which re-serializes (normalizes whitespace),
            // so assert on content rather than byte-exact equality
            assertTrue(dto.getRequestMetadataJson().contains("\"alg\""));
            assertTrue(dto.getRequestMetadataJson().contains("SHA256"));
            assertEquals(requestedByUuid.toString(), dto.getRequestedBy().getUuid());
            assertEquals(requestedByUsername, dto.getRequestedBy().getName());
            assertEquals(retrievedAt, dto.getSignedDocumentRetrievedAt());
            assertNotNull(dto.getCreatedAt());
        }

        @Test
        void throwsNotFoundException_whenRecordMissing() {
            // given
            SecuredUUID nonExistentUuid = SecuredUUID.fromUUID(UUID.randomUUID());

            // when
            Executable get = () -> signingRecordService.getSigningRecord(nonExistentUuid);

            // then
            assertThrows(NotFoundException.class, get);
        }
    }

    @Nested
    class DeleteTests {

        @Test
        void removesOnlyTheTargetedRecord() throws NotFoundException {
            // given
            SigningRecord keep = aSigningRecord().withSigningProfile(defaultProfile).withName("keep").build();
            SigningRecord remove = aSigningRecord().withSigningProfile(defaultProfile).withName("remove").build();
            signingRecordWriter.insert(keep);
            signingRecordWriter.insert(remove);

            // when
            signingRecordService.deleteSigningRecord(SecuredUUID.fromUUID(remove.getUuid()));

            // then
            PaginationResponseDto<SigningRecordListDto> remaining =
                    signingRecordService.listSigningRecords(SearchRequestDtoBuilder.all(), SecurityFilter.create());
            assertEquals(1, remaining.getTotalItems());
            assertEquals(keep.getUuid().toString(), remaining.getItems().getFirst().getUuid());
        }

        @Test
        void throwsNotFoundException_whenRecordMissing() {
            // given
            SecuredUUID nonExistentUuid = SecuredUUID.fromUUID(UUID.randomUUID());

            // when
            Executable delete = () -> signingRecordService.deleteSigningRecord(nonExistentUuid);

            // then
            assertThrows(NotFoundException.class, delete);
        }
    }

    @Nested
    class BulkDeleteTests {

        @Test
        void deletesAllAndReportsNoFailures() {
            // given
            SigningRecord first = aSigningRecord().withSigningProfile(defaultProfile).withName("first").build();
            SigningRecord second = aSigningRecord().withSigningProfile(defaultProfile).withName("second").build();
            signingRecordWriter.insert(first);
            signingRecordWriter.insert(second);
            List<SecuredUUID> allRecords = List.of(
                    SecuredUUID.fromUUID(first.getUuid()), SecuredUUID.fromUUID(second.getUuid()));

            // when
            List<BulkActionMessageDto> messages = signingRecordService.bulkDeleteSigningRecords(allRecords);

            // then
            assertTrue(messages.isEmpty());
            assertEquals(0, signingRecordService.listSigningRecords(
                    SearchRequestDtoBuilder.all(), SecurityFilter.create()).getTotalItems());
        }

        @Test
        void reportsFailureForMissingRecordButDeletesExisting() {
            // given
            SigningRecord existing = aSigningRecord().withSigningProfile(defaultProfile).withName("existing").build();
            signingRecordWriter.insert(existing);
            SecuredUUID existingUuid = SecuredUUID.fromUUID(existing.getUuid());
            SecuredUUID missingUuid = SecuredUUID.fromUUID(UUID.randomUUID());

            // when
            List<BulkActionMessageDto> messages =
                    signingRecordService.bulkDeleteSigningRecords(List.of(existingUuid, missingUuid));

            // then
            assertEquals(1, messages.size());
            assertEquals(missingUuid.toString(), messages.getFirst().getUuid());
            assertEquals(0, signingRecordService.listSigningRecords(
                    SearchRequestDtoBuilder.all(), SecurityFilter.create()).getTotalItems());
        }
    }

    @Nested
    class ExistsForVersionTests {

        @Test
        void trueForProfileVersionThatHasRecords() throws Exception {
            // given
            Fixture fixture = seedRecordsAcrossProfilesAndVersions();

            // when
            boolean exists = signingRecordInternalService.doesSigningRecordExistInternal(
                    UUID.fromString(fixture.alpha().getUuid()), VERSION_2);

            // then
            assertTrue(exists);
        }

        @Test
        void falseForProfileVersionWithoutRecords() throws Exception {
            // given
            Fixture fixture = seedRecordsAcrossProfilesAndVersions();
            int versionWithoutRecords = 3;

            // when
            boolean exists = signingRecordInternalService.doesSigningRecordExistInternal(
                    UUID.fromString(fixture.alpha().getUuid()), versionWithoutRecords);

            // then
            assertFalse(exists);
        }

        @Test
        void isScopedToTheProfile() throws Exception {
            // beta-profile has no version-2 record even though alpha-profile does
            // given
            Fixture fixture = seedRecordsAcrossProfilesAndVersions();

            // when
            boolean exists = signingRecordInternalService.doesSigningRecordExistInternal(
                    UUID.fromString(fixture.beta().getUuid()), VERSION_2);

            // then
            assertFalse(exists);
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Fixtures — all seeding goes through the signing-profile service and the record writer
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Two profiles spanning three signing-profile versions with one record each: alpha-profile holds versions 1 and 2
     * (records {@value ALPHA_RECORD_V1}, {@value ALPHA_RECORD_V2}) and beta-profile holds version 1 (record
     * {@value BETA_RECORD_V1}). The alpha version-2 row is produced by an actual {@code updateSigningProfile} bump,
     * which the service performs precisely because alpha version 1 already has a record.
     */
    private Fixture seedRecordsAcrossProfilesAndVersions() throws Exception {
        SigningProfileDto alpha = createSigningProfile(ALPHA_PROFILE);
        insertRecord(alpha, VERSION_1, ALPHA_RECORD_V1);
        bumpToNextVersion(alpha);
        insertRecord(alpha, VERSION_2, ALPHA_RECORD_V2);

        SigningProfileDto beta = createSigningProfile(BETA_PROFILE);
        insertRecord(beta, VERSION_1, BETA_RECORD_V1);

        return new Fixture(alpha, beta);
    }

    private record Fixture(SigningProfileDto alpha, SigningProfileDto beta) {
    }

    private SigningProfileDto createSigningProfile(String name) throws Exception {
        return signingProfileService.createSigningProfile(
                aSigningProfileRequest()
                        .withName(name)
                        .withDelegatedSigning(signerConnector.getUuid())
                        .withRawSigning()
                        .build()
        );
    }

    /**
     * Bumps {@code profile} to its next version through the service. The bump only materialises a new version row
     * when records already exist for the current version, so callers must seed a record first.
     */
    private void bumpToNextVersion(SigningProfileDto profile) throws Exception {
        signingProfileService.updateSigningProfile(
                SecuredUUID.fromString(profile.getUuid()),
                aSigningProfileRequestFromExistingProfile(profile).build());
    }

    private void insertRecord(SigningProfileDto profile, int version, String name) {
        signingRecordWriter.insert(aSigningRecord()
                .withSigningProfile(profile)
                .withVersion(version)
                .withName(name)
                .build());
    }
}
