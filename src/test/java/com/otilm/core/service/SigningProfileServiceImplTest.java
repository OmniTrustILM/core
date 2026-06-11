package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.SigningProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV2;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.core.attribute.RsaSignatureAttributes;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.SigningProfileListDto;
import com.otilm.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspActivationDetailDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.otilm.api.model.client.signing.profile.scheme.DelegatedSigningDto;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.scheme.StaticKeyManagedSigningDto;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowDto;
import com.otilm.api.model.client.signing.profile.workflow.RawSigningWorkflowDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.profile.workflow.TimestampingWorkflowDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.AttributeRelation;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.timequality.TimeQualityConfigurationModel;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.AttributeRelationRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.TestCertificateAuthority;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.v2.ConnectorService;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mocks.ContentSigningFormatterMock;
import com.otilm.core.util.mocks.CryptographyProviderConnectorMock;
import com.otilm.core.util.mocks.SignerConnectorMock;
import com.otilm.core.util.mocks.TimestampingFormatterConnectorMock;
import com.otilm.core.util.seeders.FunctionGroupSeeder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static com.otilm.core.util.builders.ContentSigningWorkflowRequestDtoBuilder.aContentSigningWorkflow;
import static com.otilm.core.util.builders.SigningRecordEntityBuilder.aSigningRecord;
import static com.otilm.core.util.builders.TimestampingWorkflowRequestDtoBuilder.aTimestampingWorkflow;
import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV1ConnectorRequest;
import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV2ConnectorRequest;
import static com.otilm.core.util.builders.KeyPairRequestDtoBuilder.aKeyPairRequest;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyEqualsFilter;
import static com.otilm.core.util.builders.SearchRequestDtoBuilder.aSearchRequest;
import static com.otilm.core.util.builders.RequestAttributeV3Builder.aCustomAttribute;
import static com.otilm.core.util.builders.RsaSignatureAttributesBuilder.rsaSignatureAttributes;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequest;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequestFromExistingProfile;
import static com.otilm.core.util.builders.TokenInstanceRequestDtoBuilder.aTokenInstanceRequest;
import static com.otilm.core.util.builders.TokenProfileRequestDtoBuilder.aTokenProfileRequest;
import static com.otilm.core.util.builders.TimeQualityConfigurationRequestDtoBuilder.aTimeQualityConfigurationRequest;
import static com.otilm.core.util.builders.TspProfileRequestDtoBuilder.aTspProfileRequest;
import static org.junit.jupiter.api.Assertions.*;

class SigningProfileServiceImplTest extends BaseSpringBootTest {

    private static final String CUSTOM_ATTR_UUID = "c1d2e3f4-0001-0002-0003-000000000004";
    private static final String CUSTOM_ATTR_NAME = "signingProfileTestAttribute";

    @Autowired
    private SigningProfileService signingProfileService;

    @Autowired
    private TspProfileService tspProfileService;

    @Autowired
    private ConnectorService connectorService;

    @Autowired
    private TokenInstanceService tokenInstanceService;

    @Autowired
    private TokenProfileService tokenProfileService;

    @Autowired
    private CryptographicKeyService cryptographicKeyService;

    @Autowired
    private TimeQualityConfigurationService timeQualityConfigurationService;

    @Autowired
    private FunctionGroupSeeder functionGroupSeeder;

    @Autowired
    private TestCertificateAuthority testCertificateAuthority;

    private ContentSigningFormatterMock contentSigningFormatterMock;
    private TimestampingFormatterConnectorMock timestampingFormatterMock;
    private CryptographyProviderConnectorMock cryptographyProviderServerMock;
    private SignerConnectorMock signerConnectorServerMock;
    private ConnectorDetailDto contentSigningFormatterConnector;
    private ConnectorDetailDto timestampingFormatterConnector;
    private ConnectorDetailDto cryptographyProviderConnector;
    private ConnectorDetailDto signerConnector;
    private TokenInstanceDetailDto tokenInstance;
    private TokenProfileDetailDto defaultTokenProfile;
    private KeyPair keyPair;
    private KeyDetailDto key;
    private Certificate defaultSigningCertificate;
    private SigningProfileDto defaultDelegatedSigningProfile;
    private SigningProfileDto defaultManagedStaticKeySigningProfile;
    private SigningProfileDto defaultContentSigningProfile;
    private SigningProfileDto defaultTimestampingProfile;
    private SigningProfileDto defaultRawSigningProfile;

    private TspProfileDto defaultTspProtocol;
    @Autowired
    private SigningRecordWriter signingRecordWriter;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    private AttributeRelationRepository attributeRelationRepository;

    private static String firstErrorMessage(ValidationException ex) {
        return ex.getErrors().stream()
                .map(ValidationError::getErrorDescription)
                .findFirst()
                .orElse("");
    }

    private static String extractStringAttrValue(List<ResponseAttribute> attrs, String name) {
        ResponseAttributeV2 attr = (ResponseAttributeV2) attrs.stream()
                .filter(a -> name.equals(a.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Attribute '" + name + "' not found in: " + attrs));
        return attr.getContent().getFirst().getData().toString();
    }

    private static RequestAttribute aStringAttribute(UUID uuid, String name, String value) {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(uuid);
        attr.setName(name);
        attr.setContentType(AttributeContentType.STRING);
        attr.setContent(List.of(new StringAttributeContentV2(value, value)));
        return attr;
    }

    @BeforeEach
    void setUp() throws Exception {

        // Seed platform reference data normally provided by Flyway (wiped by per-test truncation)
        functionGroupSeeder.seedCryptographyProvider();

        // Set up mocks of connectors (the servers to call)
        cryptographyProviderServerMock = CryptographyProviderConnectorMock.start();
        contentSigningFormatterMock = ContentSigningFormatterMock.start();
        timestampingFormatterMock = TimestampingFormatterConnectorMock.start();
        signerConnectorServerMock = SignerConnectorMock.start();

        // Register the connectors to ILM
        cryptographyProviderConnector = connectorService.createConnector(
                aV1ConnectorRequest()
                        .withName("soft-cryptography-provider")
                        .withUrl(this.cryptographyProviderServerMock.getUrl())
                        .build()
        );
        contentSigningFormatterConnector = connectorService.createConnector(
                aV2ConnectorRequest()
                        .withName("content-signing-formatter")
                        .withUrl(this.contentSigningFormatterMock.getUrl())
                        .build()
        );
        timestampingFormatterConnector = connectorService.createConnector(
                aV2ConnectorRequest()
                        .withName("timestamping-formatter")
                        .withUrl(this.timestampingFormatterMock.getUrl())
                        .build()
        );
        signerConnector = connectorService.createConnector(
                aV2ConnectorRequest()
                        .withName("delegated-signer")
                        .withUrl(this.signerConnectorServerMock.getUrl())
                        .build()
        );

        // Create a token instance backed by the cryptography provider
        cryptographyProviderServerMock.stubTokenInstanceCreation(UUID.randomUUID());
        tokenInstance = tokenInstanceService.createTokenInstance(
                aTokenInstanceRequest()
                        .withName("soft-token")
                        .withConnector(cryptographyProviderConnector.getUuid())
                        .build()
        );

        // Create a token profile on the token instance
        cryptographyProviderServerMock.stubTokenProfileCreation();
        defaultTokenProfile = tokenProfileService.createTokenProfile(
                SecuredParentUUID.fromString(tokenInstance.getUuid()),
                aTokenProfileRequest()
                        .withName("soft-token-profile")
                        .build()
        );

        // Create a key pair on the token profile, reporting a real public key the certificate will reuse
        keyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        String base64Spki = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        cryptographyProviderServerMock.stubKeyPairCreation(base64Spki);
        key = cryptographicKeyService.createKey(
                UUID.fromString(tokenInstance.getUuid()),
                SecuredParentUUID.fromString(defaultTokenProfile.getUuid()),
                KeyRequestType.KEY_PAIR,
                aKeyPairRequest()
                        .withName("soft-key-pair")
                        .build()
        );

        // Establish a trusted root CA, then a TSA leaf signed by it and built from the token key pair.
        // Uploading the leaf associates it (by public-key fingerprint) with the token-backed key.
        defaultSigningCertificate = testCertificateAuthority.createTrustedCa("CN=Test Root CA")
                .issueTimestampingCertificate(keyPair, "CN=Test TSA");

        // Create signing profiles
        defaultDelegatedSigningProfile = signingProfileService.createSigningProfile(
                aSigningProfileRequest()
                        .withName("default-delegated-signing-profile")
                        .withDelegatedSigning(signerConnector.getUuid())
                        .withRawSigning()
                        .build()
        );

        defaultManagedStaticKeySigningProfile = signingProfileService.createSigningProfile(
                aSigningProfileRequest()
                        .withName("default-managed-static-key-signing-profile")
                        .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                        .withRawSigning()
                        .build()
        );

        contentSigningFormatterMock.stubFormatterAttributes();
        defaultContentSigningProfile = signingProfileService.createSigningProfile(
                aSigningProfileRequest()
                        .withName("default-content-signing-profile")
                        .withDelegatedSigning(signerConnector.getUuid())
                        .withContentSigning(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                        .build()
        );

        timestampingFormatterMock.stubFormatterAttributes();
        defaultTimestampingProfile = signingProfileService.createSigningProfile(
                aSigningProfileRequest()
                        .withName("default-timestamping-profile")
                        .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                        .withTimestamping(aTimestampingWorkflow()
                                .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                .build()
                        )
                        .build()
        );

        defaultRawSigningProfile = signingProfileService.createSigningProfile(
                aSigningProfileRequest()
                        .withName("default-raw-signing-profile")
                        .withDelegatedSigning(signerConnector.getUuid())
                        .withRawSigning()
                        .build()
        );

        // Create default TSP protocol
        defaultTspProtocol = tspProfileService.createTspProfile(
                aTspProfileRequest()
                        .withName("default-tsp-protocol")
                        .build()
        );
    }

    @AfterEach
    void tearDown() {
        contentSigningFormatterMock.stop();
        timestampingFormatterMock.stop();
        cryptographyProviderServerMock.stop();
        signerConnectorServerMock.stop();
    }

    private void createSigningRecordFor(SigningProfileDto profile) {
        signingRecordWriter.insert(aSigningRecord()
                .withSigningProfile(profile).build());
    }

    @Test
    void deniedCert_throwsAccessDeniedException() {
        // given: OPA mock configured to deny certificate DETAIL access
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.DETAIL);

        UUID rsaCertificateUuid = defaultSigningCertificate.getUuid();

        // when
        Executable listAttributes = () -> signingProfileService.listSignatureAttributesForCertificate(rsaCertificateUuid);

        // then
        assertThrows(AccessDeniedException.class, listAttributes);
    }

    @Nested
    class ListTests {

        @Test
        void emptyWhenNoneExistAndNoFilteringApplied() {
            // given: no profiles (delete all from setUp)
            signingProfileService.bulkDeleteSigningProfiles(SecuredUUID.asList(
                    defaultDelegatedSigningProfile.getUuid(),
                    defaultManagedStaticKeySigningProfile.getUuid(),
                    defaultContentSigningProfile.getUuid(),
                    defaultTimestampingProfile.getUuid(),
                    defaultRawSigningProfile.getUuid()
            ));
            var searchRequest = aSearchRequest().build();
            SecurityFilter filter = new SecurityFilter();

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(searchRequest, filter);

            // then
            assertNotNull(response);
            assertEquals(0, response.getTotalItems());
            assertTrue(response.getItems().isEmpty());
        }

        @Test
        void returnsAllExistingEntriesWhenNoFilteringApplied() {
            // given: five profiles created in setUp (raw ×3, content signing ×1, timestamping ×1), no filters
            var searchRequest = aSearchRequest().build();
            SecurityFilter filter = new SecurityFilter();

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(searchRequest, filter);

            // then
            assertNotNull(response);
            assertEquals(5, response.getTotalItems());
        }

        @Test
        void filtersByName() {
            // given: filter matching only "default-delegated-signing-profile" by exact name
            var searchRequest = aSearchRequest()
                    .withFilters(aPropertyEqualsFilter(FilterField.SIGNING_PROFILE_NAME, "default-delegated-signing-profile"))
                    .build();
            SecurityFilter filter = new SecurityFilter();

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(searchRequest, filter);

            // then
            assertEquals(1, response.getTotalItems());
            assertEquals("default-delegated-signing-profile", response.getItems().getFirst().getName());
        }

        @Test
        void filtersBySigningScheme() {
            // given: filter matching only a delegated signing scheme (default-delegated-signing-profile + default-content-signing-profile + default-raw-signing-profile)
            var searchRequest = aSearchRequest()
                    .withFilters(
                            aPropertyEqualsFilter(
                                    FilterField.SIGNING_PROFILE_SIGNING_SCHEME,
                                    SigningScheme.DELEGATED.getCode()
                            )
                    )
                    .build();
            SecurityFilter filter = new SecurityFilter();

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(searchRequest, filter);

            // then
            assertEquals(3, response.getTotalItems());
        }

        @Test
        void filtersByWorkflowType() {
            // given: filter matching only TIMESTAMPING workflow
            var searchRequest = aSearchRequest()
                    .withFilters(
                            aPropertyEqualsFilter(
                                    FilterField.SIGNING_PROFILE_WORKFLOW_TYPE,
                                    SigningWorkflowType.TIMESTAMPING.getCode()
                            )
                    )
                    .build();
            SecurityFilter filter = new SecurityFilter();

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(searchRequest, filter);

            // then
            assertEquals(1, response.getTotalItems());
            assertEquals("default-timestamping-profile", response.getItems().getFirst().getName());
        }
    }

    @Nested
    class ListSignatureAttributesTests {

        @Test
        void allowedCert_returnsAttributes() throws NotFoundException {
            // given: signingCertificate from setUp (access allowed by default)

            // when
            List<com.otilm.api.model.common.attribute.common.BaseAttribute> attrs =
                    signingProfileService.listSignatureAttributesForCertificate(defaultSigningCertificate.getUuid());

            // then
            assertNotNull(attrs);
            assertFalse(attrs.isEmpty(), "RSA certificate should produce non-empty signature attributes");
        }

        @Test
        void deniedCert_throwsAccessDeniedException() {
            // given: OPA mock configured to deny certificate DETAIL access
            denyResourceAccess(Resource.CERTIFICATE, ResourceAction.DETAIL);
            UUID rsaCertificateUuid = defaultSigningCertificate.getUuid();

            // when
            Executable listAttributes = () -> signingProfileService.listSignatureAttributesForCertificate(rsaCertificateUuid);

            // then
            assertThrows(AccessDeniedException.class, listAttributes);
        }
    }

    @Nested
    class GetTests {

        @Test
        void returnsLatestVersionByDefault() throws NotFoundException, ConnectorException, AlreadyExistException, AttributeException {
            // given: profile with multiple versions
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
            createSigningRecordFor(defaultDelegatedSigningProfile);
            signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                            .withName("a-new-name")
                            .build()
            );

            // when
            SigningProfileDto dto = signingProfileService.getSigningProfile(profileUuid, null);

            // then
            assertNotNull(dto);
            assertEquals(defaultDelegatedSigningProfile.getUuid(), dto.getUuid());
            assertEquals("a-new-name", dto.getName());
            assertEquals(2, dto.getVersion());
        }

        @Test
        void specificVersion_returnsSnapshotData() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: profile with multiple versions
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
            createSigningRecordFor(defaultDelegatedSigningProfile);
            signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .build()
            );


            // when: fetch with explicit version=1
            SigningProfileDto dto = signingProfileService.getSigningProfile(profileUuid, 1);

            // then
            assertNotNull(dto);
            assertEquals(defaultDelegatedSigningProfile.getUuid(), dto.getUuid());
            assertInstanceOf(DelegatedSigningDto.class, dto.getSigningScheme());
            assertEquals(1, dto.getVersion());
        }

        @Test
        void nonExistentVersion_throwsNotFoundException() {
            // given: a profile with only version 1
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
            int nonExistentVersion = 99;

            // when
            Executable get = () -> signingProfileService.getSigningProfile(profileUuid, nonExistentVersion);

            // then: version 99 does not exist
            assertThrows(NotFoundException.class, get);
        }

        @Test
        void afterVersionBump_oldVersionPreservesOriginalWorkflowType()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: profile with signing record (without the record, a new version will not be created)
            SigningProfileDto existingProfile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("workflow-update")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .build()
            );
            SecuredUUID profileUuid = SecuredUUID.fromString(existingProfile.getUuid());
            createSigningRecordFor(existingProfile);

            // when: the profile is updated to use a different workflow type (timestamping)
            signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(existingProfile)
                            .withTimestamping(UUID.fromString(timestampingFormatterConnector.getUuid()))
                            .build()
            );

            // then: version 1 still has the original RAW workflow
            SigningProfileDto previousProfileVersion = signingProfileService.getSigningProfile(profileUuid, 1);
            assertEquals("workflow-update", existingProfile.getName());
            assertEquals(1, existingProfile.getVersion());
            assertInstanceOf(RawSigningWorkflowDto.class, previousProfileVersion.getWorkflow());
        }

        @Test
        void noProtocolsLinked_enabledProtocolsIsEmpty() throws NotFoundException, ConnectorException, AlreadyExistException, AttributeException {
            // when: after creation, no protocols are linked
            SigningProfileDto createdProfile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("no-protocols-linked")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .build()
            );

            // then
            assertNotNull(createdProfile.getEnabledProtocols());
            assertTrue(createdProfile.getEnabledProtocols().isEmpty(), "No protocols should be enabled when none are linked");
        }

        @Test
        void withTspLinked_enabledProtocolsContainsTsp() throws NotFoundException, ConnectorException, AlreadyExistException, AttributeException {
            // given
            SigningProfileDto createdProfile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("some protocols-linked")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withTimestamping(UUID.fromString(timestampingFormatterConnector.getUuid()))
                            .build()
            );

            // when: link a TSP protocol to the profile
            signingProfileService.activateTsp(SecuredUUID.fromString(createdProfile.getUuid()),
                    SecuredUUID.fromString(defaultTspProtocol.getUuid()));

            // then
            SigningProfileDto updatedProfile = signingProfileService.getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);
            assertNotNull(updatedProfile.getEnabledProtocols());
            assertEquals(1, updatedProfile.getEnabledProtocols().size());
            assertTrue(updatedProfile.getEnabledProtocols().contains(SigningProtocol.TSP), "TSP protocol should be enabled when linked to the profile");
        }

        @Test
        void entity_returnsCorrectEntity() throws NotFoundException {
            // given
            SigningProfileDto existingProfile = defaultTimestampingProfile;
            SecuredUUID existingProfileUuid = SecuredUUID.fromString(existingProfile.getUuid());

            // when
            SigningProfile entity = signingProfileService.getSigningProfileEntity(existingProfileUuid);

            // then
            assertNotNull(entity);
            assertEquals(existingProfile.getUuid(), entity.getUuid().toString());
            assertEquals(existingProfile.getName(), entity.getName());
        }
    }

    @Nested
    class FindAllNamesTests {

        @Test
        void returnsExistingNames() {
            // when
            List<String> names = signingProfileService.findAllNames();

            // then
            assertNotNull(names);
            assertEquals(5, names.size());
            assertTrue(names.contains(defaultDelegatedSigningProfile.getName()));
            assertTrue(names.contains(defaultManagedStaticKeySigningProfile.getName()));
            assertTrue(names.contains(defaultContentSigningProfile.getName()));
            assertTrue(names.contains(defaultTimestampingProfile.getName()));
            assertTrue(names.contains(defaultRawSigningProfile.getName()));
        }
    }

    @Nested
    class CreateTests {

        @Test
        void delegatedScheme_rawWorkflow_setsExpectedAttributes() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("ct-delegated-raw")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .build()
            );
            SigningProfileDto getDto = signingProfileService.getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-delegated-raw", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            DelegatedSigningDto scheme = assertInstanceOf(DelegatedSigningDto.class, createdProfile.getSigningScheme());
            assertEquals(signerConnector.getUuid(), scheme.getConnector().getUuid());

            assertInstanceOf(RawSigningWorkflowDto.class, createdProfile.getWorkflow());
        }

        @Test
        void delegatedScheme_contentSigningWorkflow_setsExpectedAttributes() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("ct-delegated-content")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withContentSigning(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                            .build()
            );
            SigningProfileDto getDto = signingProfileService.getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-delegated-content", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            DelegatedSigningDto scheme = assertInstanceOf(DelegatedSigningDto.class, createdProfile.getSigningScheme());
            assertEquals(signerConnector.getUuid(), scheme.getConnector().getUuid());

            ContentSigningWorkflowDto workflow = assertInstanceOf(ContentSigningWorkflowDto.class, createdProfile.getWorkflow());
            assertEquals(contentSigningFormatterConnector.getUuid(), workflow.getSignatureFormatterConnector().getUuid());
        }

        @Test
        void delegatedScheme_timestampingWorkflow_setsExpectedAttributes() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("ct-delegated-timestamping")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                    .withDefaultPolicyId("1.2.3.4.5")
                                    .withAllowedPolicyIds(List.of("1.2.3.4.5", "1.2.3.4.6"))
                                    .withAllowedDigestAlgorithms(List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_384))
                                    .withQualifiedTimestamp(false)
                                    .withValidateTokenSignature(true)
                                    .build())
                            .build()
            );
            SigningProfileDto getDto = signingProfileService.getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-delegated-timestamping", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            DelegatedSigningDto scheme = assertInstanceOf(DelegatedSigningDto.class, createdProfile.getSigningScheme());
            assertEquals(signerConnector.getUuid(), scheme.getConnector().getUuid());

            TimestampingWorkflowDto workflow = assertInstanceOf(TimestampingWorkflowDto.class, createdProfile.getWorkflow());
            assertEquals(timestampingFormatterConnector.getUuid(), workflow.getSignatureFormatterConnector().getUuid());
            assertEquals("1.2.3.4.5", workflow.getDefaultPolicyId());
            assertEquals(List.of("1.2.3.4.5", "1.2.3.4.6"), workflow.getAllowedPolicyIds());
            assertEquals(List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_384), workflow.getAllowedDigestAlgorithms());
            assertFalse(workflow.getQualifiedTimestamp());
            assertTrue(workflow.getValidateTokenSignature());
        }

        @Test
        void staticKeyManagedScheme_rawWorkflow_setsExpectedAttributes() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("ct-static-raw")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withRawSigning()
                            .build()
            );
            SigningProfileDto getDto = signingProfileService.getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-static-raw", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            StaticKeyManagedSigningDto scheme = assertInstanceOf(StaticKeyManagedSigningDto.class, createdProfile.getSigningScheme());
            assertEquals(defaultSigningCertificate.getUuid(), scheme.getCertificate().getUuid());
            assertFalse(scheme.getSigningOperationAttributes().isEmpty());

            assertInstanceOf(RawSigningWorkflowDto.class, createdProfile.getWorkflow());
        }

        @Test
        void staticKeyManagedScheme_contentSigningWorkflow_setsExpectedAttributes() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("ct-static-content")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withContentSigning(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                            .build()
            );
            SigningProfileDto getDto = signingProfileService.getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-static-content", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            StaticKeyManagedSigningDto scheme = assertInstanceOf(StaticKeyManagedSigningDto.class, createdProfile.getSigningScheme());
            assertEquals(defaultSigningCertificate.getUuid(), scheme.getCertificate().getUuid());
            assertFalse(scheme.getSigningOperationAttributes().isEmpty());

            ContentSigningWorkflowDto workflow = assertInstanceOf(ContentSigningWorkflowDto.class, createdProfile.getWorkflow());
            assertEquals(contentSigningFormatterConnector.getUuid(), workflow.getSignatureFormatterConnector().getUuid());
        }

        @Test
        void staticKeyManagedScheme_timestampingWorkflow_setsExpectedAttributes() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("ct-static-timestamping")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withTimestamping(UUID.fromString(timestampingFormatterConnector.getUuid()))
                            .build()
            );
            SigningProfileDto getDto = signingProfileService.getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-static-timestamping", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            StaticKeyManagedSigningDto scheme = assertInstanceOf(StaticKeyManagedSigningDto.class, createdProfile.getSigningScheme());
            assertEquals(defaultSigningCertificate.getUuid(), scheme.getCertificate().getUuid());
            assertFalse(scheme.getSigningOperationAttributes().isEmpty());

            TimestampingWorkflowDto workflow = assertInstanceOf(TimestampingWorkflowDto.class, createdProfile.getWorkflow());
            assertEquals(timestampingFormatterConnector.getUuid(), workflow.getSignatureFormatterConnector().getUuid());
        }

        @Test
        void staticKeyManaged_incompleteChain_throwsValidationException() throws Exception {
            // given: a certificate whose chain cannot be verified (issuing CA is not in the inventory)
            Certificate incompleteChainCert = testCertificateAuthority.issueUntrustedCertificate();

            // when
            Executable createProfile = () -> signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("incomplete-chain-profile")
                            .withStaticKeyManagedSigning(incompleteChainCert.getUuid())
                            .withRawSigning()
                            .build());

            // then
            assertThrows(ValidationException.class, createProfile,
                    "createSigningProfile must reject a certificate whose chain is incomplete");
        }
    }

    @Nested
    class UpdateTests {

        @Test
        void update_schemeFromStaticKeyManagedToDelegated() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile with static-key-managed scheme
            SigningProfileDto profile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("scheme-change-profile")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withRawSigning()
                            .build()
            );
            SecuredUUID profileUuid = SecuredUUID.fromString(profile.getUuid());
            assertInstanceOf(StaticKeyManagedSigningDto.class, profile.getSigningScheme());

            // when: update to delegated scheme
            SigningProfileDto updated = signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(profile)
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build()
            );

            // then
            DelegatedSigningDto scheme = assertInstanceOf(DelegatedSigningDto.class, updated.getSigningScheme());
            assertEquals(signerConnector.getUuid(), scheme.getConnector().getUuid());
        }

        @Test
        void update_workflowFromRawToContentSigning() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile with RAW workflow
            SigningProfileDto profile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("workflow-raw-to-content")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .build()
            );
            SecuredUUID profileUuid = SecuredUUID.fromString(profile.getUuid());
            assertInstanceOf(RawSigningWorkflowDto.class, profile.getWorkflow());

            // when: update to content-signing workflow
            SigningProfileDto updated = signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(profile)
                            .withContentSigning(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                            .build()
            );

            // then
            ContentSigningWorkflowDto workflow = assertInstanceOf(ContentSigningWorkflowDto.class, updated.getWorkflow());
            assertEquals(contentSigningFormatterConnector.getUuid(), workflow.getSignatureFormatterConnector().getUuid());
        }

        @Test
        void update_workflowFromRawToTimestamping() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile with RAW workflow backed by a timestamping-eligible certificate
            SigningProfileDto profile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("workflow-raw-to-timestamping")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withRawSigning()
                            .build()
            );
            SecuredUUID profileUuid = SecuredUUID.fromString(profile.getUuid());
            assertInstanceOf(RawSigningWorkflowDto.class, profile.getWorkflow());

            // when: update to timestamping workflow
            SigningProfileDto updated = signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(profile)
                            .withTimestamping(UUID.fromString(timestampingFormatterConnector.getUuid()))
                            .build()
            );

            // then
            TimestampingWorkflowDto workflow = assertInstanceOf(TimestampingWorkflowDto.class, updated.getWorkflow());
            assertEquals(timestampingFormatterConnector.getUuid(), workflow.getSignatureFormatterConnector().getUuid());
        }

        @Test
        void signingProfileCanBeUpdated() throws Exception {
            // given
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            Certificate qualifiedCert = testCertificateAuthority.createTrustedCa("CN=Qualified Root CA")
                    .issueQualifiedTimestampingCertificate(keyPair, "CN=Test Qualified TSA");

            // when
            signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(defaultTimestampingProfile)
                            .withName("updated-timestamping-profile")
                            .withDescription("Updated description for timestamping profile")
                            .withStaticKeyManagedSigning(qualifiedCert.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                    .withDefaultPolicyId("1.2.3.4.5")
                                    .withAllowedPolicyIds(List.of("1.2.3.4.5", "1.2.3.4.6"))
                                    .withAllowedDigestAlgorithms(List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_384))
                                    .withQualifiedTimestamp(true)
                                    .withValidateTokenSignature(true)
                                    .build())
                            .build()
            );

            // then
            SigningProfileDto updated = signingProfileService.getSigningProfile(profileUuid, null);
            assertEquals("updated-timestamping-profile", updated.getName());
            assertEquals("Updated description for timestamping profile", updated.getDescription());

            TimestampingWorkflowDto workflow = assertInstanceOf(TimestampingWorkflowDto.class, updated.getWorkflow());
            assertEquals(timestampingFormatterConnector.getUuid(), workflow.getSignatureFormatterConnector().getUuid());
            assertEquals("1.2.3.4.5", workflow.getDefaultPolicyId());
            assertEquals(List.of("1.2.3.4.5", "1.2.3.4.6"), workflow.getAllowedPolicyIds());
            assertEquals(List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_384), workflow.getAllowedDigestAlgorithms());
            assertTrue(workflow.getQualifiedTimestamp());
            assertTrue(workflow.getValidateTokenSignature());
        }

        @Test
        void withSigningRecordsOnCurrentVersion_bumpsVersion()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a signing record linked to version 1
            createSigningRecordFor(defaultDelegatedSigningProfile);
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());

            // when
            SigningProfileDto dto = signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                            .withName("profile-with-bump")
                            .build()
            );

            // then
            assertEquals(2, dto.getVersion());
            assertEquals(2, signingProfileService.getSigningProfile(profileUuid, null).getVersion());
            assertNotNull(signingProfileService.getSigningProfile(profileUuid, 2),
                    "Version 2 snapshot should be created after bump");
        }


        @Test
        void withoutSigningRecords_overridesCurrentVersion()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: no signing records linked to version 1
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());

            // when
            SigningProfileDto dto = signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                            .withName("profile-without-bump")
                            .build()
            );

            // then: version stays at 1 — no bump because no signing records reference it
            assertEquals(1, dto.getVersion());
            assertEquals(1, signingProfileService.getSigningProfile(profileUuid, null).getVersion());
            assertThrows(NotFoundException.class,
                    () -> signingProfileService.getSigningProfile(profileUuid, 2),
                    "No version 2 snapshot should exist when no signing record was present");
        }

        @Test
        void withSigningRecordsOnFirstVersion_firstUpdateBumps_secondUpdateOverwritesLatest()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a signing record linked to version 1
            createSigningRecordFor(defaultDelegatedSigningProfile);
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());

            // when: first update — signing record on v1 forces a version bump
            signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                            .withName("profile-after-first-update")
                            .build()
            );
            assertEquals(2, signingProfileService.getSigningProfile(profileUuid, null).getVersion());

            // when: second update — no signing records on v2, so it is overwritten in-place
            SigningProfileDto dto = signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                            .withName("profile-after-second-update")
                            .build()
            );

            // then: version stays at 2; no version 3 snapshot is created
            assertEquals(2, dto.getVersion());
            assertEquals("profile-after-second-update", signingProfileService.getSigningProfile(profileUuid, null).getName());
            assertThrows(NotFoundException.class,
                    () -> signingProfileService.getSigningProfile(profileUuid, 3),
                    "No version 3 snapshot should exist when v2 had no signing records");
        }

        @Test
        void versionBump_workflowFormatterAttributesDifferBetweenVersions()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: stub the formatter connector to expose a single configurable attribute
            UUID formatterAttrUuid = UUID.fromString("11111111-2222-3333-4444-555555555555");
            String formatterAttrName = "data_testPolicy";
            timestampingFormatterMock.stubFormatterAttributeDefinition(formatterAttrUuid, formatterAttrName, true);

            SigningProfileDto v1Profile = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("formatter-attrs-versioned")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                    .withSignatureFormatterConnectorAttributes(List.of(
                                            aStringAttribute(formatterAttrUuid, formatterAttrName, "policy-v1")))
                                    .build())
                            .build()
            );
            SecuredUUID profileUuid = SecuredUUID.fromString(v1Profile.getUuid());
            createSigningRecordFor(v1Profile);

            // when: bump to v2 with a different attribute value
            signingProfileService.updateSigningProfile(
                    profileUuid,
                    aSigningProfileRequestFromExistingProfile(v1Profile)
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                    .withSignatureFormatterConnectorAttributes(List.of(
                                            aStringAttribute(formatterAttrUuid, formatterAttrName, "policy-v2")))
                                    .build())
                            .build()
            );

            // then: each version exposes its own formatter attribute value
            TimestampingWorkflowDto v1Workflow = assertInstanceOf(TimestampingWorkflowDto.class,
                    signingProfileService.getSigningProfile(profileUuid, 1).getWorkflow());
            TimestampingWorkflowDto v2Workflow = assertInstanceOf(TimestampingWorkflowDto.class,
                    signingProfileService.getSigningProfile(profileUuid, 2).getWorkflow());

            assertEquals("policy-v1",
                    extractStringAttrValue(v1Workflow.getSignatureFormatterConnectorAttributes(), formatterAttrName));
            assertEquals("policy-v2",
                    extractStringAttrValue(v2Workflow.getSignatureFormatterConnectorAttributes(), formatterAttrName));
        }
    }

    @Nested
    class DeleteTests {

        @Test
        void removesEntityFromDatabase() throws NotFoundException {
            // given: savedProfile from setUp
            SecuredUUID savedProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());

            // when
            signingProfileService.deleteSigningProfile(savedProfileUuid);

            // then
            Executable getDeletedProfile = () -> signingProfileService.getSigningProfile(savedProfileUuid, null);
            assertThrows(NotFoundException.class, getDeletedProfile);
        }

        @Test
        void usedAsDefaultInTspProfile_throwsValidationExceptionWithTspName()
                throws AlreadyExistException, AttributeException, NotFoundException {
            // given: a TSP profile that references a signing profile as its default
            SecuredUUID timestampingProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            tspProfileService.createTspProfile(
                    aTspProfileRequest()
                            .withName("expected-tsp-name")
                            .withDefaultSigningProfile(timestampingProfileUuid.getValue())
                            .build()
            );


            // when: delete the signing profile
            Executable deleteProfile = () -> signingProfileService.deleteSigningProfile(timestampingProfileUuid);

            // then: an exception is thrown, an error message names the blocking TSP profile, and profile is not removed
            ValidationException ex = assertThrows(ValidationException.class, deleteProfile);
            String message = firstErrorMessage(ex);
            assertTrue(message.contains("expected-tsp-name"),
                    "Error message should contain the TSP profile name, got: " + message);
            assertDoesNotThrow(() -> signingProfileService.getSigningProfile(timestampingProfileUuid, null),
                    "Profile must still exist after failed delete");
        }

        @Test
        void withSigningRecords_throwsValidationException() {
            // given: a signing profile that has a signing record
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
            createSigningRecordFor(defaultDelegatedSigningProfile);

            // when: delete the signing profile
            Executable deleteProfile = () -> signingProfileService.deleteSigningProfile(profileUuid);

            // then: delete is rejected and the profile is left intact
            ValidationException ex = assertThrows(ValidationException.class, deleteProfile);
            String message = firstErrorMessage(ex);
            assertTrue(message.contains("default-delegated-signing-profile"),
                    "Error message should contain the signing profile");
            assertTrue(message.contains("it has signing records"),
                    "Error message should contain information about existing signing records");
            assertDoesNotThrow(() -> signingProfileService.getSigningProfile(profileUuid, null),
                    "Profile must still exist after failed delete");
        }

        @Nested
        class BulkDelete {

            @Test
            void removesAllEntities() {
                // given: an existing signing profiles
                SecuredUUID firstUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
                SecuredUUID secondUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());

                // when
                List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(
                        List.of(firstUuid, secondUuid));

                // then
                assertNotNull(messages);
                assertTrue(messages.isEmpty(), "Expected no errors but got: " + messages);
                assertThrows(NotFoundException.class, () -> signingProfileService.getSigningProfile(firstUuid, null));
                assertThrows(NotFoundException.class, () -> signingProfileService.getSigningProfile(secondUuid, null));
            }

            @Test
            void withSigningRecords_returnsErrorAndLeavesBlockedProfileIntact() {
                // given: the blocked signing profile has a signing record; the second has none
                createSigningRecordFor(defaultDelegatedSigningProfile);
                SecuredUUID blockedProfileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
                SecuredUUID notBlockedProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());

                // when
                List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(
                        List.of(blockedProfileUuid, notBlockedProfileUuid)
                );

                // then: defaultDelegatedSigningProfile blocked due to signing record, second deleted
                assertFalse(messages.isEmpty());
                assertTrue(messages.stream().anyMatch(m -> blockedProfileUuid.toString().equals(m.getUuid())));

                // and then: a blocked signing profile must still exist
                assertDoesNotThrow(() -> signingProfileService.getSigningProfile(blockedProfileUuid, null),
                        "Blocked profile must still exist");

                // and then: the second profile must be deleted
                assertThrows(NotFoundException.class, () -> signingProfileService.getSigningProfile(notBlockedProfileUuid, null));
            }

            @Test
            void emptyList_returnsEmptyMessages() {
                // given: an empty list of UUIDs

                // when
                List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(List.of());

                // then
                assertNotNull(messages);
                assertTrue(messages.isEmpty(), "Bulk delete of empty list should return no error messages");
            }

            @Test
            void withNonExistentUuid_silentlyIgnoresUnknown() {
                // given: a list with one unknown UUID and one valid UUID
                SecuredUUID knownProfileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
                SecuredUUID unknownProfileUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000099");

                // when
                List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(
                        List.of(unknownProfileUuid, knownProfileUuid));

                // then
                assertFalse(messages.isEmpty(), "An error message should be returned for the non-existent UUID");
                assertTrue(messages.stream().anyMatch(m -> unknownProfileUuid.toString().equals(m.getUuid())));
                assertThrows(NotFoundException.class, () -> signingProfileService.getSigningProfile(knownProfileUuid,
                        null));
            }

            @Test
            void withTspProfileDependency_returnsErrorAndLeavesBlockedProfileIntact()
                    throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
                // given: defaultTimestampingProfile is the default of a TSP profile (blocked), plus an unblocked second profile
                SecuredUUID blockedUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
                tspProfileService.createTspProfile(
                        aTspProfileRequest()
                                .withName("blocking-tsp")
                                .withDefaultSigningProfile(UUID.fromString(defaultTimestampingProfile.getUuid()))
                                .build()
                );
                SigningProfileDto second = signingProfileService.createSigningProfile(
                        aSigningProfileRequest()
                                .withName("unblocked-profile")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withRawSigning()
                                .build()
                );
                SecuredUUID secondUuid = SecuredUUID.fromString(second.getUuid());

                // when
                List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(
                        List.of(blockedUuid, secondUuid));

                // then: defaultTimestampingProfile blocked due to TSP dependency, second deleted
                assertFalse(messages.isEmpty(), "Expected an error message for the blocked profile");
                assertTrue(messages.stream().anyMatch(m -> defaultTimestampingProfile.getUuid().equals(m.getUuid())),
                        "Error message should reference the blocked profile UUID");
                assertDoesNotThrow(() -> signingProfileService.getSigningProfile(blockedUuid, null),
                        "Blocked profile must still exist");
                assertThrows(NotFoundException.class, () -> signingProfileService.getSigningProfile(secondUuid, null),
                        "Unblocked profile must be deleted");
            }
        }

        @Nested
        class EnableDisable {

            @Test
            void enable_afterCreate_persistsState() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
                // given: a newly created profile (disabled by default)
                SigningProfileDto dto = signingProfileService.createSigningProfile(
                        aSigningProfileRequest()
                                .withName("profile-to-enable")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withRawSigning()
                                .build()
                );
                assertFalse(dto.isEnabled(), "Profiles must be created in a disabled state");
                SecuredUUID profileUuid = SecuredUUID.fromString(dto.getUuid());

                // when
                signingProfileService.enableSigningProfile(profileUuid);

                // then
                assertTrue(signingProfileService.getSigningProfile(profileUuid, null).isEnabled());
            }

            @Test
            void enable_alreadyEnabled_isIdempotent() throws NotFoundException {
                // given: profile already enabled
                SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
                signingProfileService.enableSigningProfile(profileUuid);

                // when: enable again — should be idempotent
                signingProfileService.enableSigningProfile(profileUuid);

                // then
                assertTrue(signingProfileService.getSigningProfile(profileUuid, null).isEnabled(),
                        "Profile should remain enabled after enabling an already-enabled profile");
            }


            @Test
            void disable_setsEnabledFalse() throws NotFoundException {
                // given: profile forced to enabled state
                SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
                signingProfileService.enableSigningProfile(profileUuid);

                // when
                signingProfileService.disableSigningProfile(profileUuid);

                // then
                assertFalse(signingProfileService.getSigningProfile(profileUuid, null).isEnabled());
            }

            @Test
            void disable_alreadyDisabled_isIdempotent() throws NotFoundException {
                // given: defaultDelegatedSigningProfile is already disabled (enabled = false from setUp)
                SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
                assertFalse(defaultDelegatedSigningProfile.isEnabled());

                // when: disable again — should be idempotent
                signingProfileService.disableSigningProfile(profileUuid);

                // then
                assertFalse(signingProfileService.getSigningProfile(profileUuid, null).isEnabled(),
                        "Profile should remain disabled after disabling an already-disabled profile");
            }

            @Test
            void bulkEnable_multipleProfiles() throws NotFoundException {
                // given: defaultDelegatedSigningProfile from setUp plus two additional profiles (all disabled)
                SecuredUUID firstUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
                SecuredUUID secondUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
                SecuredUUID thirdUuid = SecuredUUID.fromString(defaultManagedStaticKeySigningProfile.getUuid());

                assertFalse(defaultDelegatedSigningProfile.isEnabled());
                assertFalse(defaultTimestampingProfile.isEnabled());
                assertFalse(defaultManagedStaticKeySigningProfile.isEnabled());

                // when
                signingProfileService.bulkEnableSigningProfiles(List.of(firstUuid, secondUuid, thirdUuid));

                // then
                assertTrue(signingProfileService.getSigningProfile(firstUuid, null).isEnabled());
                assertTrue(signingProfileService.getSigningProfile(secondUuid, null).isEnabled());
                assertTrue(signingProfileService.getSigningProfile(thirdUuid, null).isEnabled());
            }

            @Test
            void bulkDisable_multipleProfiles() throws NotFoundException {
                // given: two additional enabled profiles
                SecuredUUID firstUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
                SecuredUUID secondUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
                SecuredUUID thirdUuid = SecuredUUID.fromString(defaultManagedStaticKeySigningProfile.getUuid());
                signingProfileService.bulkEnableSigningProfiles(List.of(firstUuid, secondUuid, thirdUuid));

                // when
                signingProfileService.bulkDisableSigningProfiles(List.of(secondUuid, thirdUuid));

                // then
                assertTrue(signingProfileService.getSigningProfile(firstUuid, null).isEnabled());
                assertFalse(signingProfileService.getSigningProfile(secondUuid, null).isEnabled());
                assertFalse(signingProfileService.getSigningProfile(thirdUuid, null).isEnabled());
            }

            @Test
            void bulkEnable_withNonExistentUuid_silentlyIgnores() throws NotFoundException {
                // given: a list with one unknown UUID and defaultDelegatedSigningProfile
                SecuredUUID unknownUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000099");
                SecuredUUID knownUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());

                // when
                List<BulkActionMessageDto> messages = signingProfileService.bulkEnableSigningProfiles(
                        List.of(unknownUuid, knownUuid));

                // then: the unknown UUID surfaces as an error; the known profile is still enabled
                assertFalse(messages.isEmpty(), "An error message should be returned for the non-existent UUID");
                assertTrue(messages.stream().anyMatch(m -> unknownUuid.toString().equals(m.getUuid())));
                assertTrue(signingProfileService.getSigningProfile(knownUuid, null).isEnabled(),
                        "The known profile should be enabled even when the list contains an unknown UUID");
            }

            @Test
            void bulkDisable_withNonExistentUuid_silentlyIgnores() throws NotFoundException {
                // given: defaultDelegatedSigningProfile forced to enabled state, and one unknown UUID in the list
                SecuredUUID knownUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
                signingProfileService.enableSigningProfile(knownUuid);
                SecuredUUID unknownUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000099");

                // when
                List<BulkActionMessageDto> messages = signingProfileService.bulkDisableSigningProfiles(
                        List.of(unknownUuid, knownUuid));

                // then
                assertFalse(messages.isEmpty(), "An error message should be returned for the non-existent UUID");
                assertTrue(messages.stream().anyMatch(m -> unknownUuid.toString().equals(m.getUuid())));
                assertFalse(signingProfileService.getSigningProfile(knownUuid, null).isEnabled(),
                        "The known profile should be disabled even when the list contains an unknown UUID");
            }

        }
    }

    @Nested
    class TspProtocol {

        @Test
        void activate_setsLinkOnSigningProfile() throws AlreadyExistException, AttributeException, NotFoundException {
            // given: a TIMESTAMPING signing profile and a TSP profile
            SecuredUUID timestampingProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            TspProfileDto tsp = tspProfileService.createTspProfile(
                    aTspProfileRequest().withName("test-tsp-profile").build());
            SecuredUUID tspUuid = SecuredUUID.fromString(tsp.getUuid());

            // when
            TspActivationDetailDto activationDto = signingProfileService.activateTsp(
                    timestampingProfileUuid, tspUuid);

            // then
            assertTrue(activationDto.isAvailable());
            assertNotNull(activationDto.getSigningUrl());
            assertTrue(signingProfileService.getSigningProfile(timestampingProfileUuid, null)
                    .getEnabledProtocols().contains(SigningProtocol.TSP));
        }

        @Test
        void activate_tspProfileNotFound_throwsNotFoundException() {
            // given: a signing profile, and a TSP UUID that does not exist
            SecuredUUID timestampingProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            SecuredUUID nonExistentTspUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000002");

            // when
            Executable activate = () -> signingProfileService.activateTsp(timestampingProfileUuid, nonExistentTspUuid);

            // then
            assertThrows(NotFoundException.class, activate);
        }

        @Test
        void activate_replacesExistingLink() throws AlreadyExistException, AttributeException, NotFoundException {
            // given: a signing profile linked to tsp1
            SecuredUUID timestampingProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            TspProfileDto tsp1 = tspProfileService.createTspProfile(aTspProfileRequest().withName("tsp-profile-1").build());
            TspProfileDto tsp2 = tspProfileService.createTspProfile(aTspProfileRequest().withName("tsp-profile-2").build());
            SecuredUUID tsp1Uuid = SecuredUUID.fromString(tsp1.getUuid());
            SecuredUUID tsp2Uuid = SecuredUUID.fromString(tsp2.getUuid());
            signingProfileService.activateTsp(timestampingProfileUuid, tsp1Uuid);

            // when: replace with tsp2
            signingProfileService.activateTsp(timestampingProfileUuid, tsp2Uuid);

            // then: tsp2 is the active TSP (signing URL references its UUID, not tsp1's)
            assertTrue(signingProfileService.getSigningProfile(timestampingProfileUuid, null)
                            .getEnabledProtocols().contains(SigningProtocol.TSP),
                    "TSP should remain active after replacing the linked TSP profile");
        }

        @Test
        void activate_rawWorkflow_throwsValidationException() {
            // given: a signing profile with RAW_SIGNING workflow (does not support TSP)
            SecuredUUID rawSingingProfileUuid = SecuredUUID.fromString(defaultRawSigningProfile.getUuid());
            SecuredUUID tspUuid = SecuredUUID.fromString(defaultTspProtocol.getUuid());

            // when
            Executable activate = () -> signingProfileService.activateTsp(rawSingingProfileUuid, tspUuid);

            // then
            assertThrows(ValidationException.class, activate);
        }

        @Test
        void activate_contentSigningWorkflow_throwsValidationException() {
            // given: a signing profile with CONTENT_SIGNING workflow (does not support TSP)
            SecuredUUID contentSigningProfileUuid = SecuredUUID.fromString(defaultContentSigningProfile.getUuid());
            SecuredUUID tspUuid = SecuredUUID.fromString(defaultTspProtocol.getUuid());

            // when
            Executable activate = () -> signingProfileService.activateTsp(contentSigningProfileUuid, tspUuid);

            // then
            assertThrows(ValidationException.class, activate);
        }

        @Test
        void deactivate_removesFromEnabledProtocols() throws NotFoundException {
            // given: a TIMESTAMPING signing profile linked to a TSP profile
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            signingProfileService.activateTsp(profileUuid, SecuredUUID.fromString(defaultTspProtocol.getUuid()));
            assertTrue(signingProfileService.getSigningProfile(profileUuid, null)
                    .getEnabledProtocols().contains(SigningProtocol.TSP));

            // when
            signingProfileService.deactivateTsp(profileUuid);

            // then: TSP is no longer in enabled protocols
            assertFalse(signingProfileService.getSigningProfile(profileUuid, null)
                            .getEnabledProtocols().contains(SigningProtocol.TSP),
                    "TSP should be removed from enabledProtocols after deactivation");
        }

        @Test
        void deactivate_noLinkExists_isIdempotent() throws NotFoundException {
            // given: signing profile has no TSP link
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            assertFalse(defaultTimestampingProfile.getEnabledProtocols().contains(SigningProtocol.TSP));

            // when
            Executable deactivate = () -> signingProfileService.deactivateTsp(profileUuid);

            assertDoesNotThrow(deactivate, "deactivateTsp must not throw when no TSP is currently linked");
            SigningProfileDto updatedProfile = signingProfileService.getSigningProfile(profileUuid, null);
            assertFalse(updatedProfile.getEnabledProtocols().contains(SigningProtocol.TSP),
                    "TSP should still be absent after a no-op deactivation");
        }
    }

    @Nested
    class SigningOpAttrs {

        @Test
        void create_staticKey_attributesPersistedAndReturned()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            var signingAttrs = rsaSignatureAttributes()
                    .withScheme(RsaSignatureScheme.PKCS1_v1_5)
                    .withDigest(DigestAlgorithm.SHA_256)
                    .build();
            SigningProfileRequestDto request = aSigningProfileRequest()
                    .withName("static-key-with-sign-attrs")
                    .withDescription("Profile with signing operation attributes")
                    .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(), signingAttrs)
                    .withRawSigning()
                    .build();

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);


            // then: the returned DTO must expose the persisted signing operation attributes
            StaticKeyManagedSigningDto schemeDto = assertInstanceOf(StaticKeyManagedSigningDto.class, dto.getSigningScheme());
            List<ResponseAttribute> signAttrs = schemeDto.getSigningOperationAttributes();
            assertNotNull(signAttrs);
            assertEquals(2, signAttrs.size(), "Expected exactly RSA scheme and digest attributes");

            assertEquals(RsaSignatureScheme.PKCS1_v1_5.getCode(),
                    extractStringAttrValue(signAttrs, RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME),
                    "RSA signature scheme value should match PKCS1_v1_5");
            assertEquals(DigestAlgorithm.SHA_256.getCode(),
                    extractStringAttrValue(signAttrs, RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST),
                    "Digest algorithm value should match SHA_256");

            // then: the dto retuned by update should match the one obtained by get (the persisted version)
            SigningProfileDto persisted = signingProfileService.getSigningProfile(SecuredUUID.fromString(dto.getUuid()), null);
            assertEquals(dto, persisted);
        }

        @Test
        void update_staticKey_attributesReplacedOnUpdate()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a static-key profile created with PKCS1_v1_5/SHA_256 signing attributes
            SigningProfileDto created = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("static-key-update-sign-attrs")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                    rsaSignatureAttributes()
                                            .withScheme(RsaSignatureScheme.PKCS1_v1_5)
                                            .withDigest(DigestAlgorithm.SHA_256)
                                            .build())
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when: update to PSS/SHA_384
            SigningProfileDto updated = signingProfileService.updateSigningProfile(profileUuid,
                    aSigningProfileRequestFromExistingProfile(created)
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                    rsaSignatureAttributes()
                                            .withScheme(RsaSignatureScheme.PSS)
                                            .withDigest(DigestAlgorithm.SHA_384)
                                            .build())
                            .build());

            // then: both attributes must reflect the new values, not the old ones
            StaticKeyManagedSigningDto schemeDto = assertInstanceOf(StaticKeyManagedSigningDto.class, updated.getSigningScheme());
            List<ResponseAttribute> signAttrs = schemeDto.getSigningOperationAttributes();
            assertEquals(RsaSignatureScheme.PSS.getCode(),
                    extractStringAttrValue(signAttrs, RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME),
                    "RSA signature scheme should be replaced with PSS");
            assertEquals(DigestAlgorithm.SHA_384.getCode(),
                    extractStringAttrValue(signAttrs, RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST),
                    "Digest algorithm should be replaced with SHA_384");
        }

        @Test
        void update_schemeChangedToNonStaticKey_signingAttributesCleared()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a STATIC_KEY profile with signing operation attributes
            SigningProfileDto created = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("static-key-to-delegated")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                    rsaSignatureAttributes().withScheme(RsaSignatureScheme.PKCS1_v1_5).withDigest(DigestAlgorithm.SHA_256).build())
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when: switch to DELEGATED
            SigningProfileDto updated = signingProfileService.updateSigningProfile(profileUuid,
                    aSigningProfileRequestFromExistingProfile(created)
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            // then: the returned DTO has a delegated scheme with no signing operation attributes
            assertInstanceOf(DelegatedSigningDto.class, updated.getSigningScheme());

            // and re-fetching confirms the scheme change persisted
            SigningProfileDto fetched = signingProfileService.getSigningProfile(profileUuid, null);
            assertInstanceOf(DelegatedSigningDto.class, fetched.getSigningScheme());

            // and the AttributeEngine holds no SIGN rows for this profile version (no stale engine data)
            List<ResponseAttribute> remaining = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()))
                            .operation(AttributeOperation.SIGN).version(1).build());
            assertTrue(remaining.isEmpty(),
                    "SIGN attributes should be cleared from the engine when scheme changes away from STATIC_KEY");

        }

        @Test
        void delete_profileNoLongerAccessible()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a static-key profile with signing operation attributes
            SigningProfileDto created = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("delete-clears-sign-attrs")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                    rsaSignatureAttributes().withScheme(RsaSignatureScheme.PSS).withDigest(DigestAlgorithm.SHA_256).build())
                            .withRawSigning()
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when
            signingProfileService.deleteSigningProfile(profileUuid);

            // then: the profile is gone — attributes are inaccessible along with it
            assertThrows(NotFoundException.class,
                    () -> signingProfileService.getSigningProfile(profileUuid, null));

            // and the AttributeEngine holds no SIGN rows for this profile version (no stale engine data)
            List<ResponseAttribute> remaining = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()))
                            .operation(AttributeOperation.SIGN).version(1).build());
            assertTrue(remaining.isEmpty(),
                    "SIGN attributes should be cleared from the engine when Signig Profile gets deleted");
        }

        @Test
        void getSpecificVersion_returnsVersionedAttributes()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: v1 with PSS/SHA_256, signing record locks v1 so the next update bumps to v2
            SigningProfileDto created = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("versioned-get-sign-attrs")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                    rsaSignatureAttributes().withScheme(RsaSignatureScheme.PSS).withDigest(DigestAlgorithm.SHA_256).build())
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());
            createSigningRecordFor(created);

            // when: bump to v2 with PKCS1_v1_5/SHA_384
            signingProfileService.updateSigningProfile(profileUuid,
                    aSigningProfileRequestFromExistingProfile(created)
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                    rsaSignatureAttributes().withScheme(RsaSignatureScheme.PKCS1_v1_5).withDigest(DigestAlgorithm.SHA_384).build())
                            .build());

            // then: each version returns its own attribute values through the DTO
            // v1
            StaticKeyManagedSigningDto v1Scheme = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    signingProfileService.getSigningProfile(profileUuid, 1).getSigningScheme());
            assertEquals(RsaSignatureScheme.PSS.getCode(),
                    extractStringAttrValue(v1Scheme.getSigningOperationAttributes(), RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME));
            assertEquals(DigestAlgorithm.SHA_256.getCode(),
                    extractStringAttrValue(v1Scheme.getSigningOperationAttributes(), RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST));
            // v2
            StaticKeyManagedSigningDto v2Scheme = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    signingProfileService.getSigningProfile(profileUuid, 2).getSigningScheme());
            assertEquals(RsaSignatureScheme.PKCS1_v1_5.getCode(),
                    extractStringAttrValue(v2Scheme.getSigningOperationAttributes(), RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME));
            assertEquals(DigestAlgorithm.SHA_384.getCode(),
                    extractStringAttrValue(v2Scheme.getSigningOperationAttributes(), RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST));

            // and: the engine holds separate rows for each version
            UUID profileUuidRaw = UUID.fromString(created.getUuid());
            assertFalse(attributeEngine.getObjectDataAttributesContent(
                            ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                                    .operation(AttributeOperation.SIGN).version(1).build()).isEmpty(),
                    "Engine must hold SIGN rows for version 1");
            assertFalse(attributeEngine.getObjectDataAttributesContent(
                            ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                                    .operation(AttributeOperation.SIGN).version(2).build()).isEmpty(),
                    "Engine must hold SIGN rows for version 2");
        }
    }

    @Nested
    class FormatterAttributes {

        @Test
        void create_contentSigning_attributesPersistedAndReturned()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: stub the content signing formatter to expose a single configurable attribute
            UUID attrUuid = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
            String attrName = "data_testFormatterAttr";
            contentSigningFormatterMock.stubFormatterAttributeDefinition(attrUuid, attrName);

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("doc-profile-with-formatter-attrs")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                                    .withSignatureFormatterConnectorAttributes(List.of(
                                            aStringAttribute(attrUuid, attrName, "testValue")))
                                    .build())
                            .build());

            // then: the attribute is returned in the DTO and its value matches what was sent
            ContentSigningWorkflowDto wfDto = assertInstanceOf(ContentSigningWorkflowDto.class, dto.getWorkflow());
            List<ResponseAttribute> attrs = wfDto.getSignatureFormatterConnectorAttributes();
            assertFalse(attrs.isEmpty(), "Formatter connector attributes should be populated after create");
            assertEquals("testValue", extractStringAttrValue(attrs, attrName));
        }

        @Test
        void update_contentSigningConnectorChanged_oldFormatterAttributesCleared()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: stub the existing content signing formatter connector with a specific attribute definition
            UUID attrUuid = UUID.fromString("11111111-2222-3333-4444-555555555556");
            String attrName = "data_formatterSwitchTest";
            contentSigningFormatterMock.stubFormatterAttributeDefinition(attrUuid, attrName);

            // and: a second content signing formatter connector (formatterB)
            ContentSigningFormatterMock formatterBMock = ContentSigningFormatterMock.start();
            formatterBMock.stubFormatterAttributeDefinition(attrUuid, attrName);
            ConnectorDetailDto formatterBConnector = connectorService.createConnector(
                    aV2ConnectorRequest()
                            .withName("content-signing-formatter-b")
                            .withUrl(formatterBMock.getUrl())
                            .build()
            );

            try {
                // and: a profile using formatterA (contentSigningFormatterConnector) with attribute "valueA"
                SigningProfileDto created = signingProfileService.createSigningProfile(
                        aSigningProfileRequest()
                                .withName("formatter-switch-test")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withContentSigning(aContentSigningWorkflow()
                                        .withSignatureFormatterConnector(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                                        .withSignatureFormatterConnectorAttributes(List.of(
                                                aStringAttribute(attrUuid, attrName, "valueA")))
                                        .build())
                                .build());
                SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());
                UUID profileUuidRaw = UUID.fromString(created.getUuid());

                // when: update to formatterB with attribute "valueB"
                signingProfileService.updateSigningProfile(profileUuid,
                        aSigningProfileRequestFromExistingProfile(created)
                                .withContentSigning(aContentSigningWorkflow()
                                        .withSignatureFormatterConnector(UUID.fromString(formatterBConnector.getUuid()))
                                        .withSignatureFormatterConnectorAttributes(List.of(
                                                aStringAttribute(attrUuid, attrName, "valueB")))
                                        .build())
                                .build());

                // then: formatterA's engine rows are gone (no stale attributes for the old connector)
                List<ResponseAttribute> oldAttrs = attributeEngine.getObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                                .connector(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                                .operation(AttributeOperation.WORKFLOW_FORMATTER).version(1).build());
                assertTrue(oldAttrs.isEmpty(),
                        "Attributes for the replaced formatter connector should be cleared from the engine");

                // then: formatterB's attributes are stored with the correct value
                List<ResponseAttribute> newAttrs = attributeEngine.getObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                                .connector(UUID.fromString(formatterBConnector.getUuid()))
                                .operation(AttributeOperation.WORKFLOW_FORMATTER).version(1).build());
                assertFalse(newAttrs.isEmpty(),
                        "Attributes for the new formatter connector should be persisted after the update");
                assertEquals("valueB", extractStringAttrValue(newAttrs, attrName));
            } finally {
                formatterBMock.stop();
            }
        }

        @Test
        void delete_removesFormatterAttributesFromEngine()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a content signing profile with a formatter attribute
            UUID attrUuid = UUID.fromString("cccccccc-dddd-eeee-ffff-000000000001");
            String attrName = "data_deleteFormatterAttr";
            contentSigningFormatterMock.stubFormatterAttributeDefinition(attrUuid, attrName);

            SigningProfileDto created = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("delete-clears-formatter-attrs")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                                    .withSignatureFormatterConnectorAttributes(List.of(
                                            aStringAttribute(attrUuid, attrName, "toDelete")))
                                    .build())
                            .build());
            UUID profileUuid = UUID.fromString(created.getUuid());

            // when
            signingProfileService.deleteSigningProfile(SecuredUUID.fromUUID(profileUuid));

            // then: no stale engine rows remain for the deleted profile
            List<ResponseAttribute> remaining = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                            .connector(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                            .operation(AttributeOperation.WORKFLOW_FORMATTER).version(1).build());
            assertTrue(remaining.isEmpty(),
                    "Formatter attributes should be cleared from the engine when the profile is deleted");
        }

    }

    @Nested
    class FormatterAttributeValidation {

        @Test
        void create_contentSigning_requiredAttributeMissing_throwsValidationException() {
            // given: the formatter connector advertises a required attribute
            UUID attrUuid = UUID.fromString("00000000-dead-beef-0002-000000000001");
            String attrName = "req_content_attr";
            contentSigningFormatterMock.stubFormatterAttributeDefinition(attrUuid, attrName, true);

            // when: create a profile omitting the required attribute
            Executable create = () -> signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("content-missing-required-attr")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                                    .build())
                            .build());

            // then
            assertThrows(ValidationException.class, create,
                    "createSigningProfile must reject a missing required formatter attribute");
        }

        @Test
        void create_timestamping_requiredAttributeMissing_throwsValidationException() {
            // given: the formatter connector advertises a required attribute
            UUID attrUuid = UUID.fromString("00000000-dead-beef-0002-000000000001");
            String attrName = "req_content_attr";
            timestampingFormatterMock.stubFormatterAttributeDefinition(attrUuid, attrName, true);

            // when: create a profile omitting the required attribute
            Executable create = () -> signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("timestamping-missing-required-attr")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(contentSigningFormatterConnector.getUuid()))
                                    .build())
                            .build());

            // then
            assertThrows(ValidationException.class, create,
                    "createSigningProfile must reject a missing required formatter attribute");
        }
    }

    @Nested
    class CustomAttributes {

        @BeforeEach
        void setUpCustomAttribute() {
            CustomAttributeV3 attrDef = new CustomAttributeV3();
            attrDef.setUuid(CUSTOM_ATTR_UUID);
            attrDef.setName(CUSTOM_ATTR_NAME);
            attrDef.setDescription("test custom attribute for signing profile");
            attrDef.setContentType(AttributeContentType.STRING);
            CustomAttributeProperties props = new CustomAttributeProperties();
            props.setReadOnly(false);
            props.setRequired(false);
            attrDef.setProperties(props);

            AttributeDefinition definition = new AttributeDefinition();
            definition.setUuid(UUID.fromString(CUSTOM_ATTR_UUID));
            definition.setName(CUSTOM_ATTR_NAME);
            definition.setAttributeUuid(UUID.fromString(CUSTOM_ATTR_UUID));
            definition.setContentType(AttributeContentType.STRING);
            definition.setLabel(CUSTOM_ATTR_NAME);
            definition.setType(AttributeType.CUSTOM);
            definition.setDefinition(attrDef);
            definition.setEnabled(true);
            definition.setVersion(3);
            attributeDefinitionRepository.save(definition);

            AttributeRelation relation = new AttributeRelation();
            relation.setResource(Resource.SIGNING_PROFILE);
            relation.setAttributeDefinitionUuid(definition.getUuid());
            attributeRelationRepository.save(relation);
        }

        @Test
        void create_withCustomAttributes_returnedInDto() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            RequestAttributeV3 customAttr = aCustomAttribute()
                    .withUuid(CUSTOM_ATTR_UUID)
                    .withName(CUSTOM_ATTR_NAME)
                    .withStringContent("profile-value-on-create")
                    .build();

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("profile-with-custom-attr")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .withCustomAttributes(List.of(customAttr))
                            .build());

            // then — DTO reflects the created value
            assertNotNull(dto.getCustomAttributes());
            assertFalse(dto.getCustomAttributes().isEmpty(),
                    "Custom attributes should be returned in the create DTO");
            assertEquals("profile-value-on-create",
                    ((ResponseAttributeV3) dto.getCustomAttributes().getFirst()).getContent().getFirst().getData());

            // and — attribute engine agrees with the DTO (no stale cache / divergence)
            List<ResponseAttribute> engineAttrs = attributeEngine.getObjectCustomAttributesContent(
                    Resource.SIGNING_PROFILE, UUID.fromString(dto.getUuid()));
            assertFalse(engineAttrs.isEmpty());
            assertEquals("profile-value-on-create",
                    ((ResponseAttributeV3) engineAttrs.getFirst()).getContent().getFirst().getData());
        }

        @Test
        void update_withCustomAttributes_returnedInDtoAndPersisted() throws AlreadyExistException, AttributeException,
                ConnectorException, NotFoundException {
            // given: a profile created with a custom attribute set to "initial-value"
            SigningProfileDto created = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("profile-update-custom-attr")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .withCustomAttributes(List.of(aCustomAttribute()
                                    .withUuid(CUSTOM_ATTR_UUID)
                                    .withName(CUSTOM_ATTR_NAME)
                                    .withStringContent("initial-value")
                                    .build()))
                            .build());

            // when: update with "updated-value"
            SigningProfileDto updated = signingProfileService.updateSigningProfile(
                    SecuredUUID.fromString(created.getUuid()),
                    aSigningProfileRequestFromExistingProfile(created)
                            .withCustomAttributes(List.of(aCustomAttribute()
                                    .withUuid(CUSTOM_ATTR_UUID)
                                    .withName(CUSTOM_ATTR_NAME)
                                    .withStringContent("updated-value")
                                    .build()))
                            .build());

            // then — DTO reflects the updated value
            assertNotNull(updated.getCustomAttributes());
            assertFalse(updated.getCustomAttributes().isEmpty());
            assertEquals("updated-value",
                    ((ResponseAttributeV3) updated.getCustomAttributes().getFirst()).getContent().getFirst().getData());

            // and — attribute engine agrees with the DTO (no stale cache / divergence)
            List<ResponseAttribute> engineAttrs = attributeEngine.getObjectCustomAttributesContent(
                    Resource.SIGNING_PROFILE, UUID.fromString(updated.getUuid()));
            assertFalse(engineAttrs.isEmpty());
            assertEquals("updated-value",
                    ((ResponseAttributeV3) engineAttrs.getFirst()).getContent().getFirst().getData());
        }

    }

    @Nested
    class NameUniqueness {

        @Test
        void create_duplicateName_throwsAlreadyExistException() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("duplicate-name")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            // when
            Executable createDuplicate = () -> signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("duplicate-name")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            // then
            assertThrows(AlreadyExistException.class, createDuplicate);
        }

        @Test
        void update_toExistingNameOfAnotherProfile_throwsAlreadyExistException() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("profile-alpha")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());
            SigningProfileDto beta = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("profile-beta")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            // when
            Executable updateToExistingName = () -> signingProfileService.updateSigningProfile(
                    SecuredUUID.fromString(beta.getUuid()),
                    aSigningProfileRequest()
                            .withName("profile-alpha")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            //then: renaming beta to alpha collides with the existing profile
            assertThrows(AlreadyExistException.class, updateToExistingName);
        }

        @Test
        void update_keepingSameName_succeeds() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            SigningProfileDto created = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("keep-same-name")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            // when
            SigningProfileDto updated = signingProfileService.updateSigningProfile(
                    SecuredUUID.fromString(created.getUuid()),
                    aSigningProfileRequest()
                            .withName("keep-same-name")
                            .withDescription("updated description")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            // then
            assertEquals("keep-same-name", updated.getName());
            assertEquals("updated description", updated.getDescription());
        }

        @Test
        void timestamping_staticKeyScheme_returnsTypedModelWithResolvedCertificate()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("ts-managed-model")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                    .build())
                            .build());

            // when
            SigningProfileModel<?, ?> model =
                    signingProfileService.getSigningProfileModel("ts-managed-model");

            // then
            assertInstanceOf(ManagedTimestampingWorkflow.class, model.workflow());
            assertInstanceOf(StaticKeyManagedSigning.class, model.signingScheme());
            StaticKeyManagedSigning schemeModel = (StaticKeyManagedSigning) model.signingScheme();
            assertEquals(defaultSigningCertificate.getUuid(), schemeModel.certificateUuid());
        }

        @Test
        void validationPropertiesRoundTrip()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("ts-managed-validation-props")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                    .withDefaultPolicyId("1.2.3.4.5")
                                    .withAllowedPolicyIds(List.of("1.2.3.4.5", "1.2.3.4.6"))
                                    .withAllowedDigestAlgorithms(List.of(DigestAlgorithm.SHA_256))
                                    .withValidateTokenSignature(true)
                                    .build())
                            .build());

            // when
            SigningProfileModel<?, ?> model =
                    signingProfileService.getSigningProfileModel("ts-managed-validation-props");

            // then
            assertInstanceOf(ManagedTimestampingWorkflow.class, model.workflow());
            ManagedTimestampingWorkflow wf = (ManagedTimestampingWorkflow) model.workflow();
            assertEquals("1.2.3.4.5", wf.defaultPolicyId());
            assertEquals(List.of("1.2.3.4.5", "1.2.3.4.6"), wf.allowedPolicyIds());
            assertEquals(List.of(DigestAlgorithm.SHA_256), wf.allowedDigestAlgorithms());
            assertTrue(wf.validateTokenSignature());
        }

        @Test
        void baseFieldsArePropagatedToModel()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            SigningProfileDto created = signingProfileService.createSigningProfile(
                    aSigningProfileRequest()
                            .withName("ts-managed-base-fields")
                            .withDescription("expected ts description")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                    .build())
                            .build());

            // when
            SigningProfileModel<?, ?> model =
                    signingProfileService.getSigningProfileModel("ts-managed-base-fields");

            // then
            assertEquals("ts-managed-base-fields", model.name());
            assertEquals("expected ts description", model.description());
            assertEquals(UUID.fromString(created.getUuid()), model.uuid());
            assertEquals(1, model.version());
            assertFalse(model.enabled());
        }

        @Nested
        class TimeQualityConfiguration {

            @Test
            void create_withTqcUuid_headerLinkedAndReturnedInDto()
                    throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
                // given
                TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                        .createTimeQualityConfiguration(
                                aTimeQualityConfigurationRequest()
                                        .withName("tqc-for-create-link")
                                        .build());

                // when
                SigningProfileDto dto = signingProfileService.createSigningProfile(
                        aSigningProfileRequest()
                                .withName("ts-with-tqc")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                        .withTimeQualityConfiguration(UUID.fromString(tqc.getUuid()))
                                        .build())
                                .build());

                // then: create response carries the TQC data
                TimestampingWorkflowDto tsDto = (TimestampingWorkflowDto) dto.getWorkflow();
                assertNotNull(tsDto.getTimeQualityConfiguration(),
                        "TimestampingWorkflowDto must expose the linked TimeQualityConfiguration");
                assertEquals(tqc.getUuid(), tsDto.getTimeQualityConfiguration().getUuid());

                // and: TQC link is persisted — re-fetch via service confirms the DB state
                TimestampingWorkflowDto fetchedTsDto = (TimestampingWorkflowDto) signingProfileService
                        .getSigningProfile(SecuredUUID.fromString(dto.getUuid()), null)
                        .getWorkflow();
                assertNotNull(fetchedTsDto.getTimeQualityConfiguration(),
                        "Re-fetched profile must still have the linked TimeQualityConfiguration");
                assertEquals(tqc.getUuid(), fetchedTsDto.getTimeQualityConfiguration().getUuid());
            }

            @Test
            void create_withNonExistentTqcUuid_throwsNotFoundException() {
                // given
                UUID nonExistentTqcUuid = UUID.randomUUID();

                // when
                Executable create = () -> signingProfileService.createSigningProfile(
                        aSigningProfileRequest()
                                .withName("ts-bad-tqc")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                        .withTimeQualityConfiguration(nonExistentTqcUuid)
                                        .build())
                                .build());

                // then
                assertThrows(NotFoundException.class, create);
            }

            @Test
            void update_workflowChangedFromTimestamping_tqcClearedFromHeader()
                    throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
                // given: a TIMESTAMPING profile with a TQC linked
                TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                        .createTimeQualityConfiguration(
                                aTimeQualityConfigurationRequest()
                                        .withName("tqc-for-clear-test")
                                        .build());

                SigningProfileDto created = signingProfileService.createSigningProfile(
                        aSigningProfileRequest()
                                .withName("ts-to-raw-profile")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                        .withTimeQualityConfiguration(UUID.fromString(tqc.getUuid()))
                                        .build())
                                .build());

                assertNotNull(((TimestampingWorkflowDto) created.getWorkflow()).getTimeQualityConfiguration(),
                        "precondition: TQC must be linked before the update");

                // when: update to RAW_SIGNING — TQC must be cleared
                SigningProfileDto updated = signingProfileService.updateSigningProfile(
                        SecuredUUID.fromString(created.getUuid()),
                        aSigningProfileRequestFromExistingProfile(created)
                                .withRawSigning()
                                .build());

                // then: re-fetched profile has RAW workflow
                SigningProfileDto fetched = signingProfileService.getSigningProfile(
                        SecuredUUID.fromString(updated.getUuid()), null);
                assertInstanceOf(RawSigningWorkflowDto.class, fetched.getWorkflow(),
                        "TimeQualityConfiguration must be cleared when workflow changes away from TIMESTAMPING");
            }

            @Test
            void listAssociated_returnsAssociatedProfiles()
                    throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
                // given: two TIMESTAMPING profiles linked to the same TQC
                TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                        .createTimeQualityConfiguration(
                                aTimeQualityConfigurationRequest()
                                        .withName("tqc-for-list-test")
                                        .build());
                UUID tqcUuid = UUID.fromString(tqc.getUuid());

                SigningProfileDto p1 = signingProfileService.createSigningProfile(
                        aSigningProfileRequest()
                                .withName("list-ts-profile-one")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                        .withTimeQualityConfiguration(tqcUuid)
                                        .build())
                                .build());
                SigningProfileDto p2 = signingProfileService.createSigningProfile(
                        aSigningProfileRequest()
                                .withName("list-ts-profile-two")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                        .withTimeQualityConfiguration(tqcUuid)
                                        .build())
                                .build());

                // when
                List<SimplifiedSigningProfileDto> result = signingProfileService
                        .listSigningProfilesAssociatedTimeQualityConfiguration(
                                SecuredUUID.fromUUID(tqcUuid), SecurityFilter.create());

                // then
                assertEquals(2, result.size());
                List<String> returnedUuids = result.stream().map(SimplifiedSigningProfileDto::getUuid).toList();
                assertTrue(returnedUuids.contains(p1.getUuid()));
                assertTrue(returnedUuids.contains(p2.getUuid()));
            }

            @Test
            void listAssociated_returnsOnlyProfilesLinkedToSpecificTqc()
                    throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
                // given: profile-A linked to tqcA, profile-B linked to tqcB
                TimeQualityConfigurationDto tqcA = timeQualityConfigurationService
                        .createTimeQualityConfiguration(
                                aTimeQualityConfigurationRequest().withName("tqc-A").build());
                TimeQualityConfigurationDto tqcB = timeQualityConfigurationService
                        .createTimeQualityConfiguration(
                                aTimeQualityConfigurationRequest().withName("tqc-B").build());

                SigningProfileDto profileA = signingProfileService.createSigningProfile(
                        aSigningProfileRequest()
                                .withName("profile-linked-to-tqc-A")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                        .withTimeQualityConfiguration(UUID.fromString(tqcA.getUuid()))
                                        .build())
                                .build());
                signingProfileService.createSigningProfile(
                        aSigningProfileRequest()
                                .withName("profile-linked-to-tqc-B")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormatterConnector(UUID.fromString(timestampingFormatterConnector.getUuid()))
                                        .withTimeQualityConfiguration(UUID.fromString(tqcB.getUuid()))
                                        .build())
                                .build());

                // when: query for TQC-A only
                List<SimplifiedSigningProfileDto> result = signingProfileService
                        .listSigningProfilesAssociatedTimeQualityConfiguration(
                                SecuredUUID.fromString(tqcA.getUuid()), SecurityFilter.create());

                // then
                assertEquals(1, result.size());
                assertEquals(profileA.getUuid(), result.getFirst().getUuid(),
                        "Only the profile linked to TQC-A should be returned");
            }

            @Test
            void listAssociated_emptyWhenNoneAssociated() throws AlreadyExistException, AttributeException, NotFoundException {
                // given
                TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                        .createTimeQualityConfiguration(
                                aTimeQualityConfigurationRequest()
                                        .withName("tqc-no-profiles")
                                        .build());

                // when
                List<SimplifiedSigningProfileDto> result = signingProfileService
                        .listSigningProfilesAssociatedTimeQualityConfiguration(
                                SecuredUUID.fromString(tqc.getUuid()), SecurityFilter.create());

                // then
                assertTrue(result.isEmpty(),
                        "No signing profiles should be returned for a TQC with no associated profiles");
            }
        }

        @Nested
        class ManagedTimestampingModel {

            @Test
            void nonExistentProfile_throwsNotFoundException() {
                // given
                String nonExistentSigningProfileName = "non-existent-profile-for-ts-check";

                // when
                Executable getProfile = () -> signingProfileService.getSigningProfileModel(nonExistentSigningProfileName);

                // then
                assertThrows(NotFoundException.class, getProfile);
            }

            @Test
            void nonTimestampingProfile_throwsIllegalArgumentException() {
                // given: a pre-configured raw (non-timestamping) profile
                String rawProfileName = defaultRawSigningProfile.getName();

                // when
                Executable getModel = () -> signingProfileService.getSigningProfileModel(rawProfileName);

                // then
                IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, getModel);
                assertTrue(ex.getMessage().contains("does not use a timestamping workflow"));
            }
        }

    }
}
