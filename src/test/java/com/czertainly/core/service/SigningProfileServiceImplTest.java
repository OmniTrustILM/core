package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationError;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttributeV2;
import com.czertainly.api.model.client.attribute.ResponseAttributeV3;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.signing.profile.SigningProfileDto;
import com.czertainly.api.model.client.signing.profile.SigningProfileListDto;
import com.czertainly.api.model.client.signing.profile.SigningProfileRequestDto;
import com.czertainly.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.czertainly.api.model.client.signing.profile.scheme.DelegatedSigningRequestDto;
import com.czertainly.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.czertainly.api.model.client.signing.profile.scheme.OneTimeKeyManagedSigningRequestDto;
import com.czertainly.api.model.client.signing.profile.scheme.SigningScheme;
import com.czertainly.api.model.client.signing.profile.scheme.StaticKeyManagedSigningDto;
import com.czertainly.api.model.client.signing.profile.scheme.StaticKeyManagedSigningRequestDto;
import com.czertainly.api.model.client.signing.profile.workflow.ContentSigningWorkflowDto;
import com.czertainly.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.czertainly.api.model.client.signing.profile.workflow.RawSigningWorkflowRequestDto;
import com.czertainly.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.czertainly.api.model.client.signing.profile.workflow.TimestampingWorkflowDto;
import com.czertainly.api.model.client.signing.profile.workflow.TimestampingWorkflowRequestDto;
import com.czertainly.api.model.client.signing.profile.workflow.WorkflowRequestDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.czertainly.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.czertainly.api.model.core.oid.SystemOid;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.common.attribute.common.AttributeVersion;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.CustomAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.core.dao.entity.AttributeDefinition;
import com.czertainly.core.dao.entity.AttributeRelation;
import com.czertainly.core.dao.entity.signing.SigningProfileVersion;
import com.czertainly.core.dao.repository.AttributeDefinitionRepository;
import com.czertainly.core.dao.repository.AttributeRelationRepository;
import com.czertainly.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.czertainly.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.api.model.core.signing.SigningProtocol;
import com.czertainly.api.model.client.connector.v2.ConnectorInterface;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.connector.v2.FeatureFlag;
import com.czertainly.core.dao.entity.ConnectorInterfaceEntity;
import com.czertainly.core.dao.repository.ConnectorInterfaceRepository;
import com.czertainly.core.attribute.RsaSignatureAttributes;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.TokenInstanceReference;
import com.czertainly.core.dao.entity.TokenProfile;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.CryptographicKeyItemRepository;
import com.czertainly.core.dao.repository.CryptographicKeyRepository;
import com.czertainly.core.dao.repository.TokenInstanceReferenceRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.dao.repository.TokenProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileRepository;
import com.czertainly.core.dao.repository.signing.SigningProfileVersionRepository;
import com.czertainly.core.dao.repository.signing.TspProfileRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.CertificateTestUtil;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.opa.dto.OpaResourceAccessResult;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

class SigningProfileServiceImplTest extends BaseSpringBootTest {

    private static final String CUSTOM_ATTR_UUID = "a1b2c3d4-0001-0002-0003-000000000003";
    private static final String CUSTOM_ATTR_NAME = "signingProfileTestAttribute";
    private static final String MISSING_UUID = "00000000-0000-0000-0000-000000000001";

    @Autowired
    private SigningProfileService signingProfileService;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private TimeQualityConfigurationService timeQualityConfigurationService;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;

    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private SigningProfileRepository signingProfileRepository;

    @Autowired
    private SigningProfileVersionRepository signingProfileVersionRepository;

    @Autowired
    private TspProfileRepository tspRepository;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    private AttributeRelationRepository attributeRelationRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    /**
     * A signing profile saved directly via repository, used as pre-existing data in tests.
     */
    private SigningProfile savedProfile;

    /**
     * A minimal RaProfile used as FK reference in ONE_TIME_KEY managed signing scheme requests.
     */
    private RaProfile raProfile;

    /**
     * A token profile used as an FK reference in static-key managed signing scheme requests.
     */
    private TokenProfile tokenProfile;

    /**
     * A CryptographicKey backed by an MLDSA key item (empty signing operation attribute definitions).
     * Used for generic static-key scheme tests that do not exercise signing operation attributes.
     */
    private CryptographicKey cryptographicKey;

    /**
     * A CryptographicKey backed by an RSA key item (RSA signing operation attribute definitions).
     * Used for tests that specifically exercise signing operation attribute storage and retrieval.
     */
    private CryptographicKey rsaCryptographicKey;

    /**
     * A Certificate associated with {@link #cryptographicKey} (MLDSA key).
     * Satisfies all conditions of constructQueryDigitalSigningCertAcceptable:
     * not archived, state=ISSUED, validationStatus=VALID, key has a private key that is ACTIVE
     * with SIGN usage, and the associated key has a Token Profile assigned.
     */
    private Certificate certificate;

    /**
     * A Certificate associated with {@link #rsaCryptographicKey} (RSA key).
     * Satisfies the same conditions as {@link #certificate}.
     */
    private Certificate rsaCertificate;

    /**
     * A Certificate specifically configured for TIMESTAMPING workflow type.
     * Contains the id-kp-timeStamping EKU and is marked as critical.
     */
    private Certificate tsaCertificate;

    /**
     * A Connector used as the signature formatter connector in CONTENT_SIGNING and TIMESTAMPING workflow tests
     * that do not exercise formatter attribute persistence specifically.
     */
    private Connector formatterConnector;

    /**
     * A Connector used as the delegated signer connector in DELEGATED scheme tests that do not exercise
     * delegated-connector attribute persistence specifically.
     */
    private Connector delegatedConnector;

    /**
     * WireMock server that backs every formatter connector URL created via {@link #createFormatterConnector}.
     */
    private WireMockServer mockServer;

    @BeforeEach
    void setUp() throws CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());
        mockServer.stubFor(
                WireMock.get(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/attributes"))
                        .willReturn(WireMock.okJson("[]"))
        );

        savedProfile = new SigningProfile();
        savedProfile.setName("existing-signing-profile");
        savedProfile.setDescription("Existing profile description");
        savedProfile.setEnabled(false);
        savedProfile.setSigningScheme(SigningScheme.DELEGATED);
        savedProfile.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        savedProfile.setLatestVersion(1);
        savedProfile = signingProfileRepository.save(savedProfile);

        SigningProfileVersion savedProfileV1 = new SigningProfileVersion();
        savedProfileV1.setSigningProfile(savedProfile);
        savedProfileV1.setVersion(1);
        savedProfileV1.setSigningScheme(SigningScheme.DELEGATED);
        savedProfileV1.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
        signingProfileVersionRepository.save(savedProfileV1);

        // Shared token instance infrastructure required by the static-key managed scheme
        Connector connector = new Connector();
        connector.setName("cryptography-connector");
        connector.setUrl("http://cryptography-connector");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        TokenInstanceReference tokenInstanceRef = new TokenInstanceReference();
        tokenInstanceRef.setName("test-token-instance");
        tokenInstanceRef.setTokenInstanceUuid(UUID.randomUUID().toString());
        tokenInstanceRef.setConnector(connector);
        tokenInstanceRef.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstanceRef = tokenInstanceReferenceRepository.saveAndFlush(tokenInstanceRef);

        tokenProfile = new TokenProfile();
        tokenProfile.setName("test-token-profile");
        tokenProfile.setTokenInstanceReference(tokenInstanceRef);
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceName("test-token-instance");
        tokenProfile = tokenProfileRepository.saveAndFlush(tokenProfile);

        // MLDSA key — produces empty attribute definitions; used by generic scheme tests
        cryptographicKey = new CryptographicKey();
        cryptographicKey.setName("test-key-mldsa");
        cryptographicKey.setTokenProfile(tokenProfile);
        cryptographicKey.setTokenInstanceReference(tokenInstanceRef);
        cryptographicKey = cryptographicKeyRepository.saveAndFlush(cryptographicKey);

        CryptographicKeyItem mldsaKeyItem = new CryptographicKeyItem();
        mldsaKeyItem.setKey(cryptographicKey);
        mldsaKeyItem.setKeyUuid(cryptographicKey.getUuid());
        mldsaKeyItem.setType(KeyType.PRIVATE_KEY);
        mldsaKeyItem.setState(KeyState.ACTIVE);
        mldsaKeyItem.setEnabled(true);
        mldsaKeyItem.setKeyAlgorithm(KeyAlgorithm.MLDSA);
        mldsaKeyItem.setLength(2048);
        mldsaKeyItem.setUsage(List.of(KeyUsage.SIGN));
        mldsaKeyItem = cryptographicKeyItemRepository.saveAndFlush(mldsaKeyItem);
        mldsaKeyItem.setKeyReferenceUuid(mldsaKeyItem.getUuid());
        cryptographicKeyItemRepository.saveAndFlush(mldsaKeyItem);

        // Certificate associated with the MLDSA key; satisfies constructQueryDigitalSigningCertAcceptable conditions
        certificate = new Certificate();
        certificate.setKey(cryptographicKey);
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate = certificateRepository.saveAndFlush(certificate);
        attachSelfSignedContent(certificate);

        // RSA key — produces RSA attribute definitions; used by attribute-persistence tests
        rsaCryptographicKey = new CryptographicKey();
        rsaCryptographicKey.setName("test-key-rsa");
        rsaCryptographicKey.setTokenProfile(tokenProfile);
        rsaCryptographicKey.setTokenInstanceReference(tokenInstanceRef);
        rsaCryptographicKey = cryptographicKeyRepository.saveAndFlush(rsaCryptographicKey);

        CryptographicKeyItem rsaKeyItem = new CryptographicKeyItem();
        rsaKeyItem.setKey(rsaCryptographicKey);
        rsaKeyItem.setKeyUuid(rsaCryptographicKey.getUuid());
        rsaKeyItem.setType(KeyType.PRIVATE_KEY);
        rsaKeyItem.setState(KeyState.ACTIVE);
        rsaKeyItem.setEnabled(true);
        rsaKeyItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        rsaKeyItem.setLength(2048);
        rsaKeyItem.setUsage(List.of(KeyUsage.SIGN));
        rsaKeyItem = cryptographicKeyItemRepository.saveAndFlush(rsaKeyItem);
        rsaKeyItem.setKeyReferenceUuid(rsaKeyItem.getUuid());
        cryptographicKeyItemRepository.saveAndFlush(rsaKeyItem);

        // Certificate associated with the RSA key; satisfies constructQueryDigitalSigningCertAcceptable conditions
        rsaCertificate = new Certificate();
        rsaCertificate.setKey(rsaCryptographicKey);
        rsaCertificate.setState(CertificateState.ISSUED);
        rsaCertificate.setValidationStatus(CertificateValidationStatus.VALID);
        rsaCertificate = certificateRepository.saveAndFlush(rsaCertificate);
        attachSelfSignedContent(rsaCertificate);

        // Certificate specifically configured for TIMESTAMPING; satisfies RFC 3161 requirements
        tsaCertificate = new Certificate();
        tsaCertificate.setKey(rsaCryptographicKey);
        tsaCertificate.setState(CertificateState.ISSUED);
        tsaCertificate.setValidationStatus(CertificateValidationStatus.VALID);
        tsaCertificate.setExtendedKeyUsage(MetaDefinitions.serializeArrayString(List.of(SystemOid.TIME_STAMPING.getOid())));
        tsaCertificate.setExtendedKeyUsageCritical(true);
        tsaCertificate = certificateRepository.saveAndFlush(tsaCertificate);
        attachSelfSignedContent(tsaCertificate);

        formatterConnector = createFormatterConnector("default-formatter-connector");

        Connector dc = new Connector();
        dc.setName("delegated-signer-connector");
        dc.setUrl("http://delegated-signer-connector");
        dc.setVersion(ConnectorVersion.V1);
        dc.setStatus(ConnectorStatus.CONNECTED);
        delegatedConnector = connectorRepository.save(dc);

        raProfile = new RaProfile();
        raProfile.setName("test-ra-profile");
        raProfile = raProfileRepository.save(raProfile);

        // Register a custom attribute available for Signing Profile resources
        CustomAttributeV3 attrDef = new CustomAttributeV3();
        attrDef.setUuid(CUSTOM_ATTR_UUID);
        attrDef.setName(CUSTOM_ATTR_NAME);
        attrDef.setDescription("test custom attribute for signing profile");
        attrDef.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties props = new CustomAttributeProperties();
        props.setReadOnly(false);
        props.setRequired(false);
        attrDef.setProperties(props);

        AttributeDefinition attributeDefinition = new AttributeDefinition();
        attributeDefinition.setUuid(UUID.fromString(CUSTOM_ATTR_UUID));
        attributeDefinition.setName(CUSTOM_ATTR_NAME);
        attributeDefinition.setAttributeUuid(UUID.fromString(CUSTOM_ATTR_UUID));
        attributeDefinition.setContentType(AttributeContentType.STRING);
        attributeDefinition.setLabel(CUSTOM_ATTR_NAME);
        attributeDefinition.setType(AttributeType.CUSTOM);
        attributeDefinition.setDefinition(attrDef);
        attributeDefinition.setEnabled(true);
        attributeDefinition.setVersion(3);
        attributeDefinitionRepository.save(attributeDefinition);

        AttributeRelation attributeRelation = new AttributeRelation();
        attributeRelation.setResource(Resource.SIGNING_PROFILE);
        attributeRelation.setAttributeDefinitionUuid(attributeDefinition.getUuid());
        attributeRelationRepository.save(attributeRelation);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class NotFound {

        @ParameterizedTest(name = "{0}")
        @MethodSource("notFoundCases")
        void throwsNotFoundException(String label, Executable action) {
            assertThrows(NotFoundException.class, action);
        }

        private Stream<Arguments> notFoundCases() {
            SecuredUUID missing = SecuredUUID.fromString(MISSING_UUID);
            return Stream.of(
                    Arguments.of("getSigningProfile",
                            (Executable) () -> signingProfileService.getSigningProfile(missing, null)),
                    Arguments.of("getSigningProfileEntity",
                            (Executable) () -> signingProfileService.getSigningProfileEntity(missing)),
                    Arguments.of("updateSigningProfile",
                            (Executable) () -> signingProfileService.updateSigningProfile(missing, buildDelegatedRawRequest("x"))),
                    Arguments.of("deleteSigningProfile",
                            (Executable) () -> signingProfileService.deleteSigningProfile(missing)),
                    Arguments.of("enableSigningProfile",
                            (Executable) () -> signingProfileService.enableSigningProfile(missing)),
                    Arguments.of("disableSigningProfile",
                            (Executable) () -> signingProfileService.disableSigningProfile(missing)),
                    Arguments.of("deactivateTsp",
                            (Executable) () -> signingProfileService.deactivateTsp(missing))
            );
        }

        @Test
        void activateTsp_profileNotFound_throwsNotFoundException() {
            TspProfile tsp = new TspProfile();
            tsp.setName("tsp-for-not-found");
            TspProfile savedTsp = tspRepository.save(tsp);
            assertThrows(NotFoundException.class,
                    () -> signingProfileService.activateTsp(
                            SecuredUUID.fromString(MISSING_UUID), savedTsp.getSecuredUuid()));
        }
    }

    @Nested
    class ListTests {

        @Test
        void returnsExistingEntries() {
            // given: savedProfile from setUp
            SearchRequestDto request = new SearchRequestDto();

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(request, SecurityFilter.create());

            // then
            assertNotNull(response);
            assertEquals(1, response.getTotalItems());
            SigningProfileListDto listed = response.getItems().getFirst();
            assertEquals(savedProfile.getUuid().toString(), listed.getUuid());
            assertEquals(savedProfile.getName(), listed.getName());
            assertEquals(savedProfile.getDescription(), listed.getDescription());
            assertEquals(SigningWorkflowType.RAW_SIGNING, listed.getSigningWorkflowType());
            assertFalse(listed.isEnabled());
        }

        @Test
        void emptyWhenNoneExist() {
            // given: no profiles (delete the one from setUp)
            signingProfileService.bulkDeleteSigningProfiles(List.of(savedProfile.getSecuredUuid()));

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(new SearchRequestDto(), SecurityFilter.create());

            // then
            assertNotNull(response);
            assertEquals(0, response.getTotalItems());
            assertTrue(response.getItems().isEmpty());
        }

        @Test
        void multipleProfilesWithDifferentWorkflowTypes()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: savedProfile (RAW_SIGNING) from setUp plus two more profiles with different workflow types
            signingProfileService.createSigningProfile(buildDelegatedContentRequest("content-profile"));
            signingProfileService.createSigningProfile(buildDelegatedTimestampingRequest("timestamping-profile"));

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(new SearchRequestDto(), SecurityFilter.create());

            // then
            assertNotNull(response);
            assertEquals(3, response.getTotalItems());

            List<SigningWorkflowType> returnedTypes = response.getItems().stream()
                    .map(SigningProfileListDto::getSigningWorkflowType)
                    .toList();
            assertTrue(returnedTypes.contains(SigningWorkflowType.RAW_SIGNING));
            assertTrue(returnedTypes.contains(SigningWorkflowType.CONTENT_SIGNING));
            assertTrue(returnedTypes.contains(SigningWorkflowType.TIMESTAMPING));
        }

    }

    @Nested
    class ListSignatureAttributesTests {

        @Test
        void allowedCert_returnsAttributes() throws NotFoundException {
            // given: rsaCertificate from setUp (access allowed by default)

            // when
            List<com.czertainly.api.model.common.attribute.common.BaseAttribute> attrs =
                    signingProfileService.listSignatureAttributesForCertificate(rsaCertificate.getUuid());

            // then
            assertNotNull(attrs);
            assertFalse(attrs.isEmpty(), "RSA certificate should produce non-empty signature attributes");
        }

        @Test
        void deniedCert_throwsAccessDeniedException() {
            // given: OPA mock configured to deny certificate DETAIL access
            OpaResourceAccessResult denied = new OpaResourceAccessResult();
            denied.setAuthorized(false);

            Mockito.when(
                    opaClient.checkResourceAccess(
                            Mockito.any(),
                            Mockito.argThat(req -> req != null
                                    && req.getProperties() != null
                                    && Resource.CERTIFICATE.getCode().equals(req.getProperties().get("name"))
                                    && ResourceAction.DETAIL.getCode().equals(req.getProperties().get("action"))),
                            Mockito.any(),
                            Mockito.any()
                    )
            ).thenReturn(denied);

            // when/then
            assertThrows(
                    AccessDeniedException.class,
                    () -> signingProfileService.listSignatureAttributesForCertificate(rsaCertificate.getUuid())
            );
        }

    }

    @Nested
    class GetTests {

        @Test
        void returnsCorrectDto() throws NotFoundException {
            // given: savedProfile from setUp

            // when
            SigningProfileDto dto = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);

            // then
            assertNotNull(dto);
            assertEquals(savedProfile.getUuid().toString(), dto.getUuid());
            assertEquals(savedProfile.getName(), dto.getName());
            assertEquals(savedProfile.getDescription(), dto.getDescription());
            assertFalse(dto.isEnabled());
            assertEquals(1, dto.getVersion());
        }

        @Test
        void specificVersion_returnsSnapshotData() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile created via service with a version 1 snapshot
            SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("profile-for-version-get"));
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when: fetch with explicit version=1
            SigningProfileDto dto = signingProfileService.getSigningProfile(profileUuid, 1);

            // then
            assertNotNull(dto);
            assertEquals(1, dto.getVersion());
            assertNotNull(dto.getSigningScheme());
            assertEquals(SigningScheme.DELEGATED, dto.getSigningScheme().getSigningScheme());
            assertNotNull(dto.getWorkflow());
            assertEquals(SigningWorkflowType.RAW_SIGNING, dto.getWorkflow().getType());
        }

        @Test
        void nonExistentVersion_throwsNotFoundException() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile with only version 1
            SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("profile-missing-version"));
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when/then: version 99 does not exist
            assertThrows(NotFoundException.class,
                    () -> signingProfileService.getSigningProfile(profileUuid, 99));
        }

        @Test
        void afterVersionBump_oldVersionPreservesOriginalWorkflowType()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile created with DELEGATED + RAW_SIGNING (version 1), then updated to CONTENT_SIGNING (version 2)
            SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("profile-history"));
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());
            signingProfileService.updateSigningProfile(profileUuid, buildDelegatedContentRequest("profile-history"));

            // when: fetch version 1
            SigningProfileDto v1 = signingProfileService.getSigningProfile(profileUuid, 1);

            // then: version 1 snapshot still reports RAW_SIGNING
            assertEquals(1, v1.getVersion());
            assertEquals(SigningWorkflowType.RAW_SIGNING, v1.getWorkflow().getType());

            // when: fetch latest
            SigningProfileDto latest = signingProfileService.getSigningProfile(profileUuid, null);

            // then: latest (version 2) reports CONTENT_SIGNING
            assertEquals(2, latest.getVersion());
            assertEquals(SigningWorkflowType.CONTENT_SIGNING, latest.getWorkflow().getType());
        }

        @Test
        void noProtocolsLinked_enabledProtocolsIsEmpty() throws NotFoundException {
            // given: savedProfile from setUp with no TSP linked

            // when
            SigningProfileDto dto = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);

            // then
            assertNotNull(dto.getEnabledProtocols());
            assertTrue(dto.getEnabledProtocols().isEmpty(),
                    "No protocols should be enabled when none are linked");
        }

        @Test
        void withTspLinked_enabledProtocolsContainsTsp() throws NotFoundException {
            // given: savedProfile with a TSP profile linked
            TspProfile tspProfile = new TspProfile();
            tspProfile.setName("tsp-for-dto-test");
            tspProfile = tspRepository.save(tspProfile);
            savedProfile.setTspProfile(tspProfile);
            signingProfileRepository.save(savedProfile);

            // when
            SigningProfileDto dto = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);

            // then
            assertNotNull(dto.getEnabledProtocols());
            assertTrue(dto.getEnabledProtocols().contains(SigningProtocol.TSP),
                    "TSP should appear in enabledProtocols");
        }

        @Test
        void entity_returnsCorrectEntity() throws NotFoundException {
            // given: savedProfile from setUp

            // when
            SigningProfile entity = signingProfileService.getSigningProfileEntity(savedProfile.getSecuredUuid());

            // then
            assertNotNull(entity);
            assertEquals(savedProfile.getUuid(), entity.getUuid());
            assertEquals(savedProfile.getName(), entity.getName());
        }

    }

    @Nested
    class FindAllNamesTests {

        @Test
        void returnsExistingNames() {
            // given: savedProfile from setUp

            // when
            List<String> names = signingProfileService.findAllNames();

            // then
            assertNotNull(names);
            assertEquals(1, names.size());
            assertTrue(names.contains(savedProfile.getName()));
        }

        @Test
        void returnsAllWhenMultipleExist() {
            // given: savedProfile from setUp plus a second profile saved directly
            SigningProfile second = new SigningProfile();
            second.setName("second-signing-profile");
            second.setSigningScheme(SigningScheme.DELEGATED);
            second.setWorkflowType(SigningWorkflowType.RAW_SIGNING);
            second.setLatestVersion(1);
            signingProfileRepository.save(second);

            // when
            List<String> names = signingProfileService.findAllNames();

            // then
            assertEquals(2, names.size());
            assertTrue(names.contains(savedProfile.getName()));
            assertTrue(names.contains("second-signing-profile"));
        }

        @Test
        void emptyWhenNoneExist() {
            // given: no profiles (delete the one from setUp)
            signingProfileVersionRepository.findBySigningProfileUuidAndVersion(savedProfile.getUuid(), savedProfile.getLatestVersion())
                    .ifPresent(signingProfileVersionRepository::delete);
            signingProfileRepository.delete(savedProfile);

            // when
            List<String> names = signingProfileService.findAllNames();

            // then
            assertNotNull(names);
            assertTrue(names.isEmpty());
        }

    }

    @Nested
    class CreateScheme {

        @Test
        void delegatedRawSigning_assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            SigningProfileRequestDto request = buildDelegatedRawRequest("new-delegated-profile");

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then: DTO
            assertNotNull(dto);
            assertNotNull(dto.getUuid());
            assertEquals("new-delegated-profile", dto.getName());
            assertEquals("Test description for new-delegated-profile", dto.getDescription());
            assertFalse(dto.isEnabled());
            assertEquals(1, dto.getVersion());
            assertNotNull(dto.getSigningScheme());
            assertNotNull(dto.getWorkflow());

            // then: DB
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
            assertTrue(fromDb.isPresent());
            SigningProfile entity = fromDb.get();
            assertEquals("new-delegated-profile", entity.getName());
            assertEquals("Test description for new-delegated-profile", entity.getDescription());
            assertFalse(entity.isEnabled());
            assertEquals(SigningScheme.DELEGATED, entity.getSigningScheme());
            assertEquals(SigningWorkflowType.RAW_SIGNING, entity.getWorkflowType());
            assertEquals(1, entity.getLatestVersion());

            SigningProfileVersion currentVersion = signingProfileVersionRepository
                    .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
            assertEquals(delegatedConnector.getUuid(), currentVersion.getDelegatedSignerConnectorUuid());
            // RAW_SIGNING workflow has no formatter connector
            assertNull(currentVersion.getSignatureFormatterConnectorUuid());
            // Version snapshot must carry scheme and workflow type
            assertNotNull(currentVersion.getSigningScheme());
            assertNotNull(currentVersion.getWorkflowType());
        }

        @Test
        void staticKeyManaged_assertSchemeAndEntityFields()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            SigningProfileRequestDto request = buildManagedStaticKeyRawRequest("static-key-profile");

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then: DTO
            assertNotNull(dto.getSigningScheme());
            assertEquals(SigningScheme.MANAGED, dto.getSigningScheme().getSigningScheme());

            // then: DB
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
            assertTrue(fromDb.isPresent());
            SigningProfile entity = fromDb.get();
            assertEquals(SigningScheme.MANAGED, entity.getSigningScheme());

            SigningProfileVersion currentVersion = signingProfileVersionRepository
                    .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
            assertEquals(ManagedSigningType.STATIC_KEY, currentVersion.getManagedSigningType());
            // No delegated connector when using the managed signing scheme
            assertNull(currentVersion.getDelegatedSignerConnectorUuid());
            // No RA profile / CSR template for the static key managed signing scheme
            assertNull(currentVersion.getRaProfileUuid());
            assertNull(currentVersion.getCsrTemplateUuid());
        }

        @Test
        void staticKeyManaged_incompleteChain_throwsValidationException()
                throws CertificateException, NoSuchAlgorithmException, OperatorCreationException {
            // given: a certificate whose chain cannot be verified
            Certificate incompleteChainCert = buildIncompleteChainCertificate();

            StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
            scheme.setCertificateUuid(incompleteChainCert.getUuid());
            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("incomplete-chain-profile");
            request.setSigningScheme(scheme);
            request.setWorkflow(new RawSigningWorkflowRequestDto());

            // when/then
            assertThrows(ValidationException.class,
                    () -> signingProfileService.createSigningProfile(request),
                    "createSigningProfile must reject a certificate whose chain is incomplete");
        }

        @Test
        void oneTimeKeyManaged_assertSchemeAndEntityFields()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            SigningProfileRequestDto request = buildManagedOneTimeKeyRawRequest("one-time-key-profile");

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then: DTO
            assertNotNull(dto.getSigningScheme());
            assertEquals(SigningScheme.MANAGED, dto.getSigningScheme().getSigningScheme());

            // then: DB
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
            assertTrue(fromDb.isPresent());
            SigningProfile entity = fromDb.get();
            assertEquals(SigningScheme.MANAGED, entity.getSigningScheme());

            SigningProfileVersion currentVersion = signingProfileVersionRepository
                    .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
            assertEquals(ManagedSigningType.ONE_TIME_KEY, currentVersion.getManagedSigningType());
            // No delegated connector when using managed scheme
            assertNull(currentVersion.getDelegatedSignerConnectorUuid());
            // Certificate UUID is not set for one-time key type
            assertNull(currentVersion.getCertificateUuid());
        }

    }

    @Nested
    class CreateWorkflow {

        @Test
        void contentSigningWorkflow_assertWorkflowTypeAndEntity()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            SigningProfileRequestDto request = buildDelegatedContentRequest("content-signing-profile");

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then: DTO
            assertNotNull(dto.getWorkflow());
            assertEquals(SigningWorkflowType.CONTENT_SIGNING, dto.getWorkflow().getType());

            // then: DB
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
            assertTrue(fromDb.isPresent());
            assertEquals(SigningWorkflowType.CONTENT_SIGNING, fromDb.get().getWorkflowType());
        }

        @Test
        void timestampingWorkflow_assertWorkflowTypeAndEntity()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            SigningProfileRequestDto request = buildDelegatedTimestampingRequest("timestamping-profile");

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then: DTO
            assertNotNull(dto.getWorkflow());
            assertEquals(SigningWorkflowType.TIMESTAMPING, dto.getWorkflow().getType());

            // then: DB
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
            assertTrue(fromDb.isPresent());
            assertEquals(SigningWorkflowType.TIMESTAMPING, fromDb.get().getWorkflowType());
        }

        @Test
        void timestampingWorkflowWithPoliciesAndAlgorithms_assertEntityFields()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            TimestampingWorkflowRequestDto timestampingWorkflow = new TimestampingWorkflowRequestDto();
            timestampingWorkflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
            timestampingWorkflow.setDefaultPolicyId("1.2.3.4.5");
            timestampingWorkflow.setAllowedPolicyIds(List.of("1.2.3.4.5", "1.2.3.4.6"));
            timestampingWorkflow.setAllowedDigestAlgorithms(List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_384));
            timestampingWorkflow.setQualifiedTimestamp(false);
            timestampingWorkflow.setValidateTokenSignature(true);

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("timestamping-with-policies");
            request.setDescription("Timestamping profile with policies");
            request.setSigningScheme(buildDelegatedScheme());
            request.setWorkflow(timestampingWorkflow);

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then: DTO
            assertNotNull(dto.getWorkflow());
            assertEquals(SigningWorkflowType.TIMESTAMPING, dto.getWorkflow().getType());
            TimestampingWorkflowDto tsDto = (TimestampingWorkflowDto) dto.getWorkflow();
            assertEquals("1.2.3.4.5", tsDto.getDefaultPolicyId());
            assertEquals(List.of("1.2.3.4.5", "1.2.3.4.6"), tsDto.getAllowedPolicyIds());
            assertTrue(tsDto.getAllowedDigestAlgorithms().contains(DigestAlgorithm.SHA_256));
            assertTrue(tsDto.getAllowedDigestAlgorithms().contains(DigestAlgorithm.SHA_384));
            assertFalse(tsDto.getQualifiedTimestamp());
            assertTrue(tsDto.getValidateTokenSignature());

            // then: DB
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
            assertTrue(fromDb.isPresent());
            SigningProfile entity = fromDb.get();
            assertEquals(SigningWorkflowType.TIMESTAMPING, entity.getWorkflowType());

            SigningProfileVersion currentVersion = signingProfileVersionRepository
                    .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
            assertEquals("1.2.3.4.5", currentVersion.getDefaultPolicyId());
            assertEquals(List.of("1.2.3.4.5", "1.2.3.4.6"), currentVersion.getAllowedPolicyIds());
            assertEquals(
                    List.of(DigestAlgorithm.SHA_256.getCode(), DigestAlgorithm.SHA_384.getCode()),
                    currentVersion.getAllowedDigestAlgorithms()
            );
            assertFalse(currentVersion.getQualifiedTimestamp());
            assertTrue(currentVersion.getValidateTokenSignature());
        }

        @Test
        void managedStaticKey_withContentSigningWorkflow_assertBothFields()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("managed-content-profile");
            request.setDescription("Managed static-key profile with content signing workflow");
            StaticKeyManagedSigningRequestDto managedContentScheme = new StaticKeyManagedSigningRequestDto();
            managedContentScheme.setCertificateUuid(certificate.getUuid());
            request.setSigningScheme(managedContentScheme);
            ContentSigningWorkflowRequestDto managedContentWorkflow = new ContentSigningWorkflowRequestDto();
            managedContentWorkflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
            request.setWorkflow(managedContentWorkflow);

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then: DTO
            assertEquals(SigningScheme.MANAGED, dto.getSigningScheme().getSigningScheme());
            assertEquals(SigningWorkflowType.CONTENT_SIGNING, dto.getWorkflow().getType());
            assertFalse(dto.isEnabled());

            // then: DB
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
            assertTrue(fromDb.isPresent());
            SigningProfile entity = fromDb.get();
            assertEquals(SigningScheme.MANAGED, entity.getSigningScheme());
            assertEquals(SigningWorkflowType.CONTENT_SIGNING, entity.getWorkflowType());

            SigningProfileVersion currentVersion = signingProfileVersionRepository
                    .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
            assertEquals(ManagedSigningType.STATIC_KEY, currentVersion.getManagedSigningType());
        }

    }

    @Nested
    class UpdateTests {

        @Test
        void assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            SigningProfileRequestDto request = buildDelegatedRawRequest("updated-profile");
            request.setDescription("Updated description");

            // when
            SigningProfileDto dto = signingProfileService.updateSigningProfile(savedProfile.getSecuredUuid(), request);

            // then: DTO
            assertNotNull(dto);
            assertEquals(savedProfile.getUuid().toString(), dto.getUuid());
            assertEquals("updated-profile", dto.getName());
            assertEquals("Updated description", dto.getDescription());
            assertFalse(dto.isEnabled());
            assertEquals(2, dto.getVersion());

            // then: DB
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
            assertTrue(fromDb.isPresent());
            SigningProfile entity = fromDb.get();
            assertEquals("updated-profile", entity.getName());
            assertEquals("Updated description", entity.getDescription());
            assertFalse(entity.isEnabled());
            assertEquals(2, entity.getLatestVersion());
            assertEquals(SigningScheme.DELEGATED, entity.getSigningScheme());
            assertEquals(SigningWorkflowType.RAW_SIGNING, entity.getWorkflowType());
        }

        @Test
        void versionBump_oldVersionAttributesPreservedInEngine()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a STATIC_KEY profile (version 1) with PKCS1-v1_5/SHA-256 signing-op attributes
            StaticKeyManagedSigningRequestDto schemeV1 = new StaticKeyManagedSigningRequestDto();
            schemeV1.setCertificateUuid(rsaCertificate.getUuid());
            schemeV1.setSigningOperationAttributes(List.of(
                    buildRsaSchemeAttribute(RsaSignatureScheme.PKCS1_v1_5),
                    buildDigestAttribute(DigestAlgorithm.SHA_256)));
            SigningProfileRequestDto createRequest = new SigningProfileRequestDto();
            createRequest.setName("versioned-sign-attrs-preserved");
            createRequest.setSigningScheme(schemeV1);
            createRequest.setWorkflow(new RawSigningWorkflowRequestDto());
            SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);
            UUID profileUuid = UUID.fromString(created.getUuid());

            List<ResponseAttribute> v1Attrs = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                            .operation(AttributeOperation.SIGN).version(1).build());
            assertFalse(v1Attrs.isEmpty(), "Version 1 signing-op attributes should be stored");

            // when: update to PSS/SHA-512 (bumps to version 2)
            StaticKeyManagedSigningRequestDto schemeV2 = new StaticKeyManagedSigningRequestDto();
            schemeV2.setCertificateUuid(rsaCertificate.getUuid());
            schemeV2.setSigningOperationAttributes(List.of(
                    buildRsaSchemeAttribute(RsaSignatureScheme.PSS),
                    buildDigestAttribute(DigestAlgorithm.SHA_512)));
            SigningProfileRequestDto updateRequest = new SigningProfileRequestDto();
            updateRequest.setName("versioned-sign-attrs-preserved");
            updateRequest.setSigningScheme(schemeV2);
            updateRequest.setWorkflow(new RawSigningWorkflowRequestDto());
            SigningProfileDto updated = signingProfileService.updateSigningProfile(SecuredUUID.fromUUID(profileUuid), updateRequest);

            // then
            assertEquals(2, updated.getVersion());

            List<ResponseAttribute> v1AttrAfterBump = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                            .operation(AttributeOperation.SIGN).version(1).build());
            assertFalse(v1AttrAfterBump.isEmpty(),
                    "Version 1 signing-op attributes must be preserved after a version bump");

            List<ResponseAttribute> v2Attrs = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                            .operation(AttributeOperation.SIGN).version(2).build());
            assertFalse(v2Attrs.isEmpty(),
                    "Version 2 signing-op attributes should be stored after bump");
        }

        @Test
        void versionBump_oldFormatterAttributesPreservedInEngine()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a CONTENT_SIGNING profile (version 1) with formatter attributes
            Connector formatter = createFormatterConnector("formatter-bump-preserve");
            FormatterAttr fa = registerFormatterAttribute(formatter, "data_bumpPreserveAttr");

            ContentSigningWorkflowRequestDto wfV1 = new ContentSigningWorkflowRequestDto();
            wfV1.setSignatureFormatterConnectorUuid(formatter.getUuid());
            wfV1.setSignatureFormatterConnectorAttributes(List.of(buildFormatterAttribute(fa.uuid(), fa.name(), "v1-value")));

            SigningProfileRequestDto createRequest = new SigningProfileRequestDto();
            createRequest.setName("formatter-attrs-bump-preserve");
            createRequest.setSigningScheme(buildDelegatedScheme());
            createRequest.setWorkflow(wfV1);
            SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);
            UUID profileUuid = UUID.fromString(created.getUuid());

            List<ResponseAttribute> v1AttrsBefore = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                            .connector(formatter.getUuid())
                            .operation(AttributeOperation.WORKFLOW_FORMATTER).version(1).build());
            assertFalse(v1AttrsBefore.isEmpty(), "Version 1 formatter attributes should be stored after create");

            // when: update with new formatter attribute value (bumps to version 2)
            ContentSigningWorkflowRequestDto wfV2 = new ContentSigningWorkflowRequestDto();
            wfV2.setSignatureFormatterConnectorUuid(formatter.getUuid());
            wfV2.setSignatureFormatterConnectorAttributes(List.of(buildFormatterAttribute(fa.uuid(), fa.name(), "v2-value")));

            SigningProfileRequestDto updateRequest = new SigningProfileRequestDto();
            updateRequest.setName("formatter-attrs-bump-preserve");
            updateRequest.setSigningScheme(buildDelegatedScheme());
            updateRequest.setWorkflow(wfV2);
            SigningProfileDto updated = signingProfileService.updateSigningProfile(SecuredUUID.fromUUID(profileUuid), updateRequest);

            // then
            assertEquals(2, updated.getVersion(), "Version must be bumped to 2");

            List<ResponseAttribute> v1AttrsAfterBump = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                            .connector(formatter.getUuid())
                            .operation(AttributeOperation.WORKFLOW_FORMATTER).version(1).build());
            assertFalse(v1AttrsAfterBump.isEmpty(),
                    "Version 1 formatter attributes must be preserved after a version bump");

            List<ResponseAttribute> v2Attrs = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                            .connector(formatter.getUuid())
                            .operation(AttributeOperation.WORKFLOW_FORMATTER).version(2).build());
            assertFalse(v2Attrs.isEmpty(),
                    "Version 2 formatter attributes should be stored after bump");
        }

        @Test
        void changeSchemeFromDelegatedToStaticKeyManaged()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: savedProfile uses DELEGATED scheme
            assertEquals(SigningScheme.DELEGATED, savedProfile.getSigningScheme());

            // when: update to MANAGED/STATIC_KEY
            signingProfileService.updateSigningProfile(savedProfile.getSecuredUuid(), buildManagedStaticKeyRawRequest("scheme-switched"));

            // then
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
            assertTrue(fromDb.isPresent());
            SigningProfile entity = fromDb.get();
            assertEquals(SigningScheme.MANAGED, entity.getSigningScheme());

            SigningProfileVersion currentVersion = signingProfileVersionRepository
                    .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
            assertEquals(ManagedSigningType.STATIC_KEY, currentVersion.getManagedSigningType());
            // Previous delegated connector reference must have been cleared
            assertNull(currentVersion.getDelegatedSignerConnectorUuid());
        }

        @Test
        void staticKeyManaged_incompleteChain_throwsValidationException()
                throws CertificateException, NoSuchAlgorithmException, OperatorCreationException {
            // given: a certificate whose chain cannot be verified
            Certificate incompleteChainCert = buildIncompleteChainCertificate();

            StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
            scheme.setCertificateUuid(incompleteChainCert.getUuid());
            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("incomplete-chain-update");
            request.setSigningScheme(scheme);
            request.setWorkflow(new RawSigningWorkflowRequestDto());

            // when/then
            assertThrows(ValidationException.class,
                    () -> signingProfileService.updateSigningProfile(savedProfile.getSecuredUuid(), request),
                    "updateSigningProfile must reject a certificate whose chain is incomplete");
        }

        @Test
        void changeSchemeFromStaticKeyManagedToDelegated()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a MANAGED/STATIC_KEY profile
            SigningProfileDto created = signingProfileService.createSigningProfile(buildManagedStaticKeyRawRequest("managed-to-delegated"));
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when: switch to DELEGATED
            signingProfileService.updateSigningProfile(profileUuid, buildDelegatedRawRequest("managed-to-delegated"));

            // then
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(created.getUuid()));
            assertTrue(fromDb.isPresent());
            SigningProfile entity = fromDb.get();
            assertEquals(SigningScheme.DELEGATED, entity.getSigningScheme());

            SigningProfileVersion currentVersion = signingProfileVersionRepository
                    .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
            // managedSigningType must have been cleared by applyScheme
            assertNull(currentVersion.getManagedSigningType());
            // token profile and certificate references must have been cleared
            assertNull(currentVersion.getCertificateUuid());
        }

        @Test
        void changeWorkflowFromRawToTimestamping()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: savedProfile uses RAW_SIGNING workflow; build a TIMESTAMPING update request
            TimestampingWorkflowRequestDto timestampingWorkflow = new TimestampingWorkflowRequestDto();
            timestampingWorkflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
            timestampingWorkflow.setDefaultPolicyId("1.2.3.4.5");
            timestampingWorkflow.setAllowedPolicyIds(List.of("1.2.3.4.5"));
            timestampingWorkflow.setQualifiedTimestamp(false);
            timestampingWorkflow.setValidateTokenSignature(false);

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("workflow-changed");
            request.setDescription("Changed to timestamping");
            request.setSigningScheme(buildDelegatedScheme());
            request.setWorkflow(timestampingWorkflow);

            // when
            SigningProfileDto dto = signingProfileService.updateSigningProfile(savedProfile.getSecuredUuid(), request);

            // then
            assertEquals(SigningWorkflowType.TIMESTAMPING, dto.getWorkflow().getType());

            Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
            assertTrue(fromDb.isPresent());
            SigningProfile entity = fromDb.get();
            assertEquals(SigningWorkflowType.TIMESTAMPING, entity.getWorkflowType());
            SigningProfileVersion currentVersion = signingProfileVersionRepository
                    .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
            assertEquals("1.2.3.4.5", currentVersion.getDefaultPolicyId());
            assertFalse(currentVersion.getQualifiedTimestamp());
            assertFalse(currentVersion.getValidateTokenSignature());
        }

        @Test
        void multipleBumps_versionsAccumulate()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile at version 1 (RAW_SIGNING), updated twice to reach version 3 (TIMESTAMPING)
            SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("multi-bump-profile"));
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());
            UUID profileUuidRaw = UUID.fromString(created.getUuid());

            // when
            signingProfileService.updateSigningProfile(profileUuid, buildDelegatedContentRequest("multi-bump-profile"));
            signingProfileService.updateSigningProfile(profileUuid, buildDelegatedTimestampingRequest("multi-bump-profile"));

            // then: three snapshot versions exist
            assertTrue(signingProfileVersionRepository.findBySigningProfileUuidAndVersion(profileUuidRaw, 1).isPresent());
            assertTrue(signingProfileVersionRepository.findBySigningProfileUuidAndVersion(profileUuidRaw, 2).isPresent());
            assertTrue(signingProfileVersionRepository.findBySigningProfileUuidAndVersion(profileUuidRaw, 3).isPresent());

            SigningProfileDto latest = signingProfileService.getSigningProfile(profileUuid, null);
            assertEquals(3, latest.getVersion());
            assertEquals(SigningWorkflowType.TIMESTAMPING, latest.getWorkflow().getType());

            SigningProfileDto v1 = signingProfileService.getSigningProfile(profileUuid, 1);
            assertEquals(SigningWorkflowType.RAW_SIGNING, v1.getWorkflow().getType());

            SigningProfileDto v2 = signingProfileService.getSigningProfile(profileUuid, 2);
            assertEquals(SigningWorkflowType.CONTENT_SIGNING, v2.getWorkflow().getType());
        }

    }

    @Nested
    class DeleteTests {

        @Test
        void removesEntityFromDatabase() throws NotFoundException {
            // given: savedProfile from setUp

            // when
            signingProfileService.deleteSigningProfile(savedProfile.getSecuredUuid());

            // then
            assertFalse(signingProfileRepository.findById(savedProfile.getUuid()).isPresent());
            assertThrows(NotFoundException.class,
                    () -> signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null));
        }

        @Test
        void usedAsDefaultInTspProfile_throwsValidationExceptionWithTspName() {
            // given: savedProfile is the default signing profile of a TSP profile
            TspProfile tspProfile = new TspProfile();
            tspProfile.setName("expected-tsp-name");
            tspProfile.setDefaultSigningProfile(savedProfile);
            tspRepository.save(tspProfile);

            // when/then
            ValidationException ex = assertThrows(ValidationException.class,
                    () -> signingProfileService.deleteSigningProfile(savedProfile.getSecuredUuid()));

            // then: error message names the blocking TSP profile and profile is not removed
            String message = ex.getErrors().stream()
                    .map(ValidationError::getErrorDescription)
                    .findFirst()
                    .orElse("");
            assertTrue(message.contains("expected-tsp-name"),
                    "Error message should contain the TSP profile name, got: " + message);
            assertTrue(signingProfileRepository.findById(savedProfile.getUuid()).isPresent(),
                    "Profile must still exist after failed delete");
        }

    }

    @Nested
    class BulkDelete {

        @Test
        void removesAllEntities() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: savedProfile from setUp plus a second profile
            SigningProfileDto second = signingProfileService.createSigningProfile(buildDelegatedRawRequest("second-profile"));

            // when
            List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(
                    List.of(savedProfile.getSecuredUuid(),
                            SecuredUUID.fromString(second.getUuid())));

            // then
            assertNotNull(messages);
            assertTrue(messages.isEmpty(), "Expected no errors but got: " + messages);
            assertFalse(signingProfileRepository.findById(savedProfile.getUuid()).isPresent());
            assertFalse(signingProfileRepository.findById(UUID.fromString(second.getUuid())).isPresent());
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
            SecuredUUID unknownUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000099");

            // when
            List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(
                    List.of(unknownUuid, savedProfile.getSecuredUuid()));

            // then
            assertFalse(messages.isEmpty(), "An error message should be returned for the non-existent UUID");
            assertTrue(messages.stream().anyMatch(m -> "00000000-0000-0000-0000-000000000099".equals(m.getUuid())));
            assertFalse(signingProfileRepository.findById(savedProfile.getUuid()).isPresent(),
                    "The known profile should be deleted even when the list contains an unknown UUID");
        }

        @Test
        void withTspProfileDependency_returnsErrorAndLeavesBlockedProfileIntact()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: savedProfile is the default of a TSP profile (blocked), plus an unblocked second profile
            TspProfile tspProfile = new TspProfile();
            tspProfile.setName("blocking-tsp");
            tspProfile.setDefaultSigningProfile(savedProfile);
            tspRepository.save(tspProfile);

            SigningProfileDto second = signingProfileService.createSigningProfile(buildDelegatedRawRequest("unblocked-profile"));

            // when
            List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(
                    List.of(savedProfile.getSecuredUuid(),
                            SecuredUUID.fromString(second.getUuid())));

            // then
            assertFalse(messages.isEmpty(), "Expected an error message for the blocked profile");
            assertTrue(messages.stream().anyMatch(m -> savedProfile.getUuid().toString().equals(m.getUuid())),
                    "Error message should reference the blocked profile UUID");
            assertTrue(signingProfileRepository.findById(savedProfile.getUuid()).isPresent(),
                    "Blocked profile must still exist in the database");
            assertFalse(signingProfileRepository.findById(UUID.fromString(second.getUuid())).isPresent(),
                    "Unblocked profile must be deleted");
        }

    }

    @Nested
    class EnableDisable {

        @Test
        void enable_setsEnabledTrue() throws NotFoundException {
            // given: savedProfile from setUp is disabled
            assertFalse(savedProfile.isEnabled());

            // when
            signingProfileService.enableSigningProfile(savedProfile.getSecuredUuid());

            // then
            SigningProfileDto dto = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);
            assertTrue(dto.isEnabled());

            Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
            assertTrue(fromDb.isPresent());
            assertTrue(fromDb.get().isEnabled());
        }

        @Test
        void enable_alreadyEnabled_isIdempotent() throws NotFoundException {
            // given: savedProfile already enabled
            savedProfile.setEnabled(true);
            signingProfileRepository.save(savedProfile);

            // when: enable again — should be idempotent
            signingProfileService.enableSigningProfile(savedProfile.getSecuredUuid());

            // then
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
            assertTrue(fromDb.isPresent());
            assertTrue(fromDb.get().isEnabled(), "Profile should remain enabled after enabling an already-enabled profile");
        }

        @Test
        void enable_afterCreate_persistsState() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a newly created profile (disabled by default)
            SigningProfileRequestDto request = buildDelegatedRawRequest("enabled-profile");
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);
            assertFalse(dto.isEnabled(), "Profiles must be created in a disabled state");

            // when
            signingProfileService.enableSigningProfile(SecuredUUID.fromString(dto.getUuid()));

            // then
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
            assertTrue(fromDb.isPresent());
            assertTrue(fromDb.get().isEnabled());
        }

        @Test
        void disable_setsEnabledFalse() throws NotFoundException {
            // given: savedProfile forced to enabled state
            savedProfile.setEnabled(true);
            signingProfileRepository.save(savedProfile);

            // when
            signingProfileService.disableSigningProfile(savedProfile.getSecuredUuid());

            // then
            SigningProfileDto dto = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);
            assertFalse(dto.isEnabled());

            Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
            assertTrue(fromDb.isPresent());
            assertFalse(fromDb.get().isEnabled());
        }

        @Test
        void disable_alreadyDisabled_isIdempotent() throws NotFoundException {
            // given: savedProfile is already disabled (enabled = false from setUp)

            // when: disable again — should be idempotent
            signingProfileService.disableSigningProfile(savedProfile.getSecuredUuid());

            // then
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
            assertTrue(fromDb.isPresent());
            assertFalse(fromDb.get().isEnabled(), "Profile should remain disabled after disabling an already-disabled profile");
        }

        @Test
        void bulkEnable_multipleProfiles() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: savedProfile from setUp plus two additional profiles (all disabled)
            SigningProfileDto second = signingProfileService.createSigningProfile(buildDelegatedRawRequest("second-for-bulk-enable"));
            SigningProfileDto third = signingProfileService.createSigningProfile(buildDelegatedContentRequest("third-for-bulk-enable"));

            // when
            signingProfileService.bulkEnableSigningProfiles(List.of(
                    savedProfile.getSecuredUuid(),
                    SecuredUUID.fromString(second.getUuid()),
                    SecuredUUID.fromString(third.getUuid())
            ));

            // then
            assertTrue(signingProfileRepository.findById(savedProfile.getUuid()).map(SigningProfile::isEnabled).orElse(false));
            assertTrue(signingProfileRepository.findById(UUID.fromString(second.getUuid())).map(SigningProfile::isEnabled).orElse(false));
            assertTrue(signingProfileRepository.findById(UUID.fromString(third.getUuid())).map(SigningProfile::isEnabled).orElse(false));
        }

        @Test
        void bulkDisable_multipleProfiles() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: two additional enabled profiles
            SigningProfileRequestDto req2 = buildDelegatedRawRequest("second-for-bulk-disable");
            SigningProfileDto second = signingProfileService.createSigningProfile(req2);
            signingProfileService.enableSigningProfile(SecuredUUID.fromString(second.getUuid()));

            SigningProfileRequestDto req3 = buildDelegatedContentRequest("third-for-bulk-disable");
            SigningProfileDto third = signingProfileService.createSigningProfile(req3);
            signingProfileService.enableSigningProfile(SecuredUUID.fromString(third.getUuid()));

            // when
            signingProfileService.bulkDisableSigningProfiles(List.of(
                    SecuredUUID.fromString(second.getUuid()),
                    SecuredUUID.fromString(third.getUuid())
            ));

            // then
            assertFalse(signingProfileRepository.findById(UUID.fromString(second.getUuid())).map(SigningProfile::isEnabled).orElse(true));
            assertFalse(signingProfileRepository.findById(UUID.fromString(third.getUuid())).map(SigningProfile::isEnabled).orElse(true));
        }

        @Test
        void bulkEnable_withNonExistentUuid_silentlyIgnores() {
            // given: a list with one unknown UUID and savedProfile
            SecuredUUID unknownUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000099");

            // when
            List<BulkActionMessageDto> messages = signingProfileService.bulkEnableSigningProfiles(
                    List.of(unknownUuid, savedProfile.getSecuredUuid()));

            // then: the unknown UUID surfaces as an error; the known profile is still enabled
            assertFalse(messages.isEmpty(), "An error message should be returned for the non-existent UUID");
            assertTrue(messages.stream().anyMatch(m -> "00000000-0000-0000-0000-000000000099".equals(m.getUuid())));
            assertTrue(signingProfileRepository.findById(savedProfile.getUuid())
                            .map(SigningProfile::isEnabled).orElse(false),
                    "The known profile should be enabled even when the list contains an unknown UUID");
        }

        @Test
        void bulkDisable_withNonExistentUuid_silentlyIgnores() {
            // given: savedProfile forced to enabled state, and one unknown UUID in the list
            savedProfile.setEnabled(true);
            signingProfileRepository.save(savedProfile);

            SecuredUUID unknownUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000099");

            // when
            List<BulkActionMessageDto> messages = signingProfileService.bulkDisableSigningProfiles(
                    List.of(unknownUuid, savedProfile.getSecuredUuid()));

            // then
            assertFalse(messages.isEmpty(), "An error message should be returned for the non-existent UUID");
            assertTrue(messages.stream().anyMatch(m -> "00000000-0000-0000-0000-000000000099".equals(m.getUuid())));
            assertFalse(signingProfileRepository.findById(savedProfile.getUuid())
                            .map(SigningProfile::isEnabled).orElse(true),
                    "The known profile should be disabled even when the list contains an unknown UUID");
        }

    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class TspProtocol {

        @Test
        void activate_setsLinkOnSigningProfile() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a TIMESTAMPING signing profile and a TSP profile
            SigningProfileDto profileDto = signingProfileService.createSigningProfile(buildDelegatedTimestampingRequest("timestamping-for-tsp-activate"));
            SecuredUUID profileUuid = SecuredUUID.fromString(profileDto.getUuid());

            TspProfile tspProfile = new TspProfile();
            tspProfile.setName("test-tsp-profile");
            tspProfile = tspRepository.save(tspProfile);

            // when
            var activationDto = signingProfileService.activateTsp(profileUuid, tspProfile.getSecuredUuid());

            // then
            assertTrue(activationDto.isAvailable());
            assertNotNull(activationDto.getSigningUrl());

            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(profileDto.getUuid()));
            assertTrue(fromDb.isPresent());
            assertEquals(tspProfile.getUuid(), fromDb.get().getTspProfileUuid());
        }

        @Test
        void activate_tspProfileNotFound_throwsNotFoundException() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a signing profile, and a TSP UUID that does not exist
            SigningProfileDto profileDto = signingProfileService.createSigningProfile(buildDelegatedTimestampingRequest("timestamping-for-tsp-not-found"));
            SecuredUUID profileUuid = SecuredUUID.fromString(profileDto.getUuid());

            // when/then
            assertThrows(NotFoundException.class,
                    () -> signingProfileService.activateTsp(
                            profileUuid,
                            SecuredUUID.fromString("00000000-0000-0000-0000-000000000002")));
        }

        @Test
        void activate_replacesExistingLink() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a signing profile linked to tspProfile1
            SigningProfileDto profileDto = signingProfileService.createSigningProfile(buildDelegatedTimestampingRequest("timestamping-for-tsp-replace"));
            SecuredUUID profileUuid = SecuredUUID.fromString(profileDto.getUuid());

            TspProfile tspProfile1 = new TspProfile();
            tspProfile1.setName("tsp-profile-1");
            tspProfile1 = tspRepository.save(tspProfile1);

            TspProfile tspProfile2 = new TspProfile();
            tspProfile2.setName("tsp-profile-2");
            tspProfile2 = tspRepository.save(tspProfile2);

            signingProfileService.activateTsp(profileUuid, tspProfile1.getSecuredUuid());

            // when: replace with tspProfile2
            signingProfileService.activateTsp(profileUuid, tspProfile2.getSecuredUuid());

            // then
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(profileDto.getUuid()));
            assertTrue(fromDb.isPresent());
            assertEquals(tspProfile2.getUuid(), fromDb.get().getTspProfileUuid(),
                    "The profile should reference the second TSP profile after replacement");
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("unsupportedWorkflowTypes")
        void activate_unsupportedWorkflowType_throwsValidationException(
                SigningWorkflowType type, String profileName)
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a signing profile with an unsupported workflow type for TSP activation
            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName(profileName);
            request.setSigningScheme(buildDelegatedScheme());
            request.setWorkflow(switch (type) {
                case RAW_SIGNING -> new RawSigningWorkflowRequestDto();
                case CONTENT_SIGNING -> {
                    ContentSigningWorkflowRequestDto wf = new ContentSigningWorkflowRequestDto();
                    wf.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
                    yield wf;
                }
                default ->
                        throw new IllegalStateException("Unexpected workflow type in unsupportedWorkflowTypes: " + type);
            });
            SigningProfileDto profileDto = signingProfileService.createSigningProfile(request);

            TspProfile tsp = new TspProfile();
            tsp.setName("tsp-unsupported-" + type);
            TspProfile savedTsp = tspRepository.save(tsp);

            // when/then
            assertThrows(ValidationException.class,
                    () -> signingProfileService.activateTsp(
                            SecuredUUID.fromString(profileDto.getUuid()), savedTsp.getSecuredUuid()));
        }

        Stream<Arguments> unsupportedWorkflowTypes() {
            return Stream.of(
                    Arguments.of(SigningWorkflowType.RAW_SIGNING, "raw-for-tsp-unsupported"),
                    Arguments.of(SigningWorkflowType.CONTENT_SIGNING, "content-for-tsp-unsupported")
            );
        }

        @Test
        void deactivate_removesFromEnabledProtocols() throws NotFoundException {
            // given: savedProfile linked to a TSP profile
            TspProfile tspProfile = new TspProfile();
            tspProfile.setName("tsp-to-deactivate");
            tspProfile = tspRepository.save(tspProfile);

            savedProfile.setTspProfile(tspProfile);
            signingProfileRepository.save(savedProfile);

            SigningProfileDto before = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);
            assertTrue(before.getEnabledProtocols().contains(SigningProtocol.TSP));

            // when
            signingProfileService.deactivateTsp(savedProfile.getSecuredUuid());

            // then: TSP profile UUID is cleared and no longer in enabled protocols
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
            assertTrue(fromDb.isPresent());
            assertNull(fromDb.get().getTspProfileUuid(),
                    "TSP profile UUID must be cleared after deactivation");

            SigningProfileDto after = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);
            assertFalse(after.getEnabledProtocols().contains(SigningProtocol.TSP),
                    "TSP should be removed from enabledProtocols after deactivation");
        }

        @Test
        void deactivate_noLinkExists_isIdempotent() {
            // given: savedProfile has no TSP link from setUp
            assertNull(savedProfile.getTspProfileUuid());

            // when/then: deactivateTsp should be a no-op
            assertDoesNotThrow(() -> signingProfileService.deactivateTsp(savedProfile.getSecuredUuid()),
                    "deactivateTsp must not throw when no TSP is currently linked");

            // then
            Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
            assertTrue(fromDb.isPresent());
            assertNull(fromDb.get().getTspProfileUuid(),
                    "TSP profile UUID should still be null after a no-op deactivation");
        }

    }

    @Nested
    class SigningOpAttrs {

        @Test
        void create_staticKey_attributesPersistedAndReturned()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
            scheme.setCertificateUuid(rsaCertificate.getUuid());
            scheme.setSigningOperationAttributes(List.of(
                    buildRsaSchemeAttribute(RsaSignatureScheme.PKCS1_v1_5),
                    buildDigestAttribute(DigestAlgorithm.SHA_256)));

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("static-key-with-sign-attrs");
            request.setDescription("Profile with signing operation attributes");
            request.setSigningScheme(scheme);
            request.setWorkflow(new RawSigningWorkflowRequestDto());

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then: the returned DTO must expose the persisted signing operation attributes
            assertInstanceOf(StaticKeyManagedSigningDto.class, dto.getSigningScheme());
            StaticKeyManagedSigningDto schemeDto = (StaticKeyManagedSigningDto) dto.getSigningScheme();
            assertNotNull(schemeDto.getSigningOperationAttributes());
            assertFalse(schemeDto.getSigningOperationAttributes().isEmpty(),
                    "Signing operation attributes should be populated after create");
            assertTrue(
                    schemeDto.getSigningOperationAttributes().stream()
                            .anyMatch(a -> RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME.equals(a.getName())),
                    "RSA signature scheme attribute should be present in the returned DTO");
        }

        @Test
        void get_staticKey_attributesLoadedFromEngine()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a static-key profile created with signing operation attributes
            StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
            scheme.setCertificateUuid(rsaCertificate.getUuid());
            scheme.setSigningOperationAttributes(List.of(
                    buildRsaSchemeAttribute(RsaSignatureScheme.PSS),
                    buildDigestAttribute(DigestAlgorithm.SHA_256)));

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("static-key-get-sign-attrs");
            request.setSigningScheme(scheme);
            request.setWorkflow(new RawSigningWorkflowRequestDto());

            SigningProfileDto created = signingProfileService.createSigningProfile(request);
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when: re-fetch from service (attributes must be loaded from AttributeEngine)
            SigningProfileDto fetched = signingProfileService.getSigningProfile(profileUuid, null);

            // then
            assertInstanceOf(StaticKeyManagedSigningDto.class, fetched.getSigningScheme());
            StaticKeyManagedSigningDto schemeDto = (StaticKeyManagedSigningDto) fetched.getSigningScheme();
            assertFalse(schemeDto.getSigningOperationAttributes().isEmpty(),
                    "Signing operation attributes should survive a create→get round-trip");
        }

        @Test
        void update_staticKey_attributesReplacedOnUpdate()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a static-key profile created with PKCS1-v1_5/SHA-256 signing attributes
            StaticKeyManagedSigningRequestDto schemeV1 = new StaticKeyManagedSigningRequestDto();
            schemeV1.setCertificateUuid(rsaCertificate.getUuid());
            schemeV1.setSigningOperationAttributes(List.of(
                    buildRsaSchemeAttribute(RsaSignatureScheme.PKCS1_v1_5),
                    buildDigestAttribute(DigestAlgorithm.SHA_256)));

            SigningProfileRequestDto createRequest = new SigningProfileRequestDto();
            createRequest.setName("static-key-update-sign-attrs");
            createRequest.setSigningScheme(schemeV1);
            createRequest.setWorkflow(new RawSigningWorkflowRequestDto());

            SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when: update to PSS/SHA-384
            StaticKeyManagedSigningRequestDto schemeV2 = new StaticKeyManagedSigningRequestDto();
            schemeV2.setCertificateUuid(rsaCertificate.getUuid());
            schemeV2.setSigningOperationAttributes(List.of(
                    buildRsaSchemeAttribute(RsaSignatureScheme.PSS),
                    buildDigestAttribute(DigestAlgorithm.SHA_384)));

            SigningProfileRequestDto updateRequest = new SigningProfileRequestDto();
            updateRequest.setName("static-key-update-sign-attrs");
            updateRequest.setSigningScheme(schemeV2);
            updateRequest.setWorkflow(new RawSigningWorkflowRequestDto());

            SigningProfileDto updated = signingProfileService.updateSigningProfile(profileUuid, updateRequest);

            // then
            assertInstanceOf(StaticKeyManagedSigningDto.class, updated.getSigningScheme());
            StaticKeyManagedSigningDto schemeDto = (StaticKeyManagedSigningDto) updated.getSigningScheme();
            List<ResponseAttribute> signingOperationAttributes = schemeDto.getSigningOperationAttributes();
            assertFalse(signingOperationAttributes.isEmpty());
            Optional<ResponseAttribute> rsaSigningSchemeAttribute = signingOperationAttributes.stream().filter(
                    a -> RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME.equals(a.getName())).findFirst();
            assertTrue(rsaSigningSchemeAttribute.isPresent());
            // The RSA sig-scheme attribute content should reflect the new PSS value, not the old PKCS1-v1_5
            if (AttributeVersion.V2.equals(rsaSigningSchemeAttribute.get().getVersion())) {
                ResponseAttributeV2 rsaSigningSchemeAttributeV2 = (ResponseAttributeV2) rsaSigningSchemeAttribute.get();
                var attributeContentV2 = rsaSigningSchemeAttributeV2.getContent().getFirst();
                assertEquals(RsaSignatureScheme.PSS.getCode(), attributeContentV2.getData().toString(),
                        "Signing operation attributes should be replaced with new value on update");
            } else if (AttributeVersion.V3.equals(rsaSigningSchemeAttribute.get().getVersion())) {
                ResponseAttributeV3 rsaSigningSchemeAttributeV3 = (ResponseAttributeV3) rsaSigningSchemeAttribute.get();
                var attributeContentV3 = rsaSigningSchemeAttributeV3.getContent().getFirst();
                assertEquals(RsaSignatureScheme.PSS.getCode(), attributeContentV3.getData().toString(),
                        "Signing operation attributes should be replaced with new value on update");
            } else {
                fail("Unknown attribute version: " + rsaSigningSchemeAttribute.get().getVersion() + " - the test needs to be updated to handle this version");
            }
        }

        @Test
        void update_schemeChangedToNonStaticKey_attributesCleared()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a STATIC_KEY profile with signing operation attributes
            StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
            scheme.setCertificateUuid(rsaCertificate.getUuid());
            scheme.setSigningOperationAttributes(List.of(
                    buildRsaSchemeAttribute(RsaSignatureScheme.PKCS1_v1_5),
                    buildDigestAttribute(DigestAlgorithm.SHA_256)));

            SigningProfileRequestDto createRequest = new SigningProfileRequestDto();
            createRequest.setName("static-key-to-delegated");
            createRequest.setSigningScheme(scheme);
            createRequest.setWorkflow(new RawSigningWorkflowRequestDto());

            SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when: switch to DELEGATED — should clear signing-operation attributes from the engine
            signingProfileService.updateSigningProfile(profileUuid, buildDelegatedRawRequest("static-key-to-delegated"));

            // then: nothing remains in AttributeEngine under SIGN for this profile (version 2)
            List<ResponseAttribute> remaining = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()))
                            .operation(AttributeOperation.SIGN).version(2).build());
            assertTrue(remaining.isEmpty(),
                    "Signing-scheme attributes should be deleted when scheme changes away from STATIC_KEY");
        }

        @Test
        void delete_removesAttributesFromEngine()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a static-key profile with signing operation attributes
            StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
            scheme.setCertificateUuid(rsaCertificate.getUuid());
            scheme.setSigningOperationAttributes(List.of(
                    buildRsaSchemeAttribute(RsaSignatureScheme.PSS),
                    buildDigestAttribute(DigestAlgorithm.SHA_256)));

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("delete-clears-sign-attrs");
            request.setSigningScheme(scheme);
            request.setWorkflow(new RawSigningWorkflowRequestDto());

            SigningProfileDto created = signingProfileService.createSigningProfile(request);
            UUID profileUuid = UUID.fromString(created.getUuid());

            // when
            signingProfileService.deleteSigningProfile(SecuredUUID.fromUUID(profileUuid));

            // then: AttributeEngine should have no attributes left for this profile
            List<ResponseAttribute> remaining = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                            .operation(AttributeOperation.SIGN).version(1).build());
            assertTrue(remaining.isEmpty(),
                    "Signing-scheme attributes should be removed by deleteObjectAttributeContent on profile deletion");
        }

        @Test
        void getSpecificVersion_returnsVersionedAttributes()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a STATIC_KEY profile at version 1 (PSS) then bumped to version 2 (PKCS1_v1_5)
            StaticKeyManagedSigningRequestDto schemeV1 = new StaticKeyManagedSigningRequestDto();
            schemeV1.setCertificateUuid(rsaCertificate.getUuid());
            schemeV1.setSigningOperationAttributes(List.of(
                    buildRsaSchemeAttribute(RsaSignatureScheme.PSS),
                    buildDigestAttribute(DigestAlgorithm.SHA_256)));
            SigningProfileRequestDto createRequest = new SigningProfileRequestDto();
            createRequest.setName("versioned-get-sign-attrs");
            createRequest.setSigningScheme(schemeV1);
            createRequest.setWorkflow(new RawSigningWorkflowRequestDto());
            SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            StaticKeyManagedSigningRequestDto schemeV2 = new StaticKeyManagedSigningRequestDto();
            schemeV2.setCertificateUuid(rsaCertificate.getUuid());
            schemeV2.setSigningOperationAttributes(List.of(
                    buildRsaSchemeAttribute(RsaSignatureScheme.PKCS1_v1_5),
                    buildDigestAttribute(DigestAlgorithm.SHA_256)));
            SigningProfileRequestDto updateRequest = new SigningProfileRequestDto();
            updateRequest.setName("versioned-get-sign-attrs");
            updateRequest.setSigningScheme(schemeV2);
            updateRequest.setWorkflow(new RawSigningWorkflowRequestDto());
            signingProfileService.updateSigningProfile(profileUuid, updateRequest);

            // when: fetch version 1
            SigningProfileDto v1Dto = signingProfileService.getSigningProfile(profileUuid, 1);

            // then: version 1 DTO carries PSS attributes
            assertInstanceOf(StaticKeyManagedSigningDto.class, v1Dto.getSigningScheme());
            StaticKeyManagedSigningDto v1SchemeDto = (StaticKeyManagedSigningDto) v1Dto.getSigningScheme();
            assertFalse(v1SchemeDto.getSigningOperationAttributes().isEmpty(),
                    "Version 1 DTO must include signing-op attributes");
            assertTrue(
                    v1SchemeDto.getSigningOperationAttributes().stream()
                            .anyMatch(a -> RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME.equals(a.getName())),
                    "Version 1 must contain RSA signature scheme attribute");

            // when: fetch version 2
            SigningProfileDto v2Dto = signingProfileService.getSigningProfile(profileUuid, 2);

            // then: version 2 DTO carries PKCS1_v1_5 attributes
            assertInstanceOf(StaticKeyManagedSigningDto.class, v2Dto.getSigningScheme());
            StaticKeyManagedSigningDto v2SchemeDto = (StaticKeyManagedSigningDto) v2Dto.getSigningScheme();
            assertFalse(v2SchemeDto.getSigningOperationAttributes().isEmpty(),
                    "Version 2 DTO must include signing-op attributes");
            assertTrue(
                    v2SchemeDto.getSigningOperationAttributes().stream()
                            .anyMatch(a -> RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME.equals(a.getName())),
                    "Version 2 must contain RSA signature scheme attribute");

            // then: the engine holds distinct records for v1 and v2
            List<ResponseAttribute> v1SignAttrs = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()))
                            .operation(AttributeOperation.SIGN).version(1).build());
            List<ResponseAttribute> v2SignAttrs = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()))
                            .operation(AttributeOperation.SIGN).version(2).build());
            assertFalse(v1SignAttrs.isEmpty(), "Engine must hold v1 sign attrs");
            assertFalse(v2SignAttrs.isEmpty(), "Engine must hold v2 sign attrs");
        }

    }

    /**
     * Builds a valid RSA {@code signingOperationAttributes} request attribute for use in tests.
     */
    private RequestAttributeV2 buildRsaSchemeAttribute(RsaSignatureScheme scheme) {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID));
        attr.setName(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME);
        attr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 content = new StringAttributeContentV2(scheme.getLabel(), scheme.getCode());
        attr.setContent(List.of(content));
        return attr;
    }

    /**
     * Builds a valid digest {@code signingOperationAttributes} request attribute for use in tests.
     */
    private RequestAttributeV2 buildDigestAttribute(DigestAlgorithm algorithm) {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID));
        attr.setName(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST);
        attr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 content = new StringAttributeContentV2(algorithm.getLabel(), algorithm.getCode());
        attr.setContent(List.of(content));
        return attr;
    }

    private Connector createFormatterConnector(String name) {
        Connector connector = new Connector();
        connector.setName(name);
        connector.setUrl("http://localhost:" + mockServer.port() + "/" + name);
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        ConnectorInterfaceEntity connectorInterface = new ConnectorInterfaceEntity();
        connectorInterface.setConnectorUuid(connector.getUuid());
        connectorInterface.setInterfaceCode(ConnectorInterface.SIGNATURE_FORMATTING);
        connectorInterface.setVersion("1.0.0");
        connectorInterface.setFeatures(List.of(FeatureFlag.CONTENT_SIGNING, FeatureFlag.TIMESTAMPING));
        connectorInterfaceRepository.save(connectorInterface);

        return connector;
    }

    private RequestAttributeV2 buildFormatterAttribute(UUID attrUuid, String attrName, String value) {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(attrUuid);
        attr.setName(attrName);
        attr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 content = new StringAttributeContentV2();
        content.setData(value);
        attr.setContent(List.of(content));
        return attr;
    }

    @Nested
    class FormatterAttributes {

        @Test
        void create_contentSigning_attributesPersistedAndReturned()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            Connector formatter = createFormatterConnector("formatter-content-create");
            FormatterAttr fa = registerFormatterAttribute(formatter, "data_testFormatterAttr");

            ContentSigningWorkflowRequestDto workflow = new ContentSigningWorkflowRequestDto();
            workflow.setSignatureFormatterConnectorUuid(formatter.getUuid());
            workflow.setSignatureFormatterConnectorAttributes(
                    List.of(buildFormatterAttribute(fa.uuid(), fa.name(), "testValue")));

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("doc-profile-with-formatter-attrs");
            request.setSigningScheme(buildDelegatedScheme());
            request.setWorkflow(workflow);

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then
            assertInstanceOf(ContentSigningWorkflowDto.class, dto.getWorkflow());
            ContentSigningWorkflowDto wfDto = (ContentSigningWorkflowDto) dto.getWorkflow();
            assertFalse(wfDto.getSignatureFormatterConnectorAttributes().isEmpty(),
                    "Formatter connector attributes should be populated after create");
            assertEquals(fa.name(), wfDto.getSignatureFormatterConnectorAttributes().getFirst().getName());
        }

        @Test
        void update_connectorChanged_oldAttributesCleared()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile created with formatterA attributes
            Connector formatterA = createFormatterConnector("formatter-old");
            Connector formatterB = createFormatterConnector("formatter-new");
            FormatterAttr faA = registerFormatterAttribute(formatterA, "data_switchTest");
            FormatterAttr faB = registerFormatterAttribute(formatterB, "data_switchTest");

            ContentSigningWorkflowRequestDto workflowA = new ContentSigningWorkflowRequestDto();
            workflowA.setSignatureFormatterConnectorUuid(formatterA.getUuid());
            workflowA.setSignatureFormatterConnectorAttributes(
                    List.of(buildFormatterAttribute(faA.uuid(), faA.name(), "valueA")));

            SigningProfileRequestDto createRequest = new SigningProfileRequestDto();
            createRequest.setName("workflow-formatter-switch");
            createRequest.setSigningScheme(buildDelegatedScheme());
            createRequest.setWorkflow(workflowA);

            SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());
            UUID profileUuidRaw = UUID.fromString(created.getUuid());

            // when: update with formatterB — old formatterA attributes should be cleared
            ContentSigningWorkflowRequestDto workflowB = new ContentSigningWorkflowRequestDto();
            workflowB.setSignatureFormatterConnectorUuid(formatterB.getUuid());
            workflowB.setSignatureFormatterConnectorAttributes(
                    List.of(buildFormatterAttribute(faB.uuid(), faB.name(), "valueB")));

            SigningProfileRequestDto updateRequest = new SigningProfileRequestDto();
            updateRequest.setName("workflow-formatter-switch");
            updateRequest.setSigningScheme(buildDelegatedScheme());
            updateRequest.setWorkflow(workflowB);

            signingProfileService.updateSigningProfile(profileUuid, updateRequest);

            // then: attributes for old formatterA are gone (version 2)
            List<ResponseAttribute> oldAttrs = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                            .connector(formatterA.getUuid())
                            .operation(AttributeOperation.WORKFLOW_FORMATTER).version(2).build());
            assertTrue(oldAttrs.isEmpty(),
                    "Attributes for the old formatter connector should be removed when the connector changes");

            // then: attributes for new formatterB are present
            List<ResponseAttribute> newAttrs = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                            .connector(formatterB.getUuid())
                            .operation(AttributeOperation.WORKFLOW_FORMATTER).version(2).build());
            assertFalse(newAttrs.isEmpty(),
                    "Attributes for the new formatter connector should be stored after the update");
        }

        @Test
        void get_allWorkflowTypes_attributesReturned()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a formatter connector with a registered attribute
            Connector formatter = createFormatterConnector("formatter-multi-workflow");
            FormatterAttr fa = registerFormatterAttribute(formatter, "data_multiWorkflowAttr");

            for (SigningWorkflowType workflowLabel : List.of(SigningWorkflowType.CONTENT_SIGNING, SigningWorkflowType.TIMESTAMPING)) {
                // when/then: for each workflow type, create a profile and verify attributes are returned on get
                WorkflowRequestDto wfRequest;
                switch (workflowLabel) {
                    case CONTENT_SIGNING -> {
                        ContentSigningWorkflowRequestDto wf = new ContentSigningWorkflowRequestDto();
                        wf.setSignatureFormatterConnectorUuid(formatter.getUuid());
                        wf.setSignatureFormatterConnectorAttributes(List.of(buildFormatterAttribute(fa.uuid(), fa.name(), "val-" + workflowLabel)));
                        wfRequest = wf;
                    }
                    case TIMESTAMPING -> {
                        TimestampingWorkflowRequestDto wf = new TimestampingWorkflowRequestDto();
                        wf.setSignatureFormatterConnectorUuid(formatter.getUuid());
                        wf.setSignatureFormatterConnectorAttributes(List.of(buildFormatterAttribute(fa.uuid(), fa.name(), "val-" + workflowLabel)));
                        wfRequest = wf;
                    }
                    default -> throw new IllegalStateException("Unexpected workflow type: " + workflowLabel);
                }

                SigningProfileRequestDto request = new SigningProfileRequestDto();
                request.setName("formatter-attrs-" + workflowLabel);
                request.setSigningScheme(buildDelegatedScheme());
                request.setWorkflow(wfRequest);

                SigningProfileDto dto = signingProfileService.createSigningProfile(request);
                SigningProfileDto fetched = signingProfileService.getSigningProfile(
                        SecuredUUID.fromString(dto.getUuid()), null);

                List<ResponseAttribute> fetchedAttrs;
                switch (fetched.getWorkflow().getType()) {
                    case CONTENT_SIGNING ->
                            fetchedAttrs = ((ContentSigningWorkflowDto) fetched.getWorkflow()).getSignatureFormatterConnectorAttributes();
                    case TIMESTAMPING ->
                            fetchedAttrs = ((TimestampingWorkflowDto) fetched.getWorkflow()).getSignatureFormatterConnectorAttributes();
                    default ->
                            throw new IllegalStateException("Unexpected workflow type: " + fetched.getWorkflow().getType());
                }
                assertFalse(fetchedAttrs.isEmpty(),
                        "Formatter attributes should be loaded for workflow type: " + workflowLabel);
                assertEquals(fa.name(), fetchedAttrs.getFirst().getName());
            }
        }

        @Test
        void delete_removesFormatterAttributesFromEngine()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile with formatter attributes
            Connector formatter = createFormatterConnector("formatter-delete-test");
            FormatterAttr fa = registerFormatterAttribute(formatter, "data_deleteFormatterAttr");

            ContentSigningWorkflowRequestDto workflow = new ContentSigningWorkflowRequestDto();
            workflow.setSignatureFormatterConnectorUuid(formatter.getUuid());
            workflow.setSignatureFormatterConnectorAttributes(
                    List.of(buildFormatterAttribute(fa.uuid(), fa.name(), "toDelete")));

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("delete-clears-formatter-attrs");
            request.setSigningScheme(buildDelegatedScheme());
            request.setWorkflow(workflow);

            SigningProfileDto created = signingProfileService.createSigningProfile(request);
            UUID profileUuid = UUID.fromString(created.getUuid());

            // when
            signingProfileService.deleteSigningProfile(SecuredUUID.fromUUID(profileUuid));

            // then
            List<ResponseAttribute> remaining = attributeEngine.getObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                            .connector(formatter.getUuid())
                            .operation(AttributeOperation.WORKFLOW_FORMATTER).version(1).build());
            assertTrue(remaining.isEmpty(),
                    "Formatter attributes should be removed by deleteObjectAttributeContent on profile deletion");
        }

    }

    @Nested
    class FormatterAttributeValidation {

        @Test
        void create_validAttribute_accepted()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a formatter connector whose WireMock definition accepts the submitted attribute
            Connector formatter = createFormatterConnector("formatter-valid-content");

            UUID attrUuid = UUID.fromString("00000000-dead-beef-0001-000000000001");
            String attrName = "data_validFormatterAttr";

            // WireMock returns the definition so fetchAndUpdateFormatterAttributeDefinitions stores it.
            // validateUpdateDataAttributes is then called with that definition and the submitted content.
            mockServer.stubFor(
                    WireMock.get(WireMock.urlPathEqualTo("/formatter-valid-content/v1/signatureProvider/formatting/attributes"))
                            .willReturn(WireMock.okJson("""
                                    [{"uuid":"%s","name":"%s","type":"data","version":"2","contentType":"string",\
                                    "properties":{"label":"Valid Formatter Attribute","required":false,"readOnly":false,"list":false,"multiSelect":false,"visible":true}}]
                                    """.formatted(attrUuid, attrName)))
            );

            ContentSigningWorkflowRequestDto workflow = new ContentSigningWorkflowRequestDto();
            workflow.setSignatureFormatterConnectorUuid(formatter.getUuid());
            workflow.setSignatureFormatterConnectorAttributes(
                    List.of(buildFormatterAttribute(attrUuid, attrName, "valid-value")));

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("content-valid-formatter-attrs");
            request.setSigningScheme(buildDelegatedScheme());
            request.setWorkflow(workflow);

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then
            assertNotNull(dto);
            assertEquals(SigningWorkflowType.CONTENT_SIGNING, dto.getWorkflow().getType());
            ContentSigningWorkflowDto wfDto = (ContentSigningWorkflowDto) dto.getWorkflow();
            assertFalse(wfDto.getSignatureFormatterConnectorAttributes().isEmpty(),
                    "Formatter attribute that passes connector-definition validation must be persisted");
        }

        @Test
        void create_contentSigning_requiredAttributeMissing_throwsValidationException() {
            // given: a formatter connector that requires an attribute, and the request omits it
            Connector formatter = createFormatterConnector("formatter-required-content");

            // WireMock returns a required attribute definition — the client submits nothing.
            mockServer.stubFor(
                    WireMock.get(WireMock.urlPathEqualTo("/formatter-required-content/v1/signatureProvider/formatting/attributes"))
                            .willReturn(WireMock.okJson("""
                                    [{"uuid":"00000000-dead-beef-0002-000000000001","name":"req_content_attr","type":"data","version":"2","contentType":"string",\
                                    "properties":{"label":"Required Content Attr","required":true,"readOnly":false,"list":false,"multiSelect":false,"visible":true}}]
                                    """))
            );

            ContentSigningWorkflowRequestDto workflow = new ContentSigningWorkflowRequestDto();
            workflow.setSignatureFormatterConnectorUuid(formatter.getUuid());
            workflow.setSignatureFormatterConnectorAttributes(List.of());

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("content-missing-required-attr");
            request.setSigningScheme(buildDelegatedScheme());
            request.setWorkflow(workflow);

            // when/then
            assertThrows(ValidationException.class,
                    () -> signingProfileService.createSigningProfile(request),
                    "createSigningProfile must reject missing required formatter attribute in CONTENT_SIGNING workflow");
        }

        @Test
        void create_timestamping_requiredAttributeMissing_throwsValidationException() {
            // given: a formatter connector that requires an attribute for TIMESTAMPING, and the request omits it
            Connector formatter = createFormatterConnector("formatter-required-timestamping");

            mockServer.stubFor(
                    WireMock.get(WireMock.urlPathEqualTo("/formatter-required-timestamping/v1/signatureProvider/formatting/attributes"))
                            .willReturn(WireMock.okJson("""
                                    [{"uuid":"00000000-dead-beef-0003-000000000001","name":"req_ts_attr","type":"data","version":"2","contentType":"string",\
                                    "properties":{"label":"Required Timestamping Attr","required":true,"readOnly":false,"list":false,"multiSelect":false,"visible":true}}]
                                    """))
            );

            TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
            workflow.setSignatureFormatterConnectorUuid(formatter.getUuid());
            workflow.setSignatureFormatterConnectorAttributes(List.of());

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("ts-missing-required-attr");
            request.setSigningScheme(buildDelegatedScheme());
            request.setWorkflow(workflow);

            // when/then
            assertThrows(ValidationException.class,
                    () -> signingProfileService.createSigningProfile(request),
                    "createSigningProfile must reject missing required formatter attribute in TIMESTAMPING workflow");
        }

    }

    @Nested
    class CustomAttributes {

        @Test
        void create_withCustomAttributes_returnedInDto() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            RequestAttributeV3 customAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                    CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                    List.of(new StringAttributeContentV3("profile-value-on-create")));

            SigningProfileRequestDto request = buildDelegatedRawRequest("profile-with-custom-attr");
            request.setCustomAttributes(List.of(customAttr));

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then
            assertNotNull(dto.getCustomAttributes());
            assertFalse(dto.getCustomAttributes().isEmpty(),
                    "Custom attributes should be returned in the create DTO");
            assertEquals("profile-value-on-create",
                    ((ResponseAttributeV3) dto.getCustomAttributes().getFirst()).getContent().getFirst().getData());
        }

        @Test
        void update_withCustomAttributes_returnedInDto() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile created with a custom attribute set to "initial-value"
            RequestAttributeV3 createAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                    CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                    List.of(new StringAttributeContentV3("initial-value")));
            SigningProfileRequestDto createRequest = buildDelegatedRawRequest("profile-update-custom-attr");
            createRequest.setCustomAttributes(List.of(createAttr));
            SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);

            // when: update with "updated-value"
            RequestAttributeV3 updateAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                    CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                    List.of(new StringAttributeContentV3("updated-value")));
            SigningProfileRequestDto updateRequest = buildDelegatedRawRequest("profile-update-custom-attr");
            updateRequest.setCustomAttributes(List.of(updateAttr));
            SigningProfileDto updated = signingProfileService.updateSigningProfile(
                    SecuredUUID.fromString(created.getUuid()), updateRequest);

            // then
            assertNotNull(updated.getCustomAttributes());
            assertFalse(updated.getCustomAttributes().isEmpty());
            assertEquals("updated-value",
                    ((ResponseAttributeV3) updated.getCustomAttributes().getFirst()).getContent().getFirst().getData());
        }

    }

    @Nested
    class NameUniqueness {

        @Test
        void create_duplicateName_throwsAlreadyExistException()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile with the name "duplicate-name" already exists
            signingProfileService.createSigningProfile(buildDelegatedRawRequest("duplicate-name"));

            // when/then
            assertThrows(AlreadyExistException.class,
                    () -> signingProfileService.createSigningProfile(buildDelegatedRawRequest("duplicate-name")));
        }

        @Test
        void update_toExistingNameOfAnotherProfile_throwsAlreadyExistException()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: two profiles "profile-alpha" and "profile-beta" already exist
            signingProfileService.createSigningProfile(buildDelegatedRawRequest("profile-alpha"));
            SigningProfileDto beta = signingProfileService.createSigningProfile(buildDelegatedRawRequest("profile-beta"));

            // when/then: renaming beta to alpha collides with the existing profile
            SigningProfileRequestDto updateRequest = buildDelegatedRawRequest("profile-alpha");

            assertThrows(AlreadyExistException.class,
                    () -> signingProfileService.updateSigningProfile(SecuredUUID.fromString(beta.getUuid()), updateRequest));
        }

        @Test
        void update_keepingSameName_succeeds() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile with name "keep-same-name"
            SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("keep-same-name"));

            // when: update keeping the same name but changing description
            SigningProfileRequestDto updateRequest = buildDelegatedRawRequest("keep-same-name");
            updateRequest.setDescription("updated description");
            SigningProfileDto updated = signingProfileService.updateSigningProfile(SecuredUUID.fromString(created.getUuid()), updateRequest);

            // then
            assertEquals("keep-same-name", updated.getName());
            assertEquals("updated description", updated.getDescription());
        }

    }

    @Nested
    class TimeQualityConfiguration {

        @Test
        void create_withTqcUuid_headerLinkedAndReturnedInDto()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                    .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-for-create-link"));

            TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
            workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
            workflow.setTimeQualityConfigurationUuid(UUID.fromString(tqc.getUuid()));

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("ts-with-tqc");
            request.setSigningScheme(buildDelegatedScheme());
            request.setWorkflow(workflow);

            // when
            SigningProfileDto dto = signingProfileService.createSigningProfile(request);

            // then: DB header entity links to TQC
            SigningProfile entity = signingProfileRepository.findById(UUID.fromString(dto.getUuid())).orElseThrow();
            assertNotNull(entity.getTimeQualityConfiguration(),
                    "SigningProfile header must have a linked TimeQualityConfiguration");
            assertEquals(UUID.fromString(tqc.getUuid()), entity.getTimeQualityConfiguration().getUuid());

            // then: DTO carries back the TQC data
            TimestampingWorkflowDto tsDto = (TimestampingWorkflowDto) dto.getWorkflow();
            assertNotNull(tsDto.getTimeQualityConfiguration(),
                    "TimestampingWorkflowDto must expose the linked TimeQualityConfiguration");
            assertEquals(tqc.getUuid(), tsDto.getTimeQualityConfiguration().getUuid());
        }

        @Test
        void create_withNonExistentTqcUuid_throwsNotFoundException() {
            // given: a random TQC UUID that does not exist
            TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
            workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
            workflow.setTimeQualityConfigurationUuid(UUID.randomUUID());

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("ts-bad-tqc");
            request.setSigningScheme(buildDelegatedScheme());
            request.setWorkflow(workflow);

            // when/then
            assertThrows(NotFoundException.class,
                    () -> signingProfileService.createSigningProfile(request));
        }

        @Test
        void update_workflowChangedFromTimestamping_tqcClearedFromHeader()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a TIMESTAMPING profile with a TQC linked
            TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                    .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-for-clear-test"));

            TimestampingWorkflowRequestDto timestampingWorkflow = new TimestampingWorkflowRequestDto();
            timestampingWorkflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
            timestampingWorkflow.setTimeQualityConfigurationUuid(UUID.fromString(tqc.getUuid()));

            SigningProfileRequestDto createRequest = new SigningProfileRequestDto();
            createRequest.setName("ts-to-raw-profile");
            createRequest.setSigningScheme(buildDelegatedScheme());
            createRequest.setWorkflow(timestampingWorkflow);

            SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);

            SigningProfile beforeUpdate = signingProfileRepository.findById(UUID.fromString(created.getUuid())).orElseThrow();
            assertNotNull(beforeUpdate.getTimeQualityConfiguration());

            // when: update to RAW_SIGNING — TQC must be cleared from the header
            SigningProfileRequestDto updateRequest = new SigningProfileRequestDto();
            updateRequest.setName("ts-to-raw-profile");
            updateRequest.setSigningScheme(buildDelegatedScheme());
            updateRequest.setWorkflow(new RawSigningWorkflowRequestDto());
            signingProfileService.updateSigningProfile(SecuredUUID.fromString(created.getUuid()), updateRequest);

            // then
            SigningProfile afterUpdate = signingProfileRepository.findById(UUID.fromString(created.getUuid())).orElseThrow();
            assertNull(afterUpdate.getTimeQualityConfiguration(),
                    "TimeQualityConfiguration must be cleared when workflow is changed away from TIMESTAMPING");
        }

        @Test
        void listAssociated_returnsAssociatedProfiles()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: two TIMESTAMPING profiles linked to the same TQC
            TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                    .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-for-list-test"));
            UUID tqcUuid = UUID.fromString(tqc.getUuid());

            TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
            workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
            workflow.setTimeQualityConfigurationUuid(tqcUuid);

            SigningProfileRequestDto r1 = new SigningProfileRequestDto();
            r1.setName("list-ts-profile-one");
            r1.setSigningScheme(buildDelegatedScheme());
            r1.setWorkflow(workflow);
            SigningProfileDto p1 = signingProfileService.createSigningProfile(r1);

            TimestampingWorkflowRequestDto workflow2 = new TimestampingWorkflowRequestDto();
            workflow2.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
            workflow2.setTimeQualityConfigurationUuid(tqcUuid);
            SigningProfileRequestDto r2 = new SigningProfileRequestDto();
            r2.setName("list-ts-profile-two");
            r2.setSigningScheme(buildDelegatedScheme());
            r2.setWorkflow(workflow2);
            SigningProfileDto p2 = signingProfileService.createSigningProfile(r2);

            // when
            List<SimplifiedSigningProfileDto> result = signingProfileService
                    .listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID.fromUUID(tqcUuid), SecurityFilter.create());

            // then
            assertEquals(2, result.size());
            List<String> returnedUuids = result.stream().map(SimplifiedSigningProfileDto::getUuid).toList();
            assertTrue(returnedUuids.contains(p1.getUuid()));
            assertTrue(returnedUuids.contains(p2.getUuid()));
        }

        @Test
        void listAssociated_emptyWhenNoneAssociated()
                throws AlreadyExistException, AttributeException, NotFoundException {
            // given: a TQC with no signing profiles linked to it
            TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                    .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-no-profiles"));

            // when
            List<SimplifiedSigningProfileDto> result = signingProfileService
                    .listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID.fromString(tqc.getUuid()), SecurityFilter.create());

            // then
            assertTrue(result.isEmpty(),
                    "No signing profiles should be returned for a TQC with no associated profiles");
        }

        @Test
        void listAssociated_returnsOnlyProfilesLinkedToSpecificTqc()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: profile-A linked to tqcA, profile-B linked to tqcB
            TimeQualityConfigurationDto tqcA = timeQualityConfigurationService
                    .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-A"));
            TimeQualityConfigurationDto tqcB = timeQualityConfigurationService
                    .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-B"));

            TimestampingWorkflowRequestDto workflowA = new TimestampingWorkflowRequestDto();
            workflowA.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
            workflowA.setTimeQualityConfigurationUuid(UUID.fromString(tqcA.getUuid()));
            SigningProfileRequestDto reqA = new SigningProfileRequestDto();
            reqA.setName("profile-linked-to-tqc-A");
            reqA.setSigningScheme(buildDelegatedScheme());
            reqA.setWorkflow(workflowA);
            SigningProfileDto profileA = signingProfileService.createSigningProfile(reqA);

            TimestampingWorkflowRequestDto workflowB = new TimestampingWorkflowRequestDto();
            workflowB.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
            workflowB.setTimeQualityConfigurationUuid(UUID.fromString(tqcB.getUuid()));
            SigningProfileRequestDto reqB = new SigningProfileRequestDto();
            reqB.setName("profile-linked-to-tqc-B");
            reqB.setSigningScheme(buildDelegatedScheme());
            reqB.setWorkflow(workflowB);
            signingProfileService.createSigningProfile(reqB);

            // when: query for TQC-A
            List<SimplifiedSigningProfileDto> result = signingProfileService
                    .listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID.fromString(tqcA.getUuid()), SecurityFilter.create());

            // then
            assertEquals(1, result.size());
            assertEquals(profileA.getUuid(), result.getFirst().getUuid(),
                    "Only the profile linked to TQC-A should be returned");
        }

    }

    /**
     * Builds a minimal valid SigningProfileRequestDto using a DELEGATED scheme and RAW_SIGNING workflow
     * (no foreign-key dependencies on connectors, token profiles, or keys).
     */
    private DelegatedSigningRequestDto buildDelegatedScheme() {
        DelegatedSigningRequestDto scheme = new DelegatedSigningRequestDto();
        scheme.setConnectorUuid(delegatedConnector.getUuid());
        return scheme;
    }

    private SigningProfileRequestDto buildDelegatedRawRequest(String name) {
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test description for " + name);
        request.setSigningScheme(buildDelegatedScheme());
        request.setWorkflow(new RawSigningWorkflowRequestDto());
        return request;
    }

    /**
     * Builds a request using a MANAGED/STATIC_KEY scheme and RAW_SIGNING workflow.
     * Uses the shared MLDSA {@link #cryptographicKey} so no signing-operation-attribute
     * definitions are produced and no attribute content needs to be provided.
     */
    private SigningProfileRequestDto buildManagedStaticKeyRawRequest(String name) {
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test description for " + name);
        StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
        scheme.setCertificateUuid(certificate.getUuid());
        request.setSigningScheme(scheme);
        request.setWorkflow(new RawSigningWorkflowRequestDto());
        return request;
    }

    /**
     * Builds a request using a MANAGED/ONE_TIME_KEY scheme and RAW_SIGNING workflow.
     * No FK UUIDs are set, so the request is safe to use against any test database.
     */
    private SigningProfileRequestDto buildManagedOneTimeKeyRawRequest(String name) {
        OneTimeKeyManagedSigningRequestDto scheme = new OneTimeKeyManagedSigningRequestDto();
        scheme.setTokenProfileUuid(tokenProfile.getUuid());
        scheme.setRaProfileUuid(raProfile.getUuid());
        scheme.setCsrTemplateUuid(UUID.randomUUID());
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test description for " + name);
        request.setSigningScheme(scheme);
        request.setWorkflow(new RawSigningWorkflowRequestDto());
        return request;
    }

    /**
     * Builds a request using a DELEGATED scheme and CONTENT_SIGNING workflow.
     */
    private SigningProfileRequestDto buildDelegatedContentRequest(String name) {
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test description for " + name);
        request.setSigningScheme(buildDelegatedScheme());
        ContentSigningWorkflowRequestDto workflow = new ContentSigningWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        request.setWorkflow(workflow);
        return request;
    }

    /**
     * Builds a request using a DELEGATED scheme and TIMESTAMPING workflow.
     */
    private SigningProfileRequestDto buildDelegatedTimestampingRequest(String name) {
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test description for " + name);
        request.setSigningScheme(buildDelegatedScheme());
        TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        request.setWorkflow(workflow);
        return request;
    }

    /**
     * Builds a request using a MANAGED/STATIC_KEY scheme and TIMESTAMPING workflow,
     * with no additional validation properties set.
     */
    private SigningProfileRequestDto buildManagedStaticKeyTimestampingRequest(String name) {
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test description for " + name);
        StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
        scheme.setCertificateUuid(tsaCertificate.getUuid());
        scheme.setSigningOperationAttributes(List.of(
                buildRsaSchemeAttribute(RsaSignatureScheme.PKCS1_v1_5),
                buildDigestAttribute(DigestAlgorithm.SHA_256)));
        request.setSigningScheme(scheme);
        TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        request.setWorkflow(workflow);
        return request;
    }

    /**
     * Builds a request using a MANAGED/STATIC_KEY scheme and TIMESTAMPING workflow
     * with a default policy ID, two allowed policy IDs, and SHA-256 as an allowed digest algorithm.
     */
    private SigningProfileRequestDto buildManagedStaticKeyTimestampingRequestWithValidationProps(String name) {
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test description for " + name);
        StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
        scheme.setCertificateUuid(tsaCertificate.getUuid());
        scheme.setSigningOperationAttributes(List.of(
                buildRsaSchemeAttribute(RsaSignatureScheme.PKCS1_v1_5),
                buildDigestAttribute(DigestAlgorithm.SHA_256)));
        request.setSigningScheme(scheme);
        TimestampingWorkflowRequestDto wf = new TimestampingWorkflowRequestDto();
        wf.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        wf.setDefaultPolicyId("1.2.3.4.5");
        wf.setAllowedPolicyIds(List.of("1.2.3.4.5", "1.2.3.4.6"));
        wf.setAllowedDigestAlgorithms(List.of(DigestAlgorithm.SHA_256));
        wf.setValidateTokenSignature(true);
        request.setWorkflow(wf);
        return request;
    }

    private void attachSelfSignedContent(Certificate cert) throws CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException {
        X509Certificate x509 = CertificateTestUtil.createCACertificate();
        Certificate entityWithContent = certificateService.createCertificateEntity(x509);
        cert.setCertificateContent(entityWithContent.getCertificateContent());
        cert.setCertificateContentId(entityWithContent.getCertificateContentId());
        certificateRepository.saveAndFlush(cert);
    }

    private TimeQualityConfigurationRequestDto buildTimeQualityConfigurationRequestDto(String name) {
        TimeQualityConfigurationRequestDto req = new TimeQualityConfigurationRequestDto();
        req.setName(name);
        req.setAccuracy(java.time.Duration.ofSeconds(1));
        req.setNtpServers(List.of("pool.ntp.org"));
        req.setNtpCheckInterval(java.time.Duration.ofSeconds(30));
        req.setNtpSamplesPerServer(4);
        req.setNtpCheckTimeout(java.time.Duration.ofSeconds(5));
        req.setNtpServersMinReachable(1);
        req.setMaxClockDrift(java.time.Duration.ofSeconds(1));
        req.setLeapSecondGuard(true);
        return req;
    }

    /**
     * Creates and persists a {@link Certificate} entity that passes eligibility checks for static-key managed signing
     * (ISSUED, VALID, active key with SIGN usage and a token profile assigned) but whose certificate content is signed
     * by an external CA absent from the inventory.
     */
    private Certificate buildIncompleteChainCertificate() throws CertificateException, NoSuchAlgorithmException, OperatorCreationException {
        X509Certificate x509 = CertificateTestUtil.createEndEntityCertificate();
        Certificate cert = new Certificate();
        cert.setKey(cryptographicKey);
        cert.setState(CertificateState.ISSUED);
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        cert = certificateRepository.saveAndFlush(cert);

        Certificate entityWithContent = certificateService.createCertificateEntity(x509);
        cert.setCertificateContent(entityWithContent.getCertificateContent());
        cert.setCertificateContentId(entityWithContent.getCertificateContentId());
        return certificateRepository.saveAndFlush(cert);
    }

    private record FormatterAttr(UUID uuid, String name) {
    }

    /**
     * Registers a DATA attribute definition for the given formatter connector in the AttributeEngine
     * and returns the UUID + name as a record for use in test assertions.
     */
    private FormatterAttr registerFormatterAttribute(Connector formatter, String attrName) throws AttributeException {
        UUID attrUuid = UUID.randomUUID();
        DataAttributeV2 attrDef = new DataAttributeV2();
        attrDef.setUuid(attrUuid.toString());
        attrDef.setName(attrName);
        attrDef.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel(attrName);
        attrDef.setProperties(props);
        attributeEngine.updateDataAttributeDefinitions(formatter.getUuid(), AttributeOperation.WORKFLOW_FORMATTER, List.of(attrDef));
        return new FormatterAttr(attrUuid, attrName);
    }

}
