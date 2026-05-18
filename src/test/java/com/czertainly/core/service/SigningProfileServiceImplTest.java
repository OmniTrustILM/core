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
import com.czertainly.core.dao.entity.signing.SigningProfile;
import com.czertainly.core.dao.entity.signing.TspProfile;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.CryptographicKeyItemRepository;
import com.czertainly.core.dao.repository.CryptographicKeyRepository;
import com.czertainly.core.dao.repository.TokenInstanceReferenceRepository;
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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

class SigningProfileServiceImplTest extends BaseSpringBootTest {

    private static final String CUSTOM_ATTR_UUID = "a1b2c3d4-0001-0002-0003-000000000003";
    private static final String CUSTOM_ATTR_NAME = "signingProfileTestAttribute";

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

    /**
     * A signing profile saved directly via repository, used as pre-existing data in tests.
     */
    private SigningProfile savedProfile;

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

    // ──────────────────────────────────────────────────────────────────────────
    // List
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testListSigningProfiles_returnsExistingEntries() {
        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(request, SecurityFilter.create());

        Assertions.assertNotNull(response);
        Assertions.assertEquals(1, response.getTotalItems());
        SigningProfileListDto listed = response.getItems().getFirst();
        Assertions.assertEquals(savedProfile.getUuid().toString(), listed.getUuid());
        Assertions.assertEquals(savedProfile.getName(), listed.getName());
        Assertions.assertEquals(savedProfile.getDescription(), listed.getDescription());
        Assertions.assertEquals(SigningWorkflowType.RAW_SIGNING, listed.getSigningWorkflowType());
        Assertions.assertFalse(listed.isEnabled());
    }

    @Test
    void testListSigningProfiles_emptyWhenNoneExist() {
        signingProfileService.bulkDeleteSigningProfiles(List.of(savedProfile.getSecuredUuid()));

        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(request, SecurityFilter.create());

        Assertions.assertNotNull(response);
        Assertions.assertEquals(0, response.getTotalItems());
        Assertions.assertTrue(response.getItems().isEmpty());
    }

    @Test
    void testListSigningProfiles_multipleProfilesWithDifferentWorkflowTypes()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // Create additional profiles with different workflow types
        signingProfileService.createSigningProfile(buildDelegatedContentRequest("content-profile"));
        signingProfileService.createSigningProfile(buildDelegatedTimestampingRequest("timestamping-profile"));

        SearchRequestDto request = new SearchRequestDto();
        PaginationResponseDto<SigningProfileListDto> response = signingProfileService.listSigningProfiles(request, SecurityFilter.create());

        Assertions.assertNotNull(response);
        Assertions.assertEquals(3, response.getTotalItems());

        List<SigningWorkflowType> returnedTypes = response.getItems().stream()
                .map(SigningProfileListDto::getSigningWorkflowType)
                .toList();
        Assertions.assertTrue(returnedTypes.contains(SigningWorkflowType.RAW_SIGNING));
        Assertions.assertTrue(returnedTypes.contains(SigningWorkflowType.CONTENT_SIGNING));
        Assertions.assertTrue(returnedTypes.contains(SigningWorkflowType.TIMESTAMPING));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // listSignatureAttributesForCertificate
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testListSignatureAttributesForCertificate_allowedCert_returnsAttributes() throws NotFoundException {
        List<com.czertainly.api.model.common.attribute.common.BaseAttribute> attrs =
                signingProfileService.listSignatureAttributesForCertificate(rsaCertificate.getUuid());

        Assertions.assertNotNull(attrs);
        Assertions.assertFalse(attrs.isEmpty(), "RSA certificate should produce non-empty signature attributes");
    }

    @Test
    void testListSignatureAttributesForCertificate_deniedCert_throwsAccessDeniedException() {
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

        Assertions.assertThrows(
                AccessDeniedException.class,
                () -> signingProfileService.listSignatureAttributesForCertificate(rsaCertificate.getUuid())
        );
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Get
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testGetSigningProfile_returnsCorrectDto() throws NotFoundException {
        SigningProfileDto dto = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);

        Assertions.assertNotNull(dto);
        Assertions.assertEquals(savedProfile.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(savedProfile.getName(), dto.getName());
        Assertions.assertEquals(savedProfile.getDescription(), dto.getDescription());
        Assertions.assertFalse(dto.isEnabled());
        Assertions.assertEquals(1, dto.getVersion());
    }

    @Test
    void testGetSigningProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.getSigningProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001"), null));
    }

    @Test
    void testGetSigningProfile_specificVersion_returnsSnapshotData() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // Create a profile via service — this creates the version 1 snapshot
        SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("profile-for-version-get"));
        SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

        // Get with explicit version=1
        SigningProfileDto dto = signingProfileService.getSigningProfile(profileUuid, 1);

        Assertions.assertNotNull(dto);
        Assertions.assertEquals(1, dto.getVersion());
        Assertions.assertNotNull(dto.getSigningScheme());
        Assertions.assertEquals(SigningScheme.DELEGATED, dto.getSigningScheme().getSigningScheme());
        Assertions.assertNotNull(dto.getWorkflow());
        Assertions.assertEquals(SigningWorkflowType.RAW_SIGNING, dto.getWorkflow().getType());
    }

    @Test
    void testGetSigningProfile_nonExistentVersion_throwsNotFoundException() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("profile-missing-version"));
        SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

        // Version 99 does not exist
        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.getSigningProfile(profileUuid, 99));
    }

    @Test
    void testGetSigningProfile_afterVersionBump_oldVersionPreservesOriginalWorkflowType()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // Create with DELEGATED + RAW_SIGNING (version 1)
        SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("profile-history"));
        SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());
        SigningProfile entity = signingProfileRepository.findById(UUID.fromString(created.getUuid())).orElseThrow();

        // Update to DELEGATED + CONTENT_SIGNING → should bump to version 2
        signingProfileService.updateSigningProfile(profileUuid, buildDelegatedContentRequest("profile-history"));

        // Version 1 snapshot must still report RAW_SIGNING
        SigningProfileDto v1 = signingProfileService.getSigningProfile(profileUuid, 1);
        Assertions.assertEquals(1, v1.getVersion());
        Assertions.assertEquals(SigningWorkflowType.RAW_SIGNING, v1.getWorkflow().getType());

        // Latest (version 2) must report CONTENT_SIGNING
        SigningProfileDto latest = signingProfileService.getSigningProfile(profileUuid, null);
        Assertions.assertEquals(2, latest.getVersion());
        Assertions.assertEquals(SigningWorkflowType.CONTENT_SIGNING, latest.getWorkflow().getType());
    }

    @Test
    void testGetSigningProfile_noProtocolsLinked_enabledProtocolsIsEmpty() throws NotFoundException {
        // savedProfile has no TSP linked
        SigningProfileDto dto = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);

        Assertions.assertNotNull(dto.getEnabledProtocols());
        Assertions.assertTrue(dto.getEnabledProtocols().isEmpty(),
                "No protocols should be enabled when none are linked");
    }

    @Test
    void testGetSigningProfile_withTspLinked_enabledProtocolsContainsTsp() throws NotFoundException {
        TspProfile tspProfile = new TspProfile();
        tspProfile.setName("tsp-for-dto-test");
        tspProfile = tspRepository.save(tspProfile);

        savedProfile.setTspProfile(tspProfile);
        signingProfileRepository.save(savedProfile);

        SigningProfileDto dto = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);

        Assertions.assertNotNull(dto.getEnabledProtocols());
        Assertions.assertTrue(dto.getEnabledProtocols().contains(SigningProtocol.TSP),
                "TSP should appear in enabledProtocols");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Get entity
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testGetSigningProfileEntity_returnsCorrectEntity() throws NotFoundException {
        SigningProfile entity = signingProfileService.getSigningProfileEntity(savedProfile.getSecuredUuid());

        Assertions.assertNotNull(entity);
        Assertions.assertEquals(savedProfile.getUuid(), entity.getUuid());
        Assertions.assertEquals(savedProfile.getName(), entity.getName());
    }

    @Test
    void testGetSigningProfileEntity_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.getSigningProfileEntity(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Find all names
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testFindAllNames_returnsExistingNames() {
        List<String> names = signingProfileService.findAllNames();

        Assertions.assertNotNull(names);
        Assertions.assertEquals(1, names.size());
        Assertions.assertTrue(names.contains(savedProfile.getName()));
    }

    @Test
    void testFindAllNames_returnsAllWhenMultipleExist() {
        SigningProfile second = new SigningProfile();
        second.setName("second-signing-profile");
        signingProfileRepository.save(second);

        List<String> names = signingProfileService.findAllNames();

        Assertions.assertEquals(2, names.size());
        Assertions.assertTrue(names.contains(savedProfile.getName()));
        Assertions.assertTrue(names.contains("second-signing-profile"));
    }

    @Test
    void testFindAllNames_emptyWhenNoneExist() {
        signingProfileRepository.delete(savedProfile);

        List<String> names = signingProfileService.findAllNames();

        Assertions.assertNotNull(names);
        Assertions.assertTrue(names.isEmpty());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Create
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateSigningProfile_delegatedRawSigning_assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileRequestDto request = buildDelegatedRawRequest("new-delegated-profile");

        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        // Assert returned DTO
        Assertions.assertNotNull(dto);
        Assertions.assertNotNull(dto.getUuid());
        Assertions.assertEquals("new-delegated-profile", dto.getName());
        Assertions.assertEquals("Test description for new-delegated-profile", dto.getDescription());
        Assertions.assertFalse(dto.isEnabled());
        Assertions.assertEquals(1, dto.getVersion());
        Assertions.assertNotNull(dto.getSigningScheme());
        Assertions.assertNotNull(dto.getWorkflow());

        // Assert entity reloaded from the database
        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        SigningProfile entity = fromDb.get();
        Assertions.assertEquals("new-delegated-profile", entity.getName());
        Assertions.assertEquals("Test description for new-delegated-profile", entity.getDescription());
        Assertions.assertFalse(entity.getEnabled());
        Assertions.assertEquals(SigningScheme.DELEGATED, entity.getSigningScheme());
        Assertions.assertEquals(SigningWorkflowType.RAW_SIGNING, entity.getWorkflowType());
        Assertions.assertEquals(1, entity.getLatestVersion());

        SigningProfileVersion currentVersion = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
        // For delegated scheme without connector UUID in request, it should be null
        Assertions.assertNull(currentVersion.getDelegatedSignerConnectorUuid());
        // Version snapshot must carry scheme and workflow type
        Assertions.assertNotNull(currentVersion.getSigningScheme());
        Assertions.assertNotNull(currentVersion.getWorkflowType());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Create – Signing scheme variations
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateSigningProfile_staticKeyManaged_assertSchemeAndEntityFields()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileRequestDto request = buildManagedStaticKeyRawRequest("static-key-profile");

        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        // Assert scheme type in DTO
        Assertions.assertNotNull(dto.getSigningScheme());
        Assertions.assertEquals(SigningScheme.MANAGED, dto.getSigningScheme().getSigningScheme());

        // Assert entity fields
        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        SigningProfile entity = fromDb.get();
        Assertions.assertEquals(SigningScheme.MANAGED, entity.getSigningScheme());

        SigningProfileVersion currentVersion = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
        Assertions.assertEquals(ManagedSigningType.STATIC_KEY, currentVersion.getManagedSigningType());
        // No delegated connector when using the managed signing scheme
        Assertions.assertNull(currentVersion.getDelegatedSignerConnectorUuid());
        // No RA profile / CSR template for the static key managed signing scheme
        Assertions.assertNull(currentVersion.getRaProfileUuid());
        Assertions.assertNull(currentVersion.getCsrTemplateUuid());
    }

    @Test
    void testCreateSigningProfile_staticKeyManaged_incompleteChain_throwsValidationException()
            throws CertificateException, NoSuchAlgorithmException, OperatorCreationException {
        Certificate incompleteChainCert = buildIncompleteChainCertificate();

        StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
        scheme.setCertificateUuid(incompleteChainCert.getUuid());
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName("incomplete-chain-profile");
        request.setSigningScheme(scheme);
        request.setWorkflow(new RawSigningWorkflowRequestDto());

        Assertions.assertThrows(ValidationException.class,
                () -> signingProfileService.createSigningProfile(request),
                "createSigningProfile must reject a certificate whose chain is incomplete");
    }

    @Test
    void testCreateSigningProfile_oneTimeKeyManaged_assertSchemeAndEntityFields()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileRequestDto request = buildManagedOneTimeKeyRawRequest("one-time-key-profile");
        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        // Assert scheme type in DTO
        Assertions.assertNotNull(dto.getSigningScheme());
        Assertions.assertEquals(SigningScheme.MANAGED, dto.getSigningScheme().getSigningScheme());

        // Assert entity fields
        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        SigningProfile entity = fromDb.get();
        Assertions.assertEquals(SigningScheme.MANAGED, entity.getSigningScheme());

        SigningProfileVersion currentVersion = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
        Assertions.assertEquals(ManagedSigningType.ONE_TIME_KEY, currentVersion.getManagedSigningType());
        // No delegated connector when using managed scheme
        Assertions.assertNull(currentVersion.getDelegatedSignerConnectorUuid());
        // Certificate UUID is not set for one-time key type
        Assertions.assertNull(currentVersion.getCertificateUuid());
    }

    @Test
    void testCreateSigningProfile_managedSchemeTypes_allCreateVersionSnapshot()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // DELEGATED is intentionally excluded here — its snapshot creation is verified in
        // testCreateSigningProfile_delegatedRawSigning_assertDtoAndDbEntity.
        SigningProfileDto staticKeyDto = signingProfileService.createSigningProfile(buildManagedStaticKeyRawRequest("snapshot-static"));
        SigningProfileDto oneTimeKeyDto = signingProfileService.createSigningProfile(buildManagedOneTimeKeyRawRequest("snapshot-onetime"));

        for (String uuidStr : List.of(staticKeyDto.getUuid(), oneTimeKeyDto.getUuid())) {
            UUID profileUuid = UUID.fromString(uuidStr);
            Optional<SigningProfileVersion> snapshot = signingProfileVersionRepository.findBySigningProfileUuidAndVersion(profileUuid, 1);
            Assertions.assertTrue(snapshot.isPresent(),
                    "Version 1 should exist for profile " + uuidStr);
            Assertions.assertNotNull(snapshot.get().getSigningScheme());
            Assertions.assertNotNull(snapshot.get().getWorkflowType());
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Create – Workflow type variations
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateSigningProfile_contentSigningWorkflow_assertWorkflowTypeAndEntity()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileRequestDto request = buildDelegatedContentRequest("content-signing-profile");
        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        Assertions.assertNotNull(dto.getWorkflow());
        Assertions.assertEquals(SigningWorkflowType.CONTENT_SIGNING, dto.getWorkflow().getType());

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertEquals(SigningWorkflowType.CONTENT_SIGNING, fromDb.get().getWorkflowType());
    }

    @Test
    void testCreateSigningProfile_timestampingWorkflow_assertWorkflowTypeAndEntity()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileRequestDto request = buildDelegatedTimestampingRequest("timestamping-profile");
        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        Assertions.assertNotNull(dto.getWorkflow());
        Assertions.assertEquals(SigningWorkflowType.TIMESTAMPING, dto.getWorkflow().getType());

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertEquals(SigningWorkflowType.TIMESTAMPING, fromDb.get().getWorkflowType());
    }

    @Test
    void testCreateSigningProfile_timestampingWorkflowWithPoliciesAndAlgorithms_assertEntityFields()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
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
        request.setSigningScheme(new DelegatedSigningRequestDto());
        request.setWorkflow(timestampingWorkflow);

        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        // Assert workflow fields in DTO
        Assertions.assertNotNull(dto.getWorkflow());
        Assertions.assertEquals(SigningWorkflowType.TIMESTAMPING, dto.getWorkflow().getType());
        TimestampingWorkflowDto tsDto = (TimestampingWorkflowDto) dto.getWorkflow();
        Assertions.assertEquals("1.2.3.4.5", tsDto.getDefaultPolicyId());
        Assertions.assertEquals(List.of("1.2.3.4.5", "1.2.3.4.6"), tsDto.getAllowedPolicyIds());
        Assertions.assertTrue(tsDto.getAllowedDigestAlgorithms().contains(DigestAlgorithm.SHA_256));
        Assertions.assertTrue(tsDto.getAllowedDigestAlgorithms().contains(DigestAlgorithm.SHA_384));
        Assertions.assertFalse(tsDto.getQualifiedTimestamp());
        Assertions.assertTrue(tsDto.getValidateTokenSignature());

        // Assert entity fields in the database
        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        SigningProfile entity = fromDb.get();
        Assertions.assertEquals(SigningWorkflowType.TIMESTAMPING, entity.getWorkflowType());

        SigningProfileVersion currentVersion = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
        Assertions.assertEquals("1.2.3.4.5", currentVersion.getDefaultPolicyId());
        Assertions.assertEquals(List.of("1.2.3.4.5", "1.2.3.4.6"), currentVersion.getAllowedPolicyIds());
        Assertions.assertEquals(
                List.of(DigestAlgorithm.SHA_256.getCode(), DigestAlgorithm.SHA_384.getCode()),
                currentVersion.getAllowedDigestAlgorithms()
        );
        Assertions.assertFalse(currentVersion.getQualifiedTimestamp());
        Assertions.assertTrue(currentVersion.getValidateTokenSignature());
    }

    @Test
    void testCreateSigningProfile_managedStaticKey_withContentSigningWorkflow_assertBothFields()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName("managed-content-profile");
        request.setDescription("Managed static-key profile with content signing workflow");
        StaticKeyManagedSigningRequestDto managedContentScheme = new StaticKeyManagedSigningRequestDto();
        managedContentScheme.setCertificateUuid(certificate.getUuid());
        request.setSigningScheme(managedContentScheme);
        ContentSigningWorkflowRequestDto managedContentWorkflow = new ContentSigningWorkflowRequestDto();
        managedContentWorkflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        request.setWorkflow(managedContentWorkflow);

        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        Assertions.assertEquals(SigningScheme.MANAGED, dto.getSigningScheme().getSigningScheme());
        Assertions.assertEquals(SigningWorkflowType.CONTENT_SIGNING, dto.getWorkflow().getType());
        Assertions.assertFalse(dto.isEnabled());

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        SigningProfile entity = fromDb.get();
        Assertions.assertEquals(SigningScheme.MANAGED, entity.getSigningScheme());
        Assertions.assertEquals(SigningWorkflowType.CONTENT_SIGNING, entity.getWorkflowType());

        SigningProfileVersion currentVersion = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
        Assertions.assertEquals(ManagedSigningType.STATIC_KEY, currentVersion.getManagedSigningType());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Update
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testUpdateSigningProfile_assertDtoAndDbEntity() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileRequestDto request = buildDelegatedRawRequest("updated-profile");
        request.setDescription("Updated description");

        SigningProfileDto dto = signingProfileService.updateSigningProfile(savedProfile.getSecuredUuid(), request);

        // Assert returned DTO
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(savedProfile.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals("updated-profile", dto.getName());
        Assertions.assertEquals("Updated description", dto.getDescription());
        Assertions.assertFalse(dto.isEnabled());
        Assertions.assertEquals(2, dto.getVersion());

        // Assert entity reloaded from the database
        Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        SigningProfile entity = fromDb.get();
        Assertions.assertEquals("updated-profile", entity.getName());
        Assertions.assertEquals("Updated description", entity.getDescription());
        Assertions.assertFalse(entity.getEnabled());
        Assertions.assertEquals(2, entity.getLatestVersion());
        Assertions.assertEquals(SigningScheme.DELEGATED, entity.getSigningScheme());
        Assertions.assertEquals(SigningWorkflowType.RAW_SIGNING, entity.getWorkflowType());
    }

    @Test
    void testUpdateSigningProfile_versionBump_oldVersionAttributesPreservedInEngine()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // Create a STATIC_KEY profile (version 1) with known signing-op attributes
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

        // Verify v1 signing-op attributes are readable with version=1
        List<ResponseAttribute> v1Attrs = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                        .operation(AttributeOperation.SIGN).version(1).build());
        Assertions.assertFalse(v1Attrs.isEmpty(), "Version 1 signing-op attributes should be stored");

        // Trigger version bump: create a signing record for v1, then update with different signing attrs
        SigningProfile profileEntity = signingProfileRepository.findById(profileUuid).orElseThrow();

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
        Assertions.assertEquals(2, updated.getVersion());

        // Version 1 attributes must still be readable (historical record preserved)
        List<ResponseAttribute> v1AttrAfterBump = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                        .operation(AttributeOperation.SIGN).version(1).build());
        Assertions.assertFalse(v1AttrAfterBump.isEmpty(),
                "Version 1 signing-op attributes must be preserved after a version bump");

        // Version 2 must have the new attributes
        List<ResponseAttribute> v2Attrs = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                        .operation(AttributeOperation.SIGN).version(2).build());
        Assertions.assertFalse(v2Attrs.isEmpty(),
                "Version 2 signing-op attributes should be stored after bump");
    }

    @Test
    void testUpdateSigningProfile_versionBump_oldFormatterAttributesPreservedInEngine()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        Connector formatter = createFormatterConnector("formatter-bump-preserve");

        UUID attrUuid = UUID.randomUUID();
        String attrName = "data_bumpPreserveAttr";
        DataAttributeV2 attrDef = new DataAttributeV2();
        attrDef.setUuid(attrUuid.toString());
        attrDef.setName(attrName);
        attrDef.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Bump Preserve Attribute");
        attrDef.setProperties(props);
        attributeEngine.updateDataAttributeDefinitions(formatter.getUuid(), AttributeOperation.WORKFLOW_FORMATTER, List.of(attrDef));

        // Create a CONTENT_SIGNING profile (version 1) with formatter attributes
        ContentSigningWorkflowRequestDto wfV1 = new ContentSigningWorkflowRequestDto();
        wfV1.setSignatureFormatterConnectorUuid(formatter.getUuid());
        wfV1.setSignatureFormatterConnectorAttributes(List.of(buildFormatterAttribute(attrUuid, attrName, "v1-value")));

        SigningProfileRequestDto createRequest = new SigningProfileRequestDto();
        createRequest.setName("formatter-attrs-bump-preserve");
        createRequest.setSigningScheme(new DelegatedSigningRequestDto());
        createRequest.setWorkflow(wfV1);
        SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);
        UUID profileUuid = UUID.fromString(created.getUuid());

        // Verify v1 formatter attributes are stored
        List<ResponseAttribute> v1AttrsBefore = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                        .connector(formatter.getUuid())
                        .operation(AttributeOperation.WORKFLOW_FORMATTER).version(1).build());
        Assertions.assertFalse(v1AttrsBefore.isEmpty(), "Version 1 formatter attributes should be stored after create");

        // Trigger version bump: create a signing record for v1, then update
        SigningProfile profileEntity = signingProfileRepository.findById(profileUuid).orElseThrow();

        ContentSigningWorkflowRequestDto wfV2 = new ContentSigningWorkflowRequestDto();
        wfV2.setSignatureFormatterConnectorUuid(formatter.getUuid());
        wfV2.setSignatureFormatterConnectorAttributes(List.of(buildFormatterAttribute(attrUuid, attrName, "v2-value")));

        SigningProfileRequestDto updateRequest = new SigningProfileRequestDto();
        updateRequest.setName("formatter-attrs-bump-preserve");
        updateRequest.setSigningScheme(new DelegatedSigningRequestDto());
        updateRequest.setWorkflow(wfV2);
        SigningProfileDto updated = signingProfileService.updateSigningProfile(SecuredUUID.fromUUID(profileUuid), updateRequest);
        Assertions.assertEquals(2, updated.getVersion(), "Version must be bumped to 2");

        // Version 1 formatter attributes must still be readable (historical record preserved)
        List<ResponseAttribute> v1AttrsAfterBump = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                        .connector(formatter.getUuid())
                        .operation(AttributeOperation.WORKFLOW_FORMATTER).version(1).build());
        Assertions.assertFalse(v1AttrsAfterBump.isEmpty(),
                "Version 1 formatter attributes must be preserved after a version bump");

        // Version 2 must have its own formatter attributes
        List<ResponseAttribute> v2Attrs = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                        .connector(formatter.getUuid())
                        .operation(AttributeOperation.WORKFLOW_FORMATTER).version(2).build());
        Assertions.assertFalse(v2Attrs.isEmpty(),
                "Version 2 formatter attributes should be stored after bump");
    }

    @Test
    void testGetSigningProfile_specificVersion_returnsVersionedSigningOperationAttributes()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // Create a STATIC_KEY profile (version 1) with PSS signing attributes
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

        // Trigger version bump: add signing record, then update to PKCS1_v1_5
        SigningProfile profileEntity = signingProfileRepository.findById(UUID.fromString(created.getUuid())).orElseThrow();

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

        // getSigningProfile with version=1 must return PSS attributes
        SigningProfileDto v1Dto = signingProfileService.getSigningProfile(profileUuid, 1);
        Assertions.assertInstanceOf(StaticKeyManagedSigningDto.class, v1Dto.getSigningScheme());
        StaticKeyManagedSigningDto v1SchemeDto = (StaticKeyManagedSigningDto) v1Dto.getSigningScheme();
        Assertions.assertFalse(v1SchemeDto.getSigningOperationAttributes().isEmpty(),
                "Version 1 DTO must include signing-op attributes");
        Assertions.assertTrue(
                v1SchemeDto.getSigningOperationAttributes().stream()
                        .anyMatch(a -> RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME.equals(a.getName())),
                "Version 1 must contain RSA signature scheme attribute");

        // getSigningProfile with version=2 (latest) must return PKCS1_v1_5 attributes
        SigningProfileDto v2Dto = signingProfileService.getSigningProfile(profileUuid, 2);
        Assertions.assertInstanceOf(StaticKeyManagedSigningDto.class, v2Dto.getSigningScheme());
        StaticKeyManagedSigningDto v2SchemeDto = (StaticKeyManagedSigningDto) v2Dto.getSigningScheme();
        Assertions.assertFalse(v2SchemeDto.getSigningOperationAttributes().isEmpty(),
                "Version 2 DTO must include signing-op attributes");
        Assertions.assertTrue(
                v2SchemeDto.getSigningOperationAttributes().stream()
                        .anyMatch(a -> RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME.equals(a.getName())),
                "Version 2 must contain RSA signature scheme attribute");

        // The content stored for v1 (PSS) and v2 (PKCS1_v1_5) must differ in the engine
        List<ResponseAttribute> v1SignAttrs = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()))
                        .operation(AttributeOperation.SIGN).version(1).build());
        List<ResponseAttribute> v2SignAttrs = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()))
                        .operation(AttributeOperation.SIGN).version(2).build());
        Assertions.assertFalse(v1SignAttrs.isEmpty(), "Engine must hold v1 sign attrs");
        Assertions.assertFalse(v2SignAttrs.isEmpty(), "Engine must hold v2 sign attrs");
    }

    @Test
    void testUpdateSigningProfile_notFound_throwsNotFoundException() {
        SigningProfileRequestDto request = buildDelegatedRawRequest("does-not-matter");

        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.updateSigningProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001"), request));
    }

    @Test
    void testUpdateSigningProfile_changeSchemeFromDelegatedToStaticKeyManaged()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // savedProfile uses DELEGATED scheme
        Assertions.assertEquals(SigningScheme.DELEGATED, savedProfile.getSigningScheme());

        // Update to MANAGED/STATIC_KEY
        signingProfileService.updateSigningProfile(savedProfile.getSecuredUuid(), buildManagedStaticKeyRawRequest("scheme-switched"));

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        SigningProfile entity = fromDb.get();
        Assertions.assertEquals(SigningScheme.MANAGED, entity.getSigningScheme());

        SigningProfileVersion currentVersion = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
        Assertions.assertEquals(ManagedSigningType.STATIC_KEY, currentVersion.getManagedSigningType());
        // Previous delegated connector reference must have been cleared
        Assertions.assertNull(currentVersion.getDelegatedSignerConnectorUuid());
    }

    @Test
    void testUpdateSigningProfile_staticKeyManaged_incompleteChain_throwsValidationException()
            throws CertificateException, NoSuchAlgorithmException, OperatorCreationException {
        Certificate incompleteChainCert = buildIncompleteChainCertificate();

        StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
        scheme.setCertificateUuid(incompleteChainCert.getUuid());
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName("incomplete-chain-update");
        request.setSigningScheme(scheme);
        request.setWorkflow(new RawSigningWorkflowRequestDto());

        Assertions.assertThrows(ValidationException.class,
                () -> signingProfileService.updateSigningProfile(savedProfile.getSecuredUuid(), request),
                "updateSigningProfile must reject a certificate whose chain is incomplete");
    }

    @Test
    void testUpdateSigningProfile_changeSchemeFromStaticKeyManagedToDelegated()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // Create a MANAGED/STATIC_KEY profile first
        SigningProfileDto created = signingProfileService.createSigningProfile(buildManagedStaticKeyRawRequest("managed-to-delegated"));
        SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

        // Switch to DELEGATED
        signingProfileService.updateSigningProfile(profileUuid, buildDelegatedRawRequest("managed-to-delegated"));

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(created.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        SigningProfile entity = fromDb.get();
        Assertions.assertEquals(SigningScheme.DELEGATED, entity.getSigningScheme());

        SigningProfileVersion currentVersion = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
        // managedSigningType must have been cleared by applyScheme
        Assertions.assertNull(currentVersion.getManagedSigningType());
        // token profile and certificate references must have been cleared
        Assertions.assertNull(currentVersion.getCertificateUuid());
    }

    @Test
    void testUpdateSigningProfile_changeWorkflowFromRawToTimestamping()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // savedProfile uses RAW_SIGNING workflow
        TimestampingWorkflowRequestDto timestampingWorkflow = new TimestampingWorkflowRequestDto();
        timestampingWorkflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        timestampingWorkflow.setDefaultPolicyId("1.2.3.4.5");
        timestampingWorkflow.setAllowedPolicyIds(List.of("1.2.3.4.5"));
        timestampingWorkflow.setQualifiedTimestamp(false);
        timestampingWorkflow.setValidateTokenSignature(false);

        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName("workflow-changed");
        request.setDescription("Changed to timestamping");
        request.setSigningScheme(new DelegatedSigningRequestDto());
        request.setWorkflow(timestampingWorkflow);

        SigningProfileDto dto = signingProfileService.updateSigningProfile(savedProfile.getSecuredUuid(), request);

        Assertions.assertEquals(SigningWorkflowType.TIMESTAMPING, dto.getWorkflow().getType());

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        SigningProfile entity = fromDb.get();
        Assertions.assertEquals(SigningWorkflowType.TIMESTAMPING, entity.getWorkflowType());
        SigningProfileVersion currentVersion = signingProfileVersionRepository
                .findBySigningProfileUuidAndVersion(entity.getUuid(), entity.getLatestVersion()).orElseThrow();
        Assertions.assertEquals("1.2.3.4.5", currentVersion.getDefaultPolicyId());
        Assertions.assertFalse(currentVersion.getQualifiedTimestamp());
        Assertions.assertFalse(currentVersion.getValidateTokenSignature());
    }

    @Test
    void testUpdateSigningProfile_multipleBumps_versionsAccumulate()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // Create a profile (version 1)
        SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("multi-bump-profile"));
        SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());
        UUID profileUuidRaw = UUID.fromString(created.getUuid());
        SigningProfile entity = signingProfileRepository.findById(profileUuidRaw).orElseThrow();

        // Trigger first bump: add sig for v1, then update → v2
        signingProfileService.updateSigningProfile(profileUuid, buildDelegatedContentRequest("multi-bump-profile"));

        // Trigger second bump: add sig for v2, then update → v3
        entity = signingProfileRepository.findById(profileUuidRaw).orElseThrow();
        signingProfileService.updateSigningProfile(profileUuid, buildDelegatedTimestampingRequest("multi-bump-profile"));

        // Verify three snapshot versions exist
        Assertions.assertTrue(signingProfileVersionRepository.findBySigningProfileUuidAndVersion(profileUuidRaw, 1).isPresent());
        Assertions.assertTrue(signingProfileVersionRepository.findBySigningProfileUuidAndVersion(profileUuidRaw, 2).isPresent());
        Assertions.assertTrue(signingProfileVersionRepository.findBySigningProfileUuidAndVersion(profileUuidRaw, 3).isPresent());

        // Verify the latest is version 3 with TIMESTAMPING
        SigningProfileDto latest = signingProfileService.getSigningProfile(profileUuid, null);
        Assertions.assertEquals(3, latest.getVersion());
        Assertions.assertEquals(SigningWorkflowType.TIMESTAMPING, latest.getWorkflow().getType());

        // Verify version 1 still has RAW_SIGNING
        SigningProfileDto v1 = signingProfileService.getSigningProfile(profileUuid, 1);
        Assertions.assertEquals(SigningWorkflowType.RAW_SIGNING, v1.getWorkflow().getType());

        // Verify version 2 has CONTENT_SIGNING
        SigningProfileDto v2 = signingProfileService.getSigningProfile(profileUuid, 2);
        Assertions.assertEquals(SigningWorkflowType.CONTENT_SIGNING, v2.getWorkflow().getType());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Delete
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testDeleteSigningProfile_removesEntityFromDatabase() throws NotFoundException {
        signingProfileService.deleteSigningProfile(savedProfile.getSecuredUuid());

        Assertions.assertFalse(signingProfileRepository.findById(savedProfile.getUuid()).isPresent());
        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null));
    }

    @Test
    void testDeleteSigningProfile_notFound_throwsNotFoundException() {
        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.deleteSigningProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    @Test
    void testDeleteSigningProfile_usedAsDefaultInTspProfile_throwsValidationException() {
        TspProfile tspProfile = new TspProfile();
        tspProfile.setName("blocking-tsp-profile");
        tspProfile.setDefaultSigningProfile(savedProfile);
        tspRepository.save(tspProfile);

        Assertions.assertThrows(ValidationException.class,
                () -> signingProfileService.deleteSigningProfile(savedProfile.getSecuredUuid()));

        // Profile must still exist after the failed delete attempt
        Assertions.assertTrue(signingProfileRepository.findById(savedProfile.getUuid()).isPresent());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Bulk delete
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testBulkDeleteSigningProfiles_removesAllEntities() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileDto second = signingProfileService.createSigningProfile(buildDelegatedRawRequest("second-profile"));

        List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(
                List.of(savedProfile.getSecuredUuid(),
                        SecuredUUID.fromString(second.getUuid())));

        Assertions.assertNotNull(messages);
        Assertions.assertTrue(messages.isEmpty(), "Expected no errors but got: " + messages);
        Assertions.assertFalse(signingProfileRepository.findById(savedProfile.getUuid()).isPresent());
        Assertions.assertFalse(signingProfileRepository.findById(UUID.fromString(second.getUuid())).isPresent());
    }

    @Test
    void testBulkDeleteSigningProfiles_emptyList_returnsEmptyMessages() {
        List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(List.of());

        Assertions.assertNotNull(messages);
        Assertions.assertTrue(messages.isEmpty(), "Bulk delete of empty list should return no error messages");
    }

    @Test
    void testBulkDeleteSigningProfiles_withNonExistentUuid_silentlyIgnoresUnknown() {
        SecuredUUID unknownUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000099");

        List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(
                List.of(unknownUuid, savedProfile.getSecuredUuid()));

        // The unknown UUID surfaces as an error message; no exception is thrown
        Assertions.assertFalse(messages.isEmpty(), "An error message should be returned for the non-existent UUID");
        Assertions.assertTrue(messages.stream().anyMatch(m -> "00000000-0000-0000-0000-000000000099".equals(m.getUuid())));
        // The known profile must still have been deleted
        Assertions.assertFalse(signingProfileRepository.findById(savedProfile.getUuid()).isPresent(),
                "The known profile should be deleted even when the list contains an unknown UUID");
    }

    @Test
    void testDeleteSigningProfile_withNoSigningRecordsOrTspProfiles_succeeds() throws NotFoundException {
        // Precondition: no signing records and no TSP profiles reference savedProfile
        signingProfileService.deleteSigningProfile(savedProfile.getSecuredUuid());

        Assertions.assertFalse(signingProfileRepository.findById(savedProfile.getUuid()).isPresent(),
                "Profile with no dependents must be removed from the database");
    }

    @Test
    void testDeleteSigningProfile_usedAsDefaultInTspProfile_errorMessageContainsTspProfileName() {
        TspProfile tspProfile = new TspProfile();
        tspProfile.setName("expected-tsp-name");
        tspProfile.setDefaultSigningProfile(savedProfile);
        tspRepository.save(tspProfile);

        ValidationException ex = Assertions.assertThrows(ValidationException.class,
                () -> signingProfileService.deleteSigningProfile(savedProfile.getSecuredUuid()));

        String message = ex.getErrors().stream()
                .map(ValidationError::getErrorDescription)
                .findFirst()
                .orElse("");
        Assertions.assertTrue(message.contains("expected-tsp-name"),
                "Error message should contain the TSP profile name, got: " + message);
    }

    @Test
    void testBulkDeleteSigningProfiles_withTspProfileDependency_returnsErrorAndLeavesBlockedProfileIntact()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        TspProfile tspProfile = new TspProfile();
        tspProfile.setName("blocking-tsp");
        tspProfile.setDefaultSigningProfile(savedProfile);
        tspRepository.save(tspProfile);

        SigningProfileDto second = signingProfileService.createSigningProfile(buildDelegatedRawRequest("unblocked-profile"));

        List<BulkActionMessageDto> messages = signingProfileService.bulkDeleteSigningProfiles(
                List.of(savedProfile.getSecuredUuid(),
                        SecuredUUID.fromString(second.getUuid())));

        Assertions.assertFalse(messages.isEmpty(), "Expected an error message for the blocked profile");
        Assertions.assertTrue(messages.stream().anyMatch(m -> savedProfile.getUuid().toString().equals(m.getUuid())),
                "Error message should reference the blocked profile UUID");
        Assertions.assertTrue(signingProfileRepository.findById(savedProfile.getUuid()).isPresent(),
                "Blocked profile must still exist in the database");
        Assertions.assertFalse(signingProfileRepository.findById(UUID.fromString(second.getUuid())).isPresent(),
                "Unblocked profile must be deleted");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Enable / Disable
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testEnableSigningProfile() throws NotFoundException {
        Assertions.assertFalse(savedProfile.getEnabled());

        signingProfileService.enableSigningProfile(savedProfile.getSecuredUuid());

        SigningProfileDto dto = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);
        Assertions.assertTrue(dto.isEnabled());

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertTrue(fromDb.get().getEnabled());
    }

    @Test
    void testEnableSigningProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.enableSigningProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    @Test
    void testEnableSigningProfile_alreadyEnabled_remainsEnabled() throws NotFoundException {
        savedProfile.setEnabled(true);
        signingProfileRepository.save(savedProfile);

        // Enable again — should be idempotent
        signingProfileService.enableSigningProfile(savedProfile.getSecuredUuid());

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertTrue(fromDb.get().getEnabled(), "Profile should remain enabled after enabling an already-enabled profile");
    }

    @Test
    void testEnableSigningProfile_afterCreate_persistsEnabledState() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileRequestDto request = buildDelegatedRawRequest("enabled-profile");

        SigningProfileDto dto = signingProfileService.createSigningProfile(request);
        Assertions.assertFalse(dto.isEnabled(), "Profiles must be created in a disabled state");

        signingProfileService.enableSigningProfile(SecuredUUID.fromString(dto.getUuid()));

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(dto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertTrue(fromDb.get().getEnabled());
    }

    @Test
    void testDisableSigningProfile() throws NotFoundException {
        savedProfile.setEnabled(true);
        signingProfileRepository.save(savedProfile);

        signingProfileService.disableSigningProfile(savedProfile.getSecuredUuid());

        SigningProfileDto dto = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);
        Assertions.assertFalse(dto.isEnabled());

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertFalse(fromDb.get().getEnabled());
    }

    @Test
    void testDisableSigningProfile_notFound() {
        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.disableSigningProfile(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    @Test
    void testDisableSigningProfile_alreadyDisabled_remainsDisabled() throws NotFoundException {
        // savedProfile is already disabled (enabled = false from setUp)
        signingProfileService.disableSigningProfile(savedProfile.getSecuredUuid());

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertFalse(fromDb.get().getEnabled(), "Profile should remain disabled after disabling an already-disabled profile");
    }

    @Test
    void testBulkEnableSigningProfiles_multipleProfiles() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileDto second = signingProfileService.createSigningProfile(buildDelegatedRawRequest("second-for-bulk-enable"));
        SigningProfileDto third = signingProfileService.createSigningProfile(buildDelegatedContentRequest("third-for-bulk-enable"));

        signingProfileService.bulkEnableSigningProfiles(List.of(
                savedProfile.getSecuredUuid(),
                SecuredUUID.fromString(second.getUuid()),
                SecuredUUID.fromString(third.getUuid())
        ));

        Assertions.assertTrue(signingProfileRepository.findById(savedProfile.getUuid()).map(SigningProfile::getEnabled).orElse(false));
        Assertions.assertTrue(signingProfileRepository.findById(UUID.fromString(second.getUuid())).map(SigningProfile::getEnabled).orElse(false));
        Assertions.assertTrue(signingProfileRepository.findById(UUID.fromString(third.getUuid())).map(SigningProfile::getEnabled).orElse(false));
    }

    @Test
    void testBulkDisableSigningProfiles_multipleProfiles() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // Create two additional enabled profiles
        SigningProfileRequestDto req2 = buildDelegatedRawRequest("second-for-bulk-disable");
        SigningProfileDto second = signingProfileService.createSigningProfile(req2);
        signingProfileService.enableSigningProfile(SecuredUUID.fromString(second.getUuid()));

        SigningProfileRequestDto req3 = buildDelegatedContentRequest("third-for-bulk-disable");
        SigningProfileDto third = signingProfileService.createSigningProfile(req3);
        signingProfileService.enableSigningProfile(SecuredUUID.fromString(third.getUuid()));

        signingProfileService.bulkDisableSigningProfiles(List.of(
                SecuredUUID.fromString(second.getUuid()),
                SecuredUUID.fromString(third.getUuid())
        ));

        Assertions.assertFalse(signingProfileRepository.findById(UUID.fromString(second.getUuid())).map(SigningProfile::getEnabled).orElse(true));
        Assertions.assertFalse(signingProfileRepository.findById(UUID.fromString(third.getUuid())).map(SigningProfile::getEnabled).orElse(true));
    }

    @Test
    void testBulkEnableSigningProfiles_withNonExistentUuid_silentlyIgnores() {
        // A UUID that does not correspond to any profile
        SecuredUUID unknownUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000099");

        List<BulkActionMessageDto> messages = signingProfileService.bulkEnableSigningProfiles(
                List.of(unknownUuid, savedProfile.getSecuredUuid()));

        // The unknown UUID surfaces as an error message; no exception is thrown
        Assertions.assertFalse(messages.isEmpty(), "An error message should be returned for the non-existent UUID");
        Assertions.assertTrue(messages.stream().anyMatch(m -> "00000000-0000-0000-0000-000000000099".equals(m.getUuid())));
        // The known profile must still have been enabled
        Assertions.assertTrue(signingProfileRepository.findById(savedProfile.getUuid())
                        .map(SigningProfile::getEnabled).orElse(false),
                "The known profile should be enabled even when the list contains an unknown UUID");
    }

    @Test
    void testBulkDisableSigningProfiles_withNonExistentUuid_silentlyIgnores() {
        savedProfile.setEnabled(true);
        signingProfileRepository.save(savedProfile);

        SecuredUUID unknownUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000099");

        List<BulkActionMessageDto> messages = signingProfileService.bulkDisableSigningProfiles(
                List.of(unknownUuid, savedProfile.getSecuredUuid()));

        Assertions.assertFalse(messages.isEmpty(), "An error message should be returned for the non-existent UUID");
        Assertions.assertTrue(messages.stream().anyMatch(m -> "00000000-0000-0000-0000-000000000099".equals(m.getUuid())));
        Assertions.assertFalse(signingProfileRepository.findById(savedProfile.getUuid())
                        .map(SigningProfile::getEnabled).orElse(true),
                "The known profile should be disabled even when the list contains an unknown UUID");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Protocol activation — TSP
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testActivateTsp_setsLinkOnSigningProfile() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileDto profileDto = signingProfileService.createSigningProfile(buildDelegatedTimestampingRequest("timestamping-for-tsp-activate"));
        SecuredUUID profileUuid = SecuredUUID.fromString(profileDto.getUuid());

        TspProfile tspProfile = new TspProfile();
        tspProfile.setName("test-tsp-profile");
        tspProfile = tspRepository.save(tspProfile);

        var activationDto = signingProfileService.activateTsp(profileUuid, tspProfile.getSecuredUuid());
        Assertions.assertTrue(activationDto.isAvailable());
        Assertions.assertNotNull(activationDto.getSigningUrl());

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(profileDto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertEquals(tspProfile.getUuid(), fromDb.get().getTspProfileUuid());
    }

    @Test
    void testActivateTsp_profileNotFound_throwsNotFoundException() {
        TspProfile tspProfile = new TspProfile();
        tspProfile.setName("tsp-for-not-found-test");
        tspProfile = tspRepository.save(tspProfile);
        final UUID tspUuid = tspProfile.getUuid();

        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.activateTsp(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001"),
                        SecuredUUID.fromUUID(tspUuid)));
    }

    @Test
    void testActivateTsp_tspProfileNotFound_throwsNotFoundException() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileDto profileDto = signingProfileService.createSigningProfile(buildDelegatedTimestampingRequest("timestamping-for-tsp-not-found"));
        SecuredUUID profileUuid = SecuredUUID.fromString(profileDto.getUuid());

        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.activateTsp(
                        profileUuid,
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000002")));
    }

    @Test
    void testActivateTsp_replacesExistingLink() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileDto profileDto = signingProfileService.createSigningProfile(buildDelegatedTimestampingRequest("timestamping-for-tsp-replace"));
        SecuredUUID profileUuid = SecuredUUID.fromString(profileDto.getUuid());

        TspProfile tspProfile1 = new TspProfile();
        tspProfile1.setName("tsp-profile-1");
        tspProfile1 = tspRepository.save(tspProfile1);

        TspProfile tspProfile2 = new TspProfile();
        tspProfile2.setName("tsp-profile-2");
        tspProfile2 = tspRepository.save(tspProfile2);

        // Link the first profile
        signingProfileService.activateTsp(profileUuid, tspProfile1.getSecuredUuid());
        // Replace it with the second profile
        signingProfileService.activateTsp(profileUuid, tspProfile2.getSecuredUuid());

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(UUID.fromString(profileDto.getUuid()));
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertEquals(tspProfile2.getUuid(), fromDb.get().getTspProfileUuid(),
                "The profile should reference the second TSP profile after replacement");
    }

    @Test
    void testActivateTsp_unsupportedWorkflowType_throwsValidationException() {
        // savedProfile uses RAW_SIGNING which does not support TSP
        TspProfile tspProfile = new TspProfile();
        tspProfile.setName("tsp-profile-unsupported-workflow");
        tspProfile = tspRepository.save(tspProfile);
        final SecuredUUID tspUuid = tspProfile.getSecuredUuid();

        Assertions.assertThrows(ValidationException.class,
                () -> signingProfileService.activateTsp(savedProfile.getSecuredUuid(), tspUuid));
    }

    @Test
    void testDeactivateTsp_profileNotFound_throwsNotFoundException() {
        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.deactivateTsp(
                        SecuredUUID.fromString("00000000-0000-0000-0000-000000000001")));
    }

    @Test
    void testDeactivateTsp_removesFromEnabledProtocols() throws NotFoundException {
        TspProfile tspProfile = new TspProfile();
        tspProfile.setName("tsp-to-deactivate");
        tspProfile = tspRepository.save(tspProfile);

        savedProfile.setTspProfile(tspProfile);
        signingProfileRepository.save(savedProfile);

        // Verify TSP is listed as an enabled protocol before deactivation
        SigningProfileDto before = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);
        Assertions.assertTrue(before.getEnabledProtocols().contains(SigningProtocol.TSP));

        signingProfileService.deactivateTsp(savedProfile.getSecuredUuid());

        // TSP profile UUID must be null in the database after deactivation
        Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertNull(fromDb.get().getTspProfileUuid(),
                "TSP profile UUID must be cleared after deactivation");

        // After deactivation, TSP should no longer appear in enabled protocols
        SigningProfileDto after = signingProfileService.getSigningProfile(savedProfile.getSecuredUuid(), null);
        Assertions.assertFalse(after.getEnabledProtocols().contains(SigningProtocol.TSP),
                "TSP should be removed from enabledProtocols after deactivation");
    }

    @Test
    void testDeactivateTsp_noLinkExists_isIdempotent() {
        // savedProfile has no TSP link from setUp — calling deactivateTsp should be a no-op
        Assertions.assertNull(savedProfile.getTspProfileUuid());

        Assertions.assertDoesNotThrow(() -> signingProfileService.deactivateTsp(savedProfile.getSecuredUuid()),
                "deactivateTsp must not throw when no TSP is currently linked");

        Optional<SigningProfile> fromDb = signingProfileRepository.findById(savedProfile.getUuid());
        Assertions.assertTrue(fromDb.isPresent());
        Assertions.assertNull(fromDb.get().getTspProfileUuid(),
                "TSP profile UUID should still be null after a no-op deactivation");
    }

    @Test
    void testActivateTsp_contentSigningWorkflow_throwsValidationException()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // CONTENT_SIGNING, like RAW_SIGNING, is not mapped to TSP in SUPPORTED_PROTOCOLS
        SigningProfileDto profileDto = signingProfileService.createSigningProfile(buildDelegatedContentRequest("content-for-tsp-test"));
        SecuredUUID profileUuid = SecuredUUID.fromString(profileDto.getUuid());

        TspProfile tspProfile = new TspProfile();
        tspProfile.setName("tsp-for-content-workflow");
        tspProfile = tspRepository.save(tspProfile);
        final SecuredUUID tspUuid = tspProfile.getSecuredUuid();

        Assertions.assertThrows(ValidationException.class,
                () -> signingProfileService.activateTsp(profileUuid, tspUuid),
                "activateTsp must reject CONTENT_SIGNING workflow with a ValidationException");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Connector attribute persistence — signingOperationAttributes
    // ──────────────────────────────────────────────────────────────────────────

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

    @Test
    void testCreateSigningProfile_staticKey_signingOperationAttributesPersistedAndReturned()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
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

        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        // The returned DTO must expose the persisted signing operation attributes
        Assertions.assertInstanceOf(StaticKeyManagedSigningDto.class, dto.getSigningScheme());
        StaticKeyManagedSigningDto schemeDto = (StaticKeyManagedSigningDto) dto.getSigningScheme();
        Assertions.assertNotNull(schemeDto.getSigningOperationAttributes());
        Assertions.assertFalse(schemeDto.getSigningOperationAttributes().isEmpty(),
                "Signing operation attributes should be populated after create");
        Assertions.assertTrue(
                schemeDto.getSigningOperationAttributes().stream()
                        .anyMatch(a -> RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME.equals(a.getName())),
                "RSA signature scheme attribute should be present in the returned DTO");
    }

    @Test
    void testGetSigningProfile_staticKey_signingOperationAttributesLoadedFromEngine()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
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

        // Re-fetch — attributes must be loaded from AttributeEngine
        SigningProfileDto fetched = signingProfileService.getSigningProfile(profileUuid, null);
        Assertions.assertInstanceOf(StaticKeyManagedSigningDto.class, fetched.getSigningScheme());
        StaticKeyManagedSigningDto schemeDto = (StaticKeyManagedSigningDto) fetched.getSigningScheme();
        Assertions.assertFalse(schemeDto.getSigningOperationAttributes().isEmpty(),
                "Signing operation attributes should survive a create→get round-trip");
    }

    @Test
    void testUpdateSigningProfile_staticKey_signingOperationAttributesReplacedOnUpdate()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // Create with PKCS1-v1_5 / SHA-256
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

        // Update to PSS / SHA-384
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

        Assertions.assertInstanceOf(StaticKeyManagedSigningDto.class, updated.getSigningScheme());
        StaticKeyManagedSigningDto schemeDto = (StaticKeyManagedSigningDto) updated.getSigningScheme();
        List<ResponseAttribute> signingOperationAttributes = schemeDto.getSigningOperationAttributes();
        Assertions.assertFalse(signingOperationAttributes.isEmpty());
        Optional<ResponseAttribute> rsaSigningSchemeAttribute = signingOperationAttributes.stream().filter(
                a -> RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME.equals(a.getName())).findFirst();
        Assertions.assertTrue(rsaSigningSchemeAttribute.isPresent());
        // The RSA sig-scheme attribute content should reflect the new PSS value, not the old PKCS1-v1_5
        if (AttributeVersion.V2.equals(rsaSigningSchemeAttribute.get().getVersion())) {
            ResponseAttributeV2 rsaSigningSchemeAttributeV2 = (ResponseAttributeV2) rsaSigningSchemeAttribute.get();
            var attributeContentV2 = rsaSigningSchemeAttributeV2.getContent().getFirst();
            Assertions.assertEquals(RsaSignatureScheme.PSS.getCode(), attributeContentV2.getData().toString(),
                    "Signing operation attributes should be replaced with new value on update");
        } else if (AttributeVersion.V3.equals(rsaSigningSchemeAttribute.get().getVersion())) {
            ResponseAttributeV3 rsaSigningSchemeAttributeV3 = (ResponseAttributeV3) rsaSigningSchemeAttribute.get();
            var attributeContentV3 = rsaSigningSchemeAttributeV3.getContent().getFirst();
            Assertions.assertEquals(RsaSignatureScheme.PSS.getCode(), attributeContentV3.getData().toString(),
                    "Signing operation attributes should be replaced with new value on update");
        } else {
            Assertions.fail("Unknown attribute version: " + rsaSigningSchemeAttribute.get().getVersion() + " - the test needs to be updated to handle this version");
        }
    }

    @Test
    void testUpdateSigningProfile_schemeChangedToNonStaticKey_signingOperationAttributesCleared()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // Create a STATIC_KEY profile with signing operation attributes
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

        // Switch to DELEGATED — should clear signing-operation attributes from the engine
        signingProfileService.updateSigningProfile(profileUuid, buildDelegatedRawRequest("static-key-to-delegated"));

        // Verify nothing remains in AttributeEngine under SIGNING_SCHEME for this profile (version 2)
        List<ResponseAttribute> remaining = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()))
                        .operation(AttributeOperation.SIGN).version(2).build());
        Assertions.assertTrue(remaining.isEmpty(),
                "Signing-scheme attributes should be deleted when scheme changes away from STATIC_KEY");
    }

    @Test
    void testDeleteSigningProfile_removesSigningOperationAttributesFromEngine()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
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

        signingProfileService.deleteSigningProfile(SecuredUUID.fromUUID(profileUuid));

        // AttributeEngine should have no attributes left for this profile
        List<ResponseAttribute> remaining = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                        .operation(AttributeOperation.SIGN).version(1).build());
        Assertions.assertTrue(remaining.isEmpty(),
                "Signing-scheme attributes should be removed by deleteObjectAttributeContent on profile deletion");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Connector attribute persistence — signatureFormatterConnectorAttributes
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Creates and persists a minimal {@link Connector} entity for use as a signature formatter connector,
     * also pre-registering a simple data attribute definition so that AttributeEngine can accept content.
     */
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

    /**
     * Builds a {@link RequestAttributeV2} to use as a formatter connector attribute in tests.
     * The UUID and name here are arbitrary but must be pre-registered via
     * {@link AttributeEngine#updateDataAttributeDefinitions} before being stored.
     */
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

    @Test
    void testCreateSigningProfile_contentSigning_formatterAttributesPersistedAndReturned()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        Connector formatter = createFormatterConnector("formatter-content-create");

        // Pre-register the attribute definition so the engine can store content for it
        UUID attrUuid = UUID.randomUUID();
        String attrName = "data_testFormatterAttr";
        DataAttributeV2 attrDef = new DataAttributeV2();
        attrDef.setUuid(attrUuid.toString());
        attrDef.setName(attrName);
        attrDef.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Test Formatter Attribute");
        attrDef.setProperties(props);
        attributeEngine.updateDataAttributeDefinitions(formatter.getUuid(), AttributeOperation.WORKFLOW_FORMATTER, List.of(attrDef));

        ContentSigningWorkflowRequestDto workflow = new ContentSigningWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatter.getUuid());
        workflow.setSignatureFormatterConnectorAttributes(
                List.of(buildFormatterAttribute(attrUuid, attrName, "testValue")));

        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName("doc-profile-with-formatter-attrs");
        request.setSigningScheme(new DelegatedSigningRequestDto());
        request.setWorkflow(workflow);

        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        Assertions.assertInstanceOf(ContentSigningWorkflowDto.class, dto.getWorkflow());
        ContentSigningWorkflowDto wfDto = (ContentSigningWorkflowDto) dto.getWorkflow();
        Assertions.assertFalse(wfDto.getSignatureFormatterConnectorAttributes().isEmpty(),
                "Formatter connector attributes should be populated after create");
        Assertions.assertEquals(attrName, wfDto.getSignatureFormatterConnectorAttributes().getFirst().getName());
    }

    @Test
    void testUpdateSigningProfile_workflowFormatterConnectorChanged_oldAttributesCleared()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        Connector formatterA = createFormatterConnector("formatter-old");
        Connector formatterB = createFormatterConnector("formatter-new");

        // Pre-register attribute definition for both connectors
        UUID attrUuid = UUID.randomUUID();
        String attrName = "data_switchTest";
        DataAttributeV2 attrDef = new DataAttributeV2();
        attrDef.setUuid(attrUuid.toString());
        attrDef.setName(attrName);
        attrDef.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Switch Test Attribute");
        attrDef.setProperties(props);
        attributeEngine.updateDataAttributeDefinitions(formatterA.getUuid(), AttributeOperation.WORKFLOW_FORMATTER, List.of(attrDef));
        attributeEngine.updateDataAttributeDefinitions(formatterB.getUuid(), AttributeOperation.WORKFLOW_FORMATTER, List.of(attrDef));

        // Create with formatterA
        ContentSigningWorkflowRequestDto workflowA = new ContentSigningWorkflowRequestDto();
        workflowA.setSignatureFormatterConnectorUuid(formatterA.getUuid());
        workflowA.setSignatureFormatterConnectorAttributes(
                List.of(buildFormatterAttribute(attrUuid, attrName, "valueA")));

        SigningProfileRequestDto createRequest = new SigningProfileRequestDto();
        createRequest.setName("workflow-formatter-switch");
        createRequest.setSigningScheme(new DelegatedSigningRequestDto());
        createRequest.setWorkflow(workflowA);

        SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);
        SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());
        UUID profileUuidRaw = UUID.fromString(created.getUuid());

        // Update with formatterB — old formatter A attributes should be cleared
        ContentSigningWorkflowRequestDto workflowB = new ContentSigningWorkflowRequestDto();
        workflowB.setSignatureFormatterConnectorUuid(formatterB.getUuid());
        workflowB.setSignatureFormatterConnectorAttributes(
                List.of(buildFormatterAttribute(attrUuid, attrName, "valueB")));

        SigningProfileRequestDto updateRequest = new SigningProfileRequestDto();
        updateRequest.setName("workflow-formatter-switch");
        updateRequest.setSigningScheme(new DelegatedSigningRequestDto());
        updateRequest.setWorkflow(workflowB);

        signingProfileService.updateSigningProfile(profileUuid, updateRequest);

        // Attributes for old formatterA should be gone (version 2)
        List<ResponseAttribute> oldAttrs = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                        .connector(formatterA.getUuid())
                        .operation(AttributeOperation.WORKFLOW_FORMATTER).version(2).build());
        Assertions.assertTrue(oldAttrs.isEmpty(),
                "Attributes for the old formatter connector should be removed when the connector changes");

        // Attributes for new formatterB should be present
        List<ResponseAttribute> newAttrs = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                        .connector(formatterB.getUuid())
                        .operation(AttributeOperation.WORKFLOW_FORMATTER).version(2).build());
        Assertions.assertFalse(newAttrs.isEmpty(),
                "Attributes for the new formatter connector should be stored after the update");
    }

    @Test
    void testGetSigningProfile_formatterAttributesReturnedForAllWorkflowTypes()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        Connector formatter = createFormatterConnector("formatter-multi-workflow");

        UUID attrUuid = UUID.randomUUID();
        String attrName = "data_multiWorkflowAttr";
        DataAttributeV2 attrDef = new DataAttributeV2();
        attrDef.setUuid(attrUuid.toString());
        attrDef.setName(attrName);
        attrDef.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Multi Workflow Attribute");
        attrDef.setProperties(props);
        attributeEngine.updateDataAttributeDefinitions(formatter.getUuid(), AttributeOperation.WORKFLOW_FORMATTER, List.of(attrDef));

        for (SigningWorkflowType workflowLabel : List.of(SigningWorkflowType.CONTENT_SIGNING, SigningWorkflowType.TIMESTAMPING)) {
            WorkflowRequestDto wfRequest;
            switch (workflowLabel) {
                case CONTENT_SIGNING -> {
                    ContentSigningWorkflowRequestDto wf = new ContentSigningWorkflowRequestDto();
                    wf.setSignatureFormatterConnectorUuid(formatter.getUuid());
                    wf.setSignatureFormatterConnectorAttributes(List.of(buildFormatterAttribute(attrUuid, attrName, "val-" + workflowLabel)));
                    wfRequest = wf;
                }
                case TIMESTAMPING -> {
                    TimestampingWorkflowRequestDto wf = new TimestampingWorkflowRequestDto();
                    wf.setSignatureFormatterConnectorUuid(formatter.getUuid());
                    wf.setSignatureFormatterConnectorAttributes(List.of(buildFormatterAttribute(attrUuid, attrName, "val-" + workflowLabel)));
                    wfRequest = wf;
                }
                default -> throw new IllegalStateException("Unexpected workflow type: " + workflowLabel);
            }

            SigningProfileRequestDto request = new SigningProfileRequestDto();
            request.setName("formatter-attrs-" + workflowLabel);
            request.setSigningScheme(new DelegatedSigningRequestDto());
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
            Assertions.assertFalse(fetchedAttrs.isEmpty(),
                    "Formatter attributes should be loaded for workflow type: " + workflowLabel);
            Assertions.assertEquals(attrName, fetchedAttrs.getFirst().getName());
        }
    }

    @Test
    void testDeleteSigningProfile_removesFormatterAttributesFromEngine()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        Connector formatter = createFormatterConnector("formatter-delete-test");

        UUID attrUuid = UUID.randomUUID();
        String attrName = "data_deleteFormatterAttr";
        DataAttributeV2 attrDef = new DataAttributeV2();
        attrDef.setUuid(attrUuid.toString());
        attrDef.setName(attrName);
        attrDef.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel("Delete Formatter Attribute");
        attrDef.setProperties(props);
        attributeEngine.updateDataAttributeDefinitions(formatter.getUuid(), AttributeOperation.WORKFLOW_FORMATTER, List.of(attrDef));

        ContentSigningWorkflowRequestDto workflow = new ContentSigningWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatter.getUuid());
        workflow.setSignatureFormatterConnectorAttributes(
                List.of(buildFormatterAttribute(attrUuid, attrName, "toDelete")));

        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName("delete-clears-formatter-attrs");
        request.setSigningScheme(new DelegatedSigningRequestDto());
        request.setWorkflow(workflow);

        SigningProfileDto created = signingProfileService.createSigningProfile(request);
        UUID profileUuid = UUID.fromString(created.getUuid());

        signingProfileService.deleteSigningProfile(SecuredUUID.fromUUID(profileUuid));

        List<ResponseAttribute> remaining = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(Resource.SIGNING_PROFILE, profileUuid)
                        .connector(formatter.getUuid())
                        .operation(AttributeOperation.WORKFLOW_FORMATTER).version(1).build());
        Assertions.assertTrue(remaining.isEmpty(),
                "Formatter attributes should be removed by deleteObjectAttributeContent on profile deletion");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Formatter attribute validation against connector-returned definitions
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateSigningProfile_contentSigning_formatterAttributeMatchesConnectorDefinition_valid()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
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
        request.setSigningScheme(new DelegatedSigningRequestDto());
        request.setWorkflow(workflow);

        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        Assertions.assertNotNull(dto);
        Assertions.assertEquals(SigningWorkflowType.CONTENT_SIGNING, dto.getWorkflow().getType());
        ContentSigningWorkflowDto wfDto = (ContentSigningWorkflowDto) dto.getWorkflow();
        Assertions.assertFalse(wfDto.getSignatureFormatterConnectorAttributes().isEmpty(),
                "Formatter attribute that passes connector-definition validation must be persisted");
    }

    @Test
    void testCreateSigningProfile_contentSigning_requiredFormatterAttributeMissing_throwsValidationException() {
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
        request.setSigningScheme(new DelegatedSigningRequestDto());
        request.setWorkflow(workflow);

        Assertions.assertThrows(ValidationException.class,
                () -> signingProfileService.createSigningProfile(request),
                "createSigningProfile must reject missing required formatter attribute in CONTENT_SIGNING workflow");
    }

    @Test
    void testCreateSigningProfile_timestamping_requiredFormatterAttributeMissing_throwsValidationException() {
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
        request.setSigningScheme(new DelegatedSigningRequestDto());
        request.setWorkflow(workflow);

        Assertions.assertThrows(ValidationException.class,
                () -> signingProfileService.createSigningProfile(request),
                "createSigningProfile must reject missing required formatter attribute in TIMESTAMPING workflow");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Custom attributes via ResourceExtensionService
    // ──────────────────────────────────────────────────────────────────────────


    @Test
    void testCreateSigningProfile_withCustomAttributes_returnedInDto() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        RequestAttributeV3 customAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("profile-value-on-create")));

        SigningProfileRequestDto request = buildDelegatedRawRequest("profile-with-custom-attr");
        request.setCustomAttributes(List.of(customAttr));

        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        Assertions.assertNotNull(dto.getCustomAttributes());
        Assertions.assertFalse(dto.getCustomAttributes().isEmpty(),
                "Custom attributes should be returned in the create DTO");
        Assertions.assertEquals("profile-value-on-create",
                ((ResponseAttributeV3) dto.getCustomAttributes().getFirst()).getContent().getFirst().getData());
    }

    @Test
    void testUpdateSigningProfile_withCustomAttributes_returnedInDto() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        RequestAttributeV3 createAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("initial-value")));
        SigningProfileRequestDto createRequest = buildDelegatedRawRequest("profile-update-custom-attr");
        createRequest.setCustomAttributes(List.of(createAttr));
        SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);

        RequestAttributeV3 updateAttr = new RequestAttributeV3(UUID.fromString(CUSTOM_ATTR_UUID),
                CUSTOM_ATTR_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3("updated-value")));
        SigningProfileRequestDto updateRequest = buildDelegatedRawRequest("profile-update-custom-attr");
        updateRequest.setCustomAttributes(List.of(updateAttr));
        SigningProfileDto updated = signingProfileService.updateSigningProfile(
                SecuredUUID.fromString(created.getUuid()), updateRequest);

        Assertions.assertNotNull(updated.getCustomAttributes());
        Assertions.assertFalse(updated.getCustomAttributes().isEmpty());
        Assertions.assertEquals("updated-value",
                ((ResponseAttributeV3) updated.getCustomAttributes().getFirst()).getContent().getFirst().getData());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Name uniqueness
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateSigningProfile_duplicateName_throwsAlreadyExistException()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        signingProfileService.createSigningProfile(buildDelegatedRawRequest("duplicate-name"));

        Assertions.assertThrows(AlreadyExistException.class,
                () -> signingProfileService.createSigningProfile(buildDelegatedRawRequest("duplicate-name")));
    }

    @Test
    void testUpdateSigningProfile_toExistingNameOfAnotherProfile_throwsAlreadyExistException()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        signingProfileService.createSigningProfile(buildDelegatedRawRequest("profile-alpha"));
        SigningProfileDto beta = signingProfileService.createSigningProfile(buildDelegatedRawRequest("profile-beta"));

        SigningProfileRequestDto updateRequest = buildDelegatedRawRequest("profile-alpha");

        Assertions.assertThrows(AlreadyExistException.class,
                () -> signingProfileService.updateSigningProfile(SecuredUUID.fromString(beta.getUuid()), updateRequest));
    }

    @Test
    void testUpdateSigningProfile_keepingSameName_succeeds() throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("keep-same-name"));

        SigningProfileRequestDto updateRequest = buildDelegatedRawRequest("keep-same-name");
        updateRequest.setDescription("updated description");

        SigningProfileDto updated = signingProfileService.updateSigningProfile(SecuredUUID.fromString(created.getUuid()), updateRequest);

        Assertions.assertEquals("keep-same-name", updated.getName());
        Assertions.assertEquals("updated description", updated.getDescription());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // TimeQualityConfiguration linkage on timestamping workflow
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testCreateSigningProfile_timestampingWorkflow_withTimeQualityConfigurationUuid_headerLinkedAndReturnedInDto()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-for-create-link"));

        TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        workflow.setTimeQualityConfigurationUuid(UUID.fromString(tqc.getUuid()));

        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName("ts-with-tqc");
        request.setSigningScheme(new DelegatedSigningRequestDto());
        request.setWorkflow(workflow);

        SigningProfileDto dto = signingProfileService.createSigningProfile(request);

        // Header entity in DB must link to the TQC
        SigningProfile entity = signingProfileRepository.findById(UUID.fromString(dto.getUuid())).orElseThrow();
        Assertions.assertNotNull(entity.getTimeQualityConfiguration(),
                "SigningProfile header must have a linked TimeQualityConfiguration");
        Assertions.assertEquals(UUID.fromString(tqc.getUuid()), entity.getTimeQualityConfiguration().getUuid());

        // DTO must carry back the TQC data
        TimestampingWorkflowDto tsDto = (TimestampingWorkflowDto) dto.getWorkflow();
        Assertions.assertNotNull(tsDto.getTimeQualityConfiguration(),
                "TimestampingWorkflowDto must expose the linked TimeQualityConfiguration");
        Assertions.assertEquals(tqc.getUuid(), tsDto.getTimeQualityConfiguration().getUuid());
    }

    @Test
    void testCreateSigningProfile_timestampingWorkflow_withNonExistentTimeQualityConfigurationUuid_throwsNotFoundException() {
        TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        workflow.setTimeQualityConfigurationUuid(UUID.randomUUID());

        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName("ts-bad-tqc");
        request.setSigningScheme(new DelegatedSigningRequestDto());
        request.setWorkflow(workflow);

        Assertions.assertThrows(NotFoundException.class,
                () -> signingProfileService.createSigningProfile(request));
    }

    @Test
    void testUpdateSigningProfile_workflowChangedFromTimestamping_timeQualityConfigurationClearedFromHeader()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-for-clear-test"));

        TimestampingWorkflowRequestDto timestampingWorkflow = new TimestampingWorkflowRequestDto();
        timestampingWorkflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        timestampingWorkflow.setTimeQualityConfigurationUuid(UUID.fromString(tqc.getUuid()));

        SigningProfileRequestDto createRequest = new SigningProfileRequestDto();
        createRequest.setName("ts-to-raw-profile");
        createRequest.setSigningScheme(new DelegatedSigningRequestDto());
        createRequest.setWorkflow(timestampingWorkflow);

        SigningProfileDto created = signingProfileService.createSigningProfile(createRequest);

        // Verify TQC is linked before the update
        SigningProfile beforeUpdate = signingProfileRepository.findById(UUID.fromString(created.getUuid())).orElseThrow();
        Assertions.assertNotNull(beforeUpdate.getTimeQualityConfiguration());

        // Update to RAW_SIGNING - TQC must be cleared from the workflow
        SigningProfileRequestDto updateRequest = new SigningProfileRequestDto();
        updateRequest.setName("ts-to-raw-profile");
        updateRequest.setSigningScheme(new DelegatedSigningRequestDto());
        updateRequest.setWorkflow(new RawSigningWorkflowRequestDto());
        signingProfileService.updateSigningProfile(SecuredUUID.fromString(created.getUuid()), updateRequest);

        SigningProfile afterUpdate = signingProfileRepository.findById(UUID.fromString(created.getUuid())).orElseThrow();
        Assertions.assertNull(afterUpdate.getTimeQualityConfiguration(),
                "TimeQualityConfiguration must be cleared when workflow is changed away from TIMESTAMPING");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // listSigningProfilesAssociatedTimeQualityConfiguration
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void testListSigningProfilesAssociatedTimeQualityConfiguration_returnsAssociatedProfiles()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-for-list-test"));
        UUID tqcUuid = UUID.fromString(tqc.getUuid());

        TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        workflow.setTimeQualityConfigurationUuid(tqcUuid);

        SigningProfileRequestDto r1 = new SigningProfileRequestDto();
        r1.setName("list-ts-profile-one");
        r1.setSigningScheme(new DelegatedSigningRequestDto());
        r1.setWorkflow(workflow);
        SigningProfileDto p1 = signingProfileService.createSigningProfile(r1);

        TimestampingWorkflowRequestDto workflow2 = new TimestampingWorkflowRequestDto();
        workflow2.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        workflow2.setTimeQualityConfigurationUuid(tqcUuid);
        SigningProfileRequestDto r2 = new SigningProfileRequestDto();
        r2.setName("list-ts-profile-two");
        r2.setSigningScheme(new DelegatedSigningRequestDto());
        r2.setWorkflow(workflow2);
        SigningProfileDto p2 = signingProfileService.createSigningProfile(r2);

        List<SimplifiedSigningProfileDto> result = signingProfileService
                .listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID.fromUUID(tqcUuid), SecurityFilter.create());

        Assertions.assertEquals(2, result.size());
        List<String> returnedUuids = result.stream().map(SimplifiedSigningProfileDto::getUuid).toList();
        Assertions.assertTrue(returnedUuids.contains(p1.getUuid()));
        Assertions.assertTrue(returnedUuids.contains(p2.getUuid()));
    }

    @Test
    void testListSigningProfilesAssociatedTimeQualityConfiguration_emptyWhenNoneAssociated()
            throws AlreadyExistException, AttributeException, NotFoundException {
        TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-no-profiles"));

        List<SimplifiedSigningProfileDto> result = signingProfileService
                .listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID.fromString(tqc.getUuid()), SecurityFilter.create());

        Assertions.assertTrue(result.isEmpty(),
                "No signing profiles should be returned for a TQC with no associated profiles");
    }

    @Test
    void testListSigningProfilesAssociatedTimeQualityConfiguration_returnsOnlyProfilesLinkedToSpecificTqc()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        TimeQualityConfigurationDto tqcA = timeQualityConfigurationService
                .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-A"));
        TimeQualityConfigurationDto tqcB = timeQualityConfigurationService
                .createTimeQualityConfiguration(buildTimeQualityConfigurationRequestDto("tqc-B"));

        TimestampingWorkflowRequestDto workflowA = new TimestampingWorkflowRequestDto();
        workflowA.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        workflowA.setTimeQualityConfigurationUuid(UUID.fromString(tqcA.getUuid()));
        SigningProfileRequestDto reqA = new SigningProfileRequestDto();
        reqA.setName("profile-linked-to-tqc-A");
        reqA.setSigningScheme(new DelegatedSigningRequestDto());
        reqA.setWorkflow(workflowA);
        SigningProfileDto profileA = signingProfileService.createSigningProfile(reqA);

        TimestampingWorkflowRequestDto workflowB = new TimestampingWorkflowRequestDto();
        workflowB.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        workflowB.setTimeQualityConfigurationUuid(UUID.fromString(tqcB.getUuid()));
        SigningProfileRequestDto reqB = new SigningProfileRequestDto();
        reqB.setName("profile-linked-to-tqc-B");
        reqB.setSigningScheme(new DelegatedSigningRequestDto());
        reqB.setWorkflow(workflowB);
        signingProfileService.createSigningProfile(reqB);

        List<SimplifiedSigningProfileDto> result = signingProfileService
                .listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID.fromString(tqcA.getUuid()), SecurityFilter.create());

        Assertions.assertEquals(1, result.size());
        Assertions.assertEquals(profileA.getUuid(), result.getFirst().getUuid(),
                "Only the profile linked to TQC-A should be returned");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Builds a minimal valid SigningProfileRequestDto using a DELEGATED scheme and RAW_SIGNING workflow
     * (no foreign-key dependencies on connectors, token profiles, or keys).
     */
    private SigningProfileRequestDto buildDelegatedRawRequest(String name) {
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test description for " + name);
        request.setSigningScheme(new DelegatedSigningRequestDto());
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
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test description for " + name);
        request.setSigningScheme(new OneTimeKeyManagedSigningRequestDto());
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
        request.setSigningScheme(new DelegatedSigningRequestDto());
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
        request.setSigningScheme(new DelegatedSigningRequestDto());
        TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        request.setWorkflow(workflow);
        return request;
    }

    /**
     * Builds a request using a MANAGED/STATIC_KEY scheme and CONTENT_SIGNING workflow,
     * optionally setting a Signature Formatter Connector UUID on the workflow.
     */
    private SigningProfileRequestDto buildManagedStaticKeyContentRequest(String name, UUID formatterConnectorUuid) {
        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription("Test description for " + name);
        StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
        scheme.setCertificateUuid(certificate.getUuid());
        request.setSigningScheme(scheme);
        ContentSigningWorkflowRequestDto workflow = new ContentSigningWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatterConnectorUuid);
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
}
