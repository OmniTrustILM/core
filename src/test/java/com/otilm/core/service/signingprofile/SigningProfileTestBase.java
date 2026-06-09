package com.otilm.core.service.signingprofile;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.SigningProfileRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.DelegatedSigningRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.OneTimeKeyManagedSigningRequestDto;
import com.otilm.api.model.client.signing.profile.scheme.StaticKeyManagedSigningRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.RawSigningWorkflowRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.TimestampingWorkflowRequestDto;
import com.otilm.api.model.client.signing.timequality.TimeQualityConfigurationRequestDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.core.attribute.RsaSignatureAttributes;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.AttributeRelation;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.AttributeRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.dao.repository.signing.TspProfileRepository;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateService;
import com.otilm.core.service.SigningProfileService;
import com.otilm.core.service.TimeQualityConfigurationService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

abstract class SigningProfileTestBase extends BaseSpringBootTest {

    protected static final String CUSTOM_ATTR_UUID = "a1b2c3d4-0001-0002-0003-000000000003";
    protected static final String CUSTOM_ATTR_NAME = "signingProfileTestAttribute";

    @Autowired
    protected SigningProfileService signingProfileService;

    @Autowired
    protected AttributeEngine attributeEngine;

    @Autowired
    protected TimeQualityConfigurationService timeQualityConfigurationService;

    @Autowired
    protected ConnectorRepository connectorRepository;

    @Autowired
    protected TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    protected TokenProfileRepository tokenProfileRepository;

    @Autowired
    protected CryptographicKeyRepository cryptographicKeyRepository;

    @Autowired
    protected CryptographicKeyItemRepository cryptographicKeyItemRepository;

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected CertificateService certificateService;

    @Autowired
    protected SigningProfileRepository signingProfileRepository;

    @Autowired
    protected SigningProfileVersionRepository signingProfileVersionRepository;

    @Autowired
    protected TspProfileRepository tspRepository;

    @Autowired
    protected AttributeDefinitionRepository attributeDefinitionRepository;

    @Autowired
    protected AttributeRelationRepository attributeRelationRepository;

    @Autowired
    protected ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    protected RaProfileRepository raProfileRepository;

    /**
     * Pre-existing signing profile created via service in setUp; used as shared test fixture.
     */
    protected SigningProfile savedProfile;

    /**
     * A minimal RaProfile used as FK reference in ONE_TIME_KEY managed signing scheme requests.
     */
    protected RaProfile raProfile;

    /**
     * A token profile used as an FK reference in static-key managed signing scheme requests.
     */
    protected TokenProfile tokenProfile;

    /**
     * A CryptographicKey backed by an MLDSA key item (empty signing operation attribute definitions).
     * Used for generic static-key scheme tests that do not exercise signing operation attributes.
     */
    protected CryptographicKey cryptographicKey;

    /**
     * A CryptographicKey backed by an RSA key item (RSA signing operation attribute definitions).
     * Used for tests that specifically exercise signing operation attribute storage and retrieval.
     */
    protected CryptographicKey rsaCryptographicKey;

    /**
     * A Certificate associated with {@link #cryptographicKey} (MLDSA key).
     * Satisfies all conditions of constructQueryDigitalSigningCertAcceptable.
     */
    protected Certificate certificate;

    /**
     * A Certificate associated with {@link #rsaCryptographicKey} (RSA key).
     */
    protected Certificate rsaCertificate;

    /**
     * A Certificate specifically configured for TIMESTAMPING workflow type.
     * Contains the id-kp-timeStamping EKU and is marked as critical.
     */
    protected Certificate tsaCertificate;

    /**
     * A Connector used as the signature formatter connector in CONTENT_SIGNING and TIMESTAMPING workflow tests.
     */
    protected Connector formatterConnector;

    /**
     * A Connector used as the delegated signer connector in DELEGATED scheme tests.
     */
    protected Connector delegatedConnector;

    /**
     * WireMock server that backs every formatter connector URL created via {@link #createFormatterConnector}.
     */
    protected WireMockServer mockServer;

    @BeforeEach
    void setUp() throws CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException,
            AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());
        mockServer.stubFor(
                WireMock.get(WireMock.urlPathMatching(".*/v1/signatureProvider/formatting/attributes"))
                        .willReturn(WireMock.okJson("[]"))
        );

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

        SigningProfileDto created = signingProfileService.createSigningProfile(buildDelegatedRawRequest("existing-signing-profile"));
        savedProfile = signingProfileService.getSigningProfileEntity(SecuredUUID.fromString(created.getUuid()));
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    /**
     * Builds a {@link DelegatedSigningRequestDto} pointing at {@link #delegatedConnector}.
     */
    protected DelegatedSigningRequestDto buildDelegatedScheme() {
        DelegatedSigningRequestDto scheme = new DelegatedSigningRequestDto();
        scheme.setConnectorUuid(delegatedConnector.getUuid());
        return scheme;
    }

    /**
     * Builds a minimal valid SigningProfileRequestDto using a DELEGATED scheme and RAW_SIGNING workflow.
     */
    protected SigningProfileRequestDto buildDelegatedRawRequest(String name) {
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
    protected SigningProfileRequestDto buildManagedStaticKeyRawRequest(String name) {
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
     */
    protected SigningProfileRequestDto buildManagedOneTimeKeyRawRequest(String name) {
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
    protected SigningProfileRequestDto buildDelegatedContentRequest(String name) {
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
    protected SigningProfileRequestDto buildDelegatedTimestampingRequest(String name) {
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
     * Builds a request using a MANAGED/STATIC_KEY scheme and CONTENT_SIGNING workflow,
     * optionally setting a Signature Formatter Connector UUID on the workflow.
     */
    protected SigningProfileRequestDto buildManagedStaticKeyContentRequest(String name, UUID formatterConnectorUuid) {
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
    protected SigningProfileRequestDto buildManagedStaticKeyTimestampingRequest(String name) {
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
    protected SigningProfileRequestDto buildManagedStaticKeyTimestampingRequestWithValidationProps(String name) {
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

    /**
     * Builds a valid RSA {@code signingOperationAttributes} request attribute for use in tests.
     */
    protected RequestAttributeV2 buildRsaSchemeAttribute(RsaSignatureScheme scheme) {
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
    protected RequestAttributeV2 buildDigestAttribute(DigestAlgorithm algorithm) {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID));
        attr.setName(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST);
        attr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 content = new StringAttributeContentV2(algorithm.getLabel(), algorithm.getCode());
        attr.setContent(List.of(content));
        return attr;
    }

    /**
     * Creates and persists a minimal {@link Connector} entity for use as a signature formatter connector,
     * also pre-registering a simple data attribute definition so that AttributeEngine can accept content.
     */
    protected Connector createFormatterConnector(String name) {
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
     * The UUID and name must be pre-registered via
     * {@link AttributeEngine#updateDataAttributeDefinitions} before being stored.
     */
    protected RequestAttributeV2 buildFormatterAttribute(UUID attrUuid, String attrName, String value) {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(attrUuid);
        attr.setName(attrName);
        attr.setContentType(AttributeContentType.STRING);
        StringAttributeContentV2 content = new StringAttributeContentV2();
        content.setData(value);
        attr.setContent(List.of(content));
        return attr;
    }

    protected void attachSelfSignedContent(Certificate cert)
            throws CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException {
        X509Certificate x509 = CertificateTestUtil.createCACertificate();
        Certificate entityWithContent = certificateService.createCertificateEntity(x509);
        cert.setCertificateContent(entityWithContent.getCertificateContent());
        cert.setCertificateContentId(entityWithContent.getCertificateContentId());
        certificateRepository.saveAndFlush(cert);
    }

    protected TimeQualityConfigurationRequestDto buildTimeQualityConfigurationRequestDto(String name) {
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
     * but whose certificate content is signed by an external CA absent from the inventory (incomplete chain).
     */
    protected Certificate buildIncompleteChainCertificate()
            throws CertificateException, NoSuchAlgorithmException, OperatorCreationException {
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
