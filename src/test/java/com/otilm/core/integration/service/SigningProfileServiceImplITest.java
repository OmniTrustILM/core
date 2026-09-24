package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.SigningProfileListDto;
import com.otilm.api.model.client.signing.profile.SigningProfileRequestDto;
import com.otilm.api.model.client.signing.profile.SimplifiedSigningProfileDto;
import com.otilm.api.model.client.signing.profile.scheme.DelegatedSigningDto;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.scheme.StaticKeyManagedSigningDto;
import com.otilm.api.model.client.signing.profile.workflow.ContentSigningWorkflowDto;
import com.otilm.api.model.client.signing.profile.workflow.RawSigningWorkflowDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.client.signing.profile.workflow.TimestampingWorkflowDto;
import com.otilm.api.model.client.signing.profile.workflow.timestamp.InternalTimestampSourceDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspActivationDetailDto;
import com.otilm.api.model.client.signing.protocols.tsp.TspProfileDto;
import com.otilm.api.model.client.signing.timequality.TimeQualityConfigurationDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingOperation;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateKeyUsage;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.attribute.RsaSignatureAttributes;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.entity.AttributeRelation;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.AttributeRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.TestCertificateAuthority;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.SigningProfileExternalService;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.service.TimeQualityConfigurationExternalService;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.TspProfileExternalService;
import com.otilm.core.service.v2.ConnectorExternalService;
import com.otilm.core.service.writer.signingrecord.SigningRecordWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.MetaDefinitions;
import com.otilm.core.util.builders.ContentSigningWorkflowRequestDtoBuilder;
import com.otilm.core.util.builders.DataAttributeV3Builder;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.ContentSigningFormattingMock;
import com.otilm.core.util.mocks.CryptographyProviderConnectorMock;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import com.otilm.core.util.mocks.SignerConnectorMock;
import com.otilm.core.util.mocks.TimestampingFormattingConnectorMock;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

import static com.otilm.core.util.CertificateTestData.DOCUMENT_SIGNING_OID;
import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV1ConnectorRequest;
import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV2ConnectorRequest;
import static com.otilm.core.util.builders.ContentSigningWorkflowRequestDtoBuilder.aContentSigningWorkflow;
import static com.otilm.core.util.builders.KeyPairRequestDtoBuilder.aKeyPairRequest;
import static com.otilm.core.util.builders.RequestAttributeV3Builder.aCustomAttribute;
import static com.otilm.core.util.builders.RsaSignatureAttributesBuilder.rsaSignatureAttributes;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyEqualsFilter;
import static com.otilm.core.util.builders.SearchRequestDtoBuilder.aSearchRequest;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequest;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequestFromExistingProfile;
import static com.otilm.core.util.builders.SigningRecordEntityBuilder.aSigningRecord;
import static com.otilm.core.util.builders.TimeQualityConfigurationRequestDtoBuilder.aTimeQualityConfigurationRequest;
import static com.otilm.core.util.builders.TimestampingWorkflowRequestDtoBuilder.aTimestampingWorkflow;
import static com.otilm.core.util.builders.TokenInstanceRequestDtoBuilder.aTokenInstanceRequest;
import static com.otilm.core.util.builders.TokenProfileRequestDtoBuilder.aTokenProfileRequest;
import static com.otilm.core.util.builders.TspProfileRequestDtoBuilder.aTspProfileRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningProfileServiceImplITest extends BaseSpringBootTest {

    private static final String CUSTOM_ATTR_UUID = "c1d2e3f4-0001-0002-0003-000000000004";
    private static final String CUSTOM_ATTR_NAME = "signingProfileTestAttribute";
    private static final String BASE_URL = "http://localhost";

    @Autowired
    private SigningProfileExternalService signingProfileService;

    @Autowired
    private SigningProfileInternalService signingProfileInternalService;

    @Autowired
    private TspProfileExternalService tspProfileService;

    @Autowired
    private ConnectorExternalService connectorService;

    @Autowired
    private TokenInstanceExternalService tokenInstanceService;

    @Autowired
    private TokenProfileExternalService tokenProfileService;

    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;

    @Autowired
    private TimeQualityConfigurationExternalService timeQualityConfigurationService;

    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    @Autowired
    private TestCertificateAuthority testCertificateAuthority;

    private ContentSigningFormattingMock contentSigningFormattingMock;
    private TimestampingFormattingConnectorMock timestampingFormattingMock;
    private CryptographyProviderConnectorMock cryptographyProviderServerMock;
    private SignerConnectorMock signerConnectorServerMock;
    private ConnectorDetailDto contentSigningFormattingConnector;
    private ConnectorDetailDto timestampingFormattingConnector;
    private ConnectorDetailDto cryptographyProviderConnector;
    private ConnectorDetailDto signerConnector;
    private TokenInstanceDetailDto tokenInstance;
    private TokenProfileDetailDto defaultTokenProfile;
    private KeyPair keyPair;
    private KeyDetailDto key;
    private Certificate defaultSigningCertificate;
    private Certificate defaultTimestampingCertificate;
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

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;

    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    @Autowired
    private AttributeContent2ObjectRepository attributeContent2ObjectRepository;

    /**
     * The row is re-read because the field's instance predates {@code certificateUploader.validate} and would write a
     * stale NOT_CHECKED validation status back.
     */
    private void widenDefaultSigningCertificate(CertificateKeyUsage keyUsage, String extendedKeyUsageOid) {
        Certificate stored = certificateRepository
                .findByUuid(SecuredUUID.fromUUID(defaultSigningCertificate.getUuid()))
                .orElseThrow();
        stored.setUsage(List.of(keyUsage));
        stored.setExtendedKeyUsage(MetaDefinitions.serializeArrayString(List.of(extendedKeyUsageOid)));
        certificateRepository.save(stored);
    }

    private ConnectorDetailDto registerTimestampedRungConnector(ContentSigningFormattingMock mock, String name)
            throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        mock.advertiseTimestampedRung().stubPerOperationFormattingAttributes();
        return connectorService.createConnector(aV2ConnectorRequest().withName(name).withUrl(mock.getUrl()).build());
    }

    private SigningProfileDto createProfileNamingTimestampSource(String name, ConnectorDetailDto connector,
            UUID timestampSourceProfileUuid)
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        return signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName(name)
                        .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                        .withContentSigning(aContentSigningWorkflow()
                                .withSignatureFormattingConnector(UUID.fromString(connector.getUuid()))
                                .withFamily(SignatureFamily.PADES)
                                .withMaxLevel(SignatureLevel.TIMESTAMPED)
                                .withInternalTimestampSource(timestampSourceProfileUuid)
                                .build())
                        .build());
    }

    private static String firstErrorMessage(ValidationException ex) {
        return ex.getErrors().stream().map(ValidationError::getErrorDescription).findFirst().orElse("");
    }

    private static String extractStringAttrValue(List<ResponseAttribute> attrs, String name) {
        ResponseAttribute attr = attrs
                .stream()
                .filter(a -> name.equals(a.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Attribute '" + name + "' not found in: " + attrs));
        List<? extends AttributeContent> content = attr.getContent();
        return content.getFirst().getData().toString();
    }

    private static RequestAttribute aStringAttribute(UUID uuid, String name, String value) {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(uuid);
        attr.setName(name);
        attr.setContentType(AttributeContentType.STRING);
        attr.setContent(List.of(new StringAttributeContentV2(value, value)));
        return attr;
    }

    private Connector persistV2Connector(String url) {
        Connector value = new Connector();
        value.setName("pkcs11-like-provider-v2");
        value.setUrl(url);
        value.setVersion(ConnectorVersion.V2);
        value.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.save(value);
    }

    private ConnectorInterfaceEntity persistCryptographyInterface(Connector owner) {
        ConnectorInterfaceEntity value = new ConnectorInterfaceEntity();
        value.setConnector(owner);
        value.setConnectorUuid(owner.getUuid());
        value.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        value.setVersion("v2");
        value.setFeatures(List.of(FeatureFlag.STATELESS));
        value = connectorInterfaceRepository.save(value);
        owner.getInterfaces().add(value);
        return value;
    }

    private TokenInstanceReference persistV2Token(ConnectorInterfaceEntity iface) {
        TokenInstanceReference value = new TokenInstanceReference();
        value.setName("v2-token");
        value.setConnector(iface.getConnector());
        value.setConnectorUuid(iface.getConnectorUuid());
        value.setConnectorInterface(iface);
        value.setKind("HSM");
        value.setStatus(TokenInstanceStatus.ACTIVATED);
        return tokenInstanceReferenceRepository.save(value);
    }

    private TokenProfile persistV2Profile(TokenInstanceReference token) {
        TokenProfile value = new TokenProfile();
        value.setName("v2-token-profile");
        value.setTokenInstanceReference(token);
        value.setTokenInstanceName(token.getName());
        value.setEnabled(true);
        value.setUsage(List.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        return tokenProfileRepository.save(value);
    }

    private CryptographicKey persistV2KeyPair(TokenInstanceReference token, TokenProfile profile, KeyPair keyPair)
            throws NoSuchAlgorithmException {
        CryptographicKey v2Key = new CryptographicKey();
        v2Key.setName("v2-key");
        v2Key.setTokenProfile(profile);
        v2Key.setTokenInstanceReference(token);
        v2Key = cryptographicKeyRepository.save(v2Key);
        String publicKeyData = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        persistV2KeyItem(v2Key, KeyType.PRIVATE_KEY, null, null);
        persistV2KeyItem(v2Key, KeyType.PUBLIC_KEY, publicKeyData,
                CertificateUtil.getThumbprint(publicKeyData.getBytes(StandardCharsets.UTF_8)));
        return v2Key;
    }

    private void persistV2KeyItem(CryptographicKey key, KeyType type, String keyData, String fingerprint) {
        MetadataAttributeV3 handle = new MetadataAttributeV3();
        handle.setUuid(UUID.randomUUID().toString());
        handle.setName("provider-handle");
        handle.setType(AttributeType.META);
        handle.setContentType(AttributeContentType.STRING);
        handle.setProperties(new MetadataAttributeProperties());
        handle.setContent(List.of(new StringAttributeContentV3("hsm-" + type)));
        CryptographicKeyItem value = new CryptographicKeyItem();
        value.setKey(key);
        value.setKeyUuid(key.getUuid());
        value.setType(type);
        value.setKeyAlgorithm(KeyAlgorithm.RSA);
        value.setFormat(type == KeyType.PUBLIC_KEY ? KeyFormat.SPKI : KeyFormat.PRKI);
        value.setLength(2048);
        value.setState(KeyState.ACTIVE);
        value.setEnabled(true);
        value.setUsage(List.of(type == KeyType.PUBLIC_KEY ? KeyUsage.VERIFY : KeyUsage.SIGN));
        value.setKeyMeta(List.of(handle));
        value.setKeyData(keyData);
        value.setFingerprint(fingerprint);
        cryptographicKeyItemRepository.save(value);
    }

    @BeforeEach
    void setUp() throws Exception {

        // Set up mocks of connectors (the servers to call); the cryptography-provider mock also seeds
        // the function-group reference data normally provided by Flyway (wiped by per-test truncation)
        cryptographyProviderServerMock = connectorMockFactory.startCryptographyProvider();
        contentSigningFormattingMock = connectorMockFactory.startContentSigningFormatting();
        timestampingFormattingMock = connectorMockFactory.startTimestampingFormatting();
        signerConnectorServerMock = connectorMockFactory.startSigner();

        // Register the connectors to ILM
        cryptographyProviderConnector = connectorService
                .createConnector(aV1ConnectorRequest()
                        .withName("soft-cryptography-provider")
                        .withUrl(this.cryptographyProviderServerMock.getUrl())
                        .build());
        contentSigningFormattingConnector = connectorService
                .createConnector(aV2ConnectorRequest()
                        .withName("content-signing-formatting")
                        .withUrl(this.contentSigningFormattingMock.getUrl())
                        .build());
        timestampingFormattingConnector = connectorService
                .createConnector(aV2ConnectorRequest()
                        .withName("timestamping-formatting")
                        .withUrl(this.timestampingFormattingMock.getUrl())
                        .build());
        signerConnector = connectorService
                .createConnector(aV2ConnectorRequest()
                        .withName("delegated-signer")
                        .withUrl(this.signerConnectorServerMock.getUrl())
                        .build());

        // Create a token instance backed by the cryptography provider
        cryptographyProviderServerMock.stubTokenInstanceCreation(UUID.randomUUID());
        tokenInstance = tokenInstanceService
                .createTokenInstance(aTokenInstanceRequest()
                        .withName("soft-token")
                        .withConnector(cryptographyProviderConnector.getUuid())
                        .build());

        // Create a token profile on the token instance
        cryptographyProviderServerMock.stubTokenProfileCreation();
        defaultTokenProfile = tokenProfileService
                .createTokenProfile(SecuredParentUUID.fromString(tokenInstance.getUuid()),
                        aTokenProfileRequest().withName("soft-token-profile").build());

        // Create a key pair on the token profile, reporting a real public key the certificate will reuse
        keyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        String base64Spki = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        cryptographyProviderServerMock.stubKeyPairCreation(base64Spki);
        key = cryptographicKeyService
                .createKey(UUID.fromString(tokenInstance.getUuid()),
                        SecuredParentUUID.fromString(defaultTokenProfile.getUuid()), KeyRequestType.KEY_PAIR,
                        aKeyPairRequest().withName("soft-key-pair").build());

        // Establish a trusted root CA, then leaves signed by it and built from the token key pair.
        // Uploading a leaf associates it (by public-key fingerprint) with the token-backed key.
        TestCertificateAuthority.TrustedCa trustedCa = testCertificateAuthority.createTrustedCa("CN=Test Root CA");
        defaultSigningCertificate = trustedCa.issueSigningCertificate(keyPair, "CN=Test Signing");
        defaultTimestampingCertificate = trustedCa.issueTimestampingCertificate(keyPair, "CN=Test TSA");

        // Create signing profiles
        defaultDelegatedSigningProfile = signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName("default-delegated-signing-profile")
                        .withDelegatedSigning(signerConnector.getUuid())
                        .withRawSigning()
                        .build());

        defaultManagedStaticKeySigningProfile = signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName("default-managed-static-key-signing-profile")
                        .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                        .withRawSigning()
                        .build());

        contentSigningFormattingMock.stubPerOperationFormattingAttributes();
        defaultContentSigningProfile = signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName("default-content-signing-profile")
                        .withDelegatedSigning(signerConnector.getUuid())
                        .withDelegatedContentSigning()
                        .build());

        timestampingFormattingMock.stubFormattingAttributes();
        defaultTimestampingProfile = signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName("default-timestamping-profile")
                        .withStaticKeyManagedSigning(defaultTimestampingCertificate.getUuid())
                        .withTimestamping(aTimestampingWorkflow()
                                .withSignatureFormattingConnector(
                                        UUID.fromString(timestampingFormattingConnector.getUuid()))
                                .build())
                        .build());

        defaultRawSigningProfile = signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName("default-raw-signing-profile")
                        .withDelegatedSigning(signerConnector.getUuid())
                        .withRawSigning()
                        .build());

        // Create default TSP protocol
        defaultTspProtocol = tspProfileService
                .createTspProfile(aTspProfileRequest().withName("default-tsp-protocol").build(), BASE_URL);
    }

    @AfterEach
    void tearDown() {
        if (contentSigningFormattingMock != null) {
            contentSigningFormattingMock.stop();
        }
        if (timestampingFormattingMock != null) {
            timestampingFormattingMock.stop();
        }
        if (cryptographyProviderServerMock != null) {
            cryptographyProviderServerMock.stop();
        }
        if (signerConnectorServerMock != null) {
            signerConnectorServerMock.stop();
        }
    }

    private void createSigningRecordFor(SigningProfileDto profile) {
        signingRecordWriter.insert(aSigningRecord().withSigningProfile(profile).build());
    }

    @Test
    void deniedCert_throwsAccessDeniedException() {
        // given: OPA mock configured to deny certificate DETAIL access
        denyResourceAccess(Resource.CERTIFICATE, ResourceAction.DETAIL);

        UUID rsaCertificateUuid = defaultSigningCertificate.getUuid();

        // when
        Executable listAttributes = () -> signingProfileService
                .listSignatureAttributesForCertificate(SecuredUUID.fromUUID(rsaCertificateUuid));

        // then
        assertThrows(AccessDeniedException.class, listAttributes);
    }

    @Nested
    class ListTests {

        @Test
        void emptyWhenNoneExistAndNoFilteringApplied() {
            // given: no profiles (delete all from setUp)
            signingProfileService
                    .bulkDeleteSigningProfiles(SecuredUUID
                            .asList(defaultDelegatedSigningProfile.getUuid(),
                                    defaultManagedStaticKeySigningProfile.getUuid(),
                                    defaultContentSigningProfile.getUuid(), defaultTimestampingProfile.getUuid(),
                                    defaultRawSigningProfile.getUuid()));
            var searchRequest = aSearchRequest().build();
            SecurityFilter filter = new SecurityFilter();

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService
                    .listSigningProfiles(searchRequest, filter);

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
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService
                    .listSigningProfiles(searchRequest, filter);

            // then
            assertNotNull(response);
            assertEquals(5, response.getTotalItems());
        }

        @Test
        void filtersByName() {
            // given: filter matching only "default-delegated-signing-profile" by exact name
            var searchRequest = aSearchRequest()
                    .withFilters(aPropertyEqualsFilter(FilterField.SIGNING_PROFILE_NAME,
                            "default-delegated-signing-profile"))
                    .build();
            SecurityFilter filter = new SecurityFilter();

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService
                    .listSigningProfiles(searchRequest, filter);

            // then
            assertEquals(1, response.getTotalItems());
            assertEquals("default-delegated-signing-profile", response.getItems().getFirst().getName());
        }

        @Test
        void filtersBySigningScheme() {
            // given: filter matching only a delegated signing scheme (default-delegated-signing-profile +
            // default-content-signing-profile + default-raw-signing-profile)
            var searchRequest = aSearchRequest()
                    .withFilters(aPropertyEqualsFilter(FilterField.SIGNING_PROFILE_SIGNING_SCHEME,
                            SigningScheme.DELEGATED.getCode()))
                    .build();
            SecurityFilter filter = new SecurityFilter();

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService
                    .listSigningProfiles(searchRequest, filter);

            // then
            assertEquals(3, response.getTotalItems());
        }

        @Test
        void filtersByWorkflowType() {
            // given: filter matching only TIMESTAMPING workflow
            var searchRequest = aSearchRequest()
                    .withFilters(aPropertyEqualsFilter(FilterField.SIGNING_PROFILE_WORKFLOW_TYPE,
                            SigningWorkflowType.TIMESTAMPING.getCode()))
                    .build();
            SecurityFilter filter = new SecurityFilter();

            // when
            PaginationResponseDto<SigningProfileListDto> response = signingProfileService
                    .listSigningProfiles(searchRequest, filter);

            // then
            assertEquals(1, response.getTotalItems());
            assertEquals("default-timestamping-profile", response.getItems().getFirst().getName());
        }
    }

    @Nested
    class ListSignatureAttributesTests {

        @Test
        void allowedCert_returnsAttributes() throws Exception {
            // given: signingCertificate from setUp (access allowed by default)

            // when
            List<BaseAttribute> attrs = signingProfileService
                    .listSignatureAttributesForCertificate(SecuredUUID.fromUUID(defaultSigningCertificate.getUuid()));

            // then
            assertNotNull(attrs);
            assertFalse(attrs.isEmpty(), "RSA certificate should produce non-empty signature attributes");
        }

        @Test
        void certWithoutAPrivateKey_returnsNoAttributes() throws Exception {
            // given: an uploaded certificate, whose key holds only the public half
            Certificate publicOnly = testCertificateAuthority.issueUntrustedCertificate();

            // when
            List<BaseAttribute> attrs = signingProfileService
                    .listSignatureAttributesForCertificate(SecuredUUID.fromUUID(publicOnly.getUuid()));

            // then
            assertTrue(attrs.isEmpty());
        }

        @Test
        void deniedCert_throwsAccessDeniedException() {
            // given: OPA mock configured to deny certificate DETAIL access
            denyResourceAccess(Resource.CERTIFICATE, ResourceAction.DETAIL);
            UUID rsaCertificateUuid = defaultSigningCertificate.getUuid();

            // when
            Executable listAttributes = () -> signingProfileService
                    .listSignatureAttributesForCertificate(SecuredUUID.fromUUID(rsaCertificateUuid));

            // then
            assertThrows(AccessDeniedException.class, listAttributes);
        }
    }

    @Nested
    class V2KeySigningAttributes {

        private static final UUID SCHEME_UUID = UUID.fromString("0b6f2a5e-2317-4c1e-9d11-000000000001");
        private static final UUID DIGEST_UUID = UUID.fromString("0b6f2a5e-2317-4c1e-9d11-000000000002");
        private static final UUID SALT_LENGTH_UUID = UUID.fromString("0b6f2a5e-2317-4c1e-9d11-000000000003");
        private static final String PKCS11_SCHEMA = "[" + stringAttribute(SCHEME_UUID, "signatureScheme") + ","
                + stringAttribute(DIGEST_UUID, "digestAlgorithm") + "]";

        private CryptographyProviderV2ConnectorMock v2Mock;
        private Connector v2Connector;
        private CryptographicKey v2Key;
        private Certificate v2SigningCertificate;
        private Certificate v2TimestampingCertificate;

        @BeforeEach
        void setUpV2Key() throws Exception {
            v2Mock = connectorMockFactory.startCryptographyProviderV2();
            v2Mock.stubOperationAttributes("sign", PKCS11_SCHEMA);
            v2Connector = persistV2Connector(v2Mock.getUrl());
            TokenInstanceReference token = persistV2Token(persistCryptographyInterface(v2Connector));
            TokenProfile profile = persistV2Profile(token);
            KeyPair v2KeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
            v2Key = persistV2KeyPair(token, profile, v2KeyPair);
            TestCertificateAuthority.TrustedCa ca = testCertificateAuthority.createTrustedCa("CN=V2 Root CA");
            v2SigningCertificate = ca.issueSigningCertificate(v2KeyPair, "CN=V2 Signing");
            v2TimestampingCertificate = ca.issueTimestampingCertificate(v2KeyPair, "CN=V2 TSA");
        }

        @AfterEach
        void stopV2Mock() {
            v2Mock.stop();
        }

        @Test
        void listSignatureAttributesForCertificate_servesTheConnectorsVocabulary() throws Exception {
            // when
            List<BaseAttribute> attributes = signingProfileService
                    .listSignatureAttributesForCertificate(SecuredUUID.fromUUID(v2SigningCertificate.getUuid()));

            // then
            assertEquals(List.of("signatureScheme", "digestAlgorithm"),
                    attributes.stream().map(BaseAttribute::getName).toList());
        }

        @Test
        void listSignatureAttributesForCertificate_keyWithTwoPrivateItems_servesTheConnectorsVocabulary()
                throws Exception {
            // given
            persistV2KeyItem(v2Key, KeyType.PRIVATE_KEY, null, null);

            // when
            List<BaseAttribute> attributes = signingProfileService
                    .listSignatureAttributesForCertificate(SecuredUUID.fromUUID(v2SigningCertificate.getUuid()));

            // then
            assertEquals(List.of("signatureScheme", "digestAlgorithm"),
                    attributes.stream().map(BaseAttribute::getName).toList());
        }

        @Test
        void create_v1Key_storesTheSigningAttributesWithoutAnOwner() {
            // when
            List<?> ownerless = attributeContent2ObjectRepository
                    .getObjectDataAttributesContentNoConnector(AttributeType.DATA, AttributeOperation.SIGN, null,
                            Resource.SIGNING_PROFILE, UUID.fromString(defaultManagedStaticKeySigningProfile.getUuid()),
                            defaultManagedStaticKeySigningProfile.getVersion());

            // then
            assertEquals(2, ownerless.size());
        }

        @Test
        void create_v2Key_persistsTheConnectorsAttributes_andReadsThemBack() throws Exception {
            // when
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("v2-static-key")
                            .withStaticKeyManagedSigning(v2SigningCertificate.getUuid(), pkcs11Attributes("PSS"))
                            .withRawSigning()
                            .build());

            // then
            List<ResponseAttribute> stored = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    created.getSigningScheme()).getSigningOperationAttributes();
            assertEquals("PSS", extractStringAttrValue(stored, "signatureScheme"));
            assertEquals("SHA-256", extractStringAttrValue(stored, "digestAlgorithm"));
            assertEquals(created,
                    signingProfileService.getSigningProfile(SecuredUUID.fromString(created.getUuid()), null));
        }

        @Test
        void loadSigningProfileModel_v2Key_carriesTheConnectorsAttributes() throws Exception {
            // given
            timestampingFormattingMock.stubFormattingAttributes();
            signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("v2-timestamping")
                            .withStaticKeyManagedSigning(v2TimestampingCertificate.getUuid(),
                                    pkcs11Attributes("PKCS1-v1_5"))
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(timestampingFormattingConnector.getUuid()))
                                    .build())
                            .build());

            // when
            SigningProfileModel<?, ?> model = signingProfileInternalService.loadSigningProfileModel("v2-timestamping");

            // then: read back in the definition's schema version, which pkcs11 requires
            StaticKeyManagedSigning scheme = assertInstanceOf(StaticKeyManagedSigning.class, model.signingScheme());
            assertEquals(Set.of("signatureScheme", "digestAlgorithm"),
                    scheme
                            .signingOperationAttributes()
                            .stream()
                            .map(RequestAttribute::getName)
                            .collect(Collectors.toSet()));
            scheme
                    .signingOperationAttributes()
                    .forEach(attribute -> assertInstanceOf(RequestAttributeV3.class, attribute));
        }

        @Test
        void create_v2Key_persistsAnAttributeAGroupCallbackDelivered() throws Exception {
            // given: a group callback delivered this child, so Core stored its definition without an operation
            DataAttributeV3 saltLength = DataAttributeV3Builder
                    .aDataAttribute()
                    .withUuid(SALT_LENGTH_UUID)
                    .withName("pssSaltLength")
                    .build();
            attributeEngine.updateDataAttributeDefinitions(v2Connector.getUuid(), null, List.of(saltLength));
            List<RequestAttribute> attributes = new ArrayList<>(pkcs11Attributes("PSS"));
            attributes.add(aStringAttributeV3(SALT_LENGTH_UUID, "pssSaltLength", "32"));

            // when
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("v2-callback-child")
                            .withStaticKeyManagedSigning(v2SigningCertificate.getUuid(), attributes)
                            .withRawSigning()
                            .build());

            // then
            List<ResponseAttribute> stored = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    created.getSigningScheme()).getSigningOperationAttributes();
            assertEquals("32", extractStringAttrValue(stored, "pssSaltLength"));
        }

        @Test
        void create_v2Key_rejectsAnAttributeTheConnectorDoesNotOffer() {
            // given: Core's legacy RSA names, which this connector does not publish
            SigningProfileRequestDto request = aSigningProfileRequest()
                    .withName("v2-legacy-names")
                    .withStaticKeyManagedSigning(v2SigningCertificate.getUuid(), RsaSignatureScheme.PKCS1_v1_5,
                            DigestAlgorithm.SHA_256)
                    .withRawSigning()
                    .build();

            // when
            Executable create = () -> signingProfileService.createSigningProfile(request);

            // then
            ValidationException failure = assertThrows(ValidationException.class, create);
            assertTrue(firstErrorMessage(failure).contains(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME));
        }

        @Test
        void update_swappingAV1KeyForAV2Key_replacesTheSigningAttributes() throws Exception {
            // given: a v1-backed profile holding Core's RSA attributes
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("v1-then-v2")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withRawSigning()
                            .build());

            // when: updated in place onto the v2-backed certificate
            SigningProfileDto updated = signingProfileService
                    .updateSigningProfile(SecuredUUID.fromString(created.getUuid()),
                            aSigningProfileRequestFromExistingProfile(created)
                                    .withStaticKeyManagedSigning(v2SigningCertificate.getUuid(),
                                            pkcs11Attributes("PSS"))
                                    .build());

            // then
            List<ResponseAttribute> stored = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    updated.getSigningScheme()).getSigningOperationAttributes();
            assertEquals(Set.of("signatureScheme", "digestAlgorithm"),
                    stored.stream().map(ResponseAttribute::getName).collect(Collectors.toSet()));
            assertEquals(updated,
                    signingProfileService.getSigningProfile(SecuredUUID.fromString(created.getUuid()), null));
            assertTrue(attributeContent2ObjectRepository
                    .getObjectDataAttributesContentNoConnector(AttributeType.DATA, AttributeOperation.SIGN, null,
                            Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()), updated.getVersion())
                    .isEmpty());
        }

        @Test
        void update_v2KeyToNonStaticScheme_clearsTheConnectorOwnedAttributes() throws Exception {
            // given
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("v2-then-delegated")
                            .withStaticKeyManagedSigning(v2SigningCertificate.getUuid(), pkcs11Attributes("PSS"))
                            .withRawSigning()
                            .build());

            // when
            signingProfileService
                    .updateSigningProfile(SecuredUUID.fromString(created.getUuid()),
                            aSigningProfileRequestFromExistingProfile(created)
                                    .withDelegatedSigning(signerConnector.getUuid())
                                    .build());

            // then
            assertTrue(attributeContent2ObjectRepository
                    .getObjectDataAttributesContent(AttributeType.DATA, v2Connector.getUuid(), AttributeOperation.SIGN,
                            null, Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()), created.getVersion())
                    .isEmpty());
        }

        private List<RequestAttribute> pkcs11Attributes(String scheme) {
            return List
                    .of(aStringAttributeV3(SCHEME_UUID, "signatureScheme", scheme),
                            aStringAttributeV3(DIGEST_UUID, "digestAlgorithm", "SHA-256"));
        }

        /** pkcs11 publishes schema-v3 definitions, so a client answers them in v3. */
        private static RequestAttribute aStringAttributeV3(UUID uuid, String name, String value) {
            return new RequestAttributeV3(uuid, name, AttributeContentType.STRING,
                    List.of(new StringAttributeContentV3(value)));
        }

        private static String stringAttribute(UUID uuid, String name) {
            return "{\"uuid\":\"" + uuid + "\",\"name\":\"" + name + "\",\"type\":\"data\",\"contentType\":\"string\","
                    + "\"version\":3,\"properties\":{\"label\":\"" + name + "\",\"visible\":true,\"required\":true,"
                    + "\"readOnly\":false,\"list\":false,\"multiSelect\":false}}";
        }
    }

    @Nested
    class GetTests {

        @Test
        void returnsLatestVersionByDefault()
                throws NotFoundException, ConnectorException, AlreadyExistException, AttributeException {
            // given: profile with multiple versions
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
            createSigningRecordFor(defaultDelegatedSigningProfile);
            signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                                    .withName("a-new-name")
                                    .build());

            // when
            SigningProfileDto dto = signingProfileService.getSigningProfile(profileUuid, null);

            // then
            assertNotNull(dto);
            assertEquals(defaultDelegatedSigningProfile.getUuid(), dto.getUuid());
            assertEquals("a-new-name", dto.getName());
            assertEquals(2, dto.getVersion());
        }

        @Test
        void specificVersion_returnsSnapshotData()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: profile with multiple versions
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
            createSigningRecordFor(defaultDelegatedSigningProfile);
            signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                                    .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                                    .build());

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
            SigningProfileDto existingProfile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("workflow-update")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(existingProfile.getUuid());
            createSigningRecordFor(existingProfile);

            // when: the profile is updated to use a different workflow type (timestamping)
            signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(existingProfile)
                                    .withTimestamping(UUID.fromString(timestampingFormattingConnector.getUuid()))
                                    .build());

            // then: version 1 still has the original RAW workflow
            SigningProfileDto previousProfileVersion = signingProfileService.getSigningProfile(profileUuid, 1);
            assertInstanceOf(RawSigningWorkflowDto.class, previousProfileVersion.getWorkflow());

            // and: version 2 has the new TIMESTAMPING workflow
            SigningProfileDto updatedProfile = signingProfileService.getSigningProfile(profileUuid, 2);
            assertInstanceOf(TimestampingWorkflowDto.class, updatedProfile.getWorkflow());
        }

        @Test
        void noProtocolsLinked_enabledProtocolsIsEmpty()
                throws NotFoundException, ConnectorException, AlreadyExistException, AttributeException {
            // when: after creation, no protocols are linked
            SigningProfileDto createdProfile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("no-protocols-linked")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .build());

            // then
            assertNotNull(createdProfile.getEnabledProtocols());
            assertTrue(createdProfile.getEnabledProtocols().isEmpty(),
                    "No protocols should be enabled when none are linked");
        }

        @Test
        void withTspLinked_enabledProtocolsContainsTsp()
                throws NotFoundException, ConnectorException, AlreadyExistException, AttributeException {
            // given
            SigningProfileDto createdProfile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("some protocols-linked")
                            .withStaticKeyManagedSigning(defaultTimestampingCertificate.getUuid())
                            .withTimestamping(UUID.fromString(timestampingFormattingConnector.getUuid()))
                            .build());

            // when: link a TSP protocol to the profile
            signingProfileService
                    .activateTsp(SecuredUUID.fromString(createdProfile.getUuid()),
                            SecuredUUID.fromString(defaultTspProtocol.getUuid()), BASE_URL);

            // then
            SigningProfileDto updatedProfile = signingProfileService
                    .getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);
            assertNotNull(updatedProfile.getEnabledProtocols());
            assertEquals(1, updatedProfile.getEnabledProtocols().size());
            assertTrue(updatedProfile.getEnabledProtocols().contains(SigningProtocol.TSP),
                    "TSP protocol should be enabled when linked to the profile");
        }

        @Test
        void entity_returnsCorrectEntity() throws NotFoundException {
            // given
            SigningProfileDto existingProfile = defaultTimestampingProfile;
            SecuredUUID existingProfileUuid = SecuredUUID.fromString(existingProfile.getUuid());

            // when
            SigningProfile entity = signingProfileInternalService.getSigningProfileEntity(existingProfileUuid);

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
            List<String> names = signingProfileInternalService.findAllNames();

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
        void contentSigningWorkflow_returnsTheTimestampSourceByName() throws Exception {
            // given
            ContentSigningFormattingMock formattingMock = connectorMockFactory.startContentSigningFormatting();
            try {
                ConnectorDetailDto connector = registerTimestampedRungConnector(formattingMock,
                        "content-signing-formatting-named-source");

                // when
                SigningProfileDto created = createProfileNamingTimestampSource("named-timestamp-source-profile",
                        connector, UUID.fromString(defaultTimestampingProfile.getUuid()));

                // then
                assertThat(((ContentSigningWorkflowDto) created.getWorkflow()).getTimestampSource())
                        .isInstanceOfSatisfying(InternalTimestampSourceDto.class,
                                source -> assertThat(source.signingProfile().getName())
                                        .isEqualTo(defaultTimestampingProfile.getName()));
            } finally {
                formattingMock.stop();
            }
        }

        @Test
        void managedContentSigning_withAOneTimeKeyScheme_throwsValidationException() {
            // given: a one-time-key scheme, which no content-signing resolver can resolve
            ThrowableAssert.ThrowingCallable create = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-managed-content-one-time-key")
                            .withOneTimeKeyManagedSigning(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID())
                            .withManagedContentSigning(UUID.fromString(contentSigningFormattingConnector.getUuid()))
                            .build());

            // then
            assertThatThrownBy(create).isInstanceOf(ValidationException.class).hasMessageContaining("STATIC_KEY");
        }

        @Test
        void managedContentSigning_certificatePurposeConstraints_persistAndReadBack()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a certificate that satisfies both constraints the profile is about to set
            widenDefaultSigningCertificate(CertificateKeyUsage.NON_REPUDIATION, DOCUMENT_SIGNING_OID);

            // when
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-managed-content-purpose-constraints")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                    .withFamily(SignatureFamily.PADES)
                                    .withMaxLevel(SignatureLevel.SIGNED)
                                    .withRequireNonRepudiation(true)
                                    .withRequiredExtendedKeyUsageOids(DOCUMENT_SIGNING_OID)
                                    .build())
                            .build());

            // then: the create response echoes both constraints
            ContentSigningWorkflowDto createdWorkflow = assertInstanceOf(ContentSigningWorkflowDto.class,
                    created.getWorkflow());
            assertThat(createdWorkflow.isRequireNonRepudiation()).isTrue();
            assertThat(createdWorkflow.getRequiredExtendedKeyUsageOids()).containsExactly(DOCUMENT_SIGNING_OID);

            // and: reading the persisted version back confirms both columns were written
            SigningProfileDto fetched = signingProfileService
                    .getSigningProfile(SecuredUUID.fromString(created.getUuid()), created.getVersion());
            ContentSigningWorkflowDto fetchedWorkflow = assertInstanceOf(ContentSigningWorkflowDto.class,
                    fetched.getWorkflow());
            assertThat(fetchedWorkflow.isRequireNonRepudiation()).isTrue();
            assertThat(fetchedWorkflow.getRequiredExtendedKeyUsageOids()).containsExactly(DOCUMENT_SIGNING_OID);
        }

        @Test
        void managedContentSigning_requiringNonRepudiation_refusesADigitalSignatureOnlyCertificate() {
            // given: defaultSigningCertificate carries digitalSignature but not nonRepudiation
            ThrowableAssert.ThrowingCallable create = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-managed-content-nr-mismatch")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                    .withFamily(SignatureFamily.PADES)
                                    .withMaxLevel(SignatureLevel.SIGNED)
                                    .withRequireNonRepudiation(true)
                                    .build())
                            .build());

            // then
            assertThatThrownBy(create)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("is not eligible for signing workflow type")
                    .hasMessageContaining("nonRepudiation");
        }

        @Test
        void delegatedScheme_rawWorkflow_setsExpectedAttributes()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-delegated-raw")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .build());
            SigningProfileDto getDto = signingProfileService
                    .getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

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
        void delegatedScheme_contentSigningWorkflow_setsExpectedAttributes()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-delegated-content")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withDelegatedContentSigning()
                            .build());
            SigningProfileDto getDto = signingProfileService
                    .getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-delegated-content", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            DelegatedSigningDto scheme = assertInstanceOf(DelegatedSigningDto.class, createdProfile.getSigningScheme());
            assertEquals(signerConnector.getUuid(), scheme.getConnector().getUuid());

            ContentSigningWorkflowDto workflow = assertInstanceOf(ContentSigningWorkflowDto.class,
                    createdProfile.getWorkflow());
            assertThat(workflow.getSignatureFormattingConnector()).isNull();
        }

        static Stream<Arguments> ladderFields() {
            return Stream
                    .of(Arguments
                            .of("family",
                                    (UnaryOperator<ContentSigningWorkflowRequestDtoBuilder>) b -> b
                                            .withFamily(SignatureFamily.PADES)),
                            Arguments
                                    .of("maxLevel",
                                            (UnaryOperator<ContentSigningWorkflowRequestDtoBuilder>) b -> b
                                                    .withMaxLevel(SignatureLevel.TIMESTAMPED)),
                            Arguments
                                    .of("timestampSource",
                                            (UnaryOperator<ContentSigningWorkflowRequestDtoBuilder>) b -> b
                                                    .withInternalTimestampSource(UUID.randomUUID())));
        }

        @ParameterizedTest(name = "{0}")
        @MethodSource("ladderFields")
        void delegatedScheme_contentSigningWorkflowCarryingOneLadderField_throwsValidationException(String field,
                UnaryOperator<ContentSigningWorkflowRequestDtoBuilder> setField) {
            // when
            ThrowableAssert.ThrowingCallable create = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-delegated-content-ladder-" + field)
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withContentSigning(setField.apply(aContentSigningWorkflow()).build())
                            .build());

            // then
            assertThatThrownBy(create)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(
                            "family, maxLevel and timestampSource must be omitted for delegated content signing");
        }

        @Test
        void delegatedScheme_contentSigningWorkflowCarryingADocumentSizeCap_persistsTheCap()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-delegated-content-with-size-cap")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withContentSigning(aContentSigningWorkflow().withDocumentSizeCap(1024L).build())
                            .build());

            // then: the create response carries the cap
            assertThat(assertInstanceOf(ContentSigningWorkflowDto.class, created.getWorkflow()).getDocumentSizeCap())
                    .isEqualTo(1024L);

            // and: reading the persisted version back confirms the column was written
            SigningProfileDto fetched = signingProfileService
                    .getSigningProfile(SecuredUUID.fromString(created.getUuid()), created.getVersion());
            assertThat(assertInstanceOf(ContentSigningWorkflowDto.class, fetched.getWorkflow()).getDocumentSizeCap())
                    .isEqualTo(1024L);
        }

        @Test
        void managedScheme_contentSigningWorkflowWithAConnectorLackingTheFeature_throwsValidationException()
                throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
            // given: a formatting connector advertising no content-signing feature, and no per-operation route either
            ContentSigningFormattingMock featurelessMock = connectorMockFactory.startContentSigningFormatting();
            try {
                featurelessMock.advertiseNoContentSigningFeature();
                ConnectorDetailDto featureless = connectorService
                        .createConnector(aV2ConnectorRequest()
                                .withName("content-signing-formatting-featureless")
                                .withUrl(featurelessMock.getUrl())
                                .build());

                // when
                ThrowableAssert.ThrowingCallable create = () -> signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("ct-managed-content-featureless-connector")
                                .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                                .withManagedContentSigning(UUID.fromString(featureless.getUuid()))
                                .build());

                // then: the family-specific gate refuses it before the connector is asked for its schemas
                assertThatThrownBy(create)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining(
                                "does not advertise the 'Content Signing' feature on its 'PAdES Formatting' interface");
            } finally {
                featurelessMock.stop();
            }
        }

        @Test
        void delegatedScheme_contentSigningWorkflowCarryingAFormattingConnector_throwsValidationException() {
            // when
            ThrowableAssert.ThrowingCallable create = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-delegated-content-with-formatting-connector")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                    .build())
                            .build());

            // then
            assertThatThrownBy(create)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(
                            "signatureFormattingConnectorUuid must be omitted for delegated content signing");
        }

        @Test
        void delegatedScheme_contentSigningWorkflowCarryingFormattingAttributes_throwsValidationException() {
            // when
            ThrowableAssert.ThrowingCallable create = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-delegated-content-with-formatting-attributes")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormattingConnectorAttributes(List
                                            .of(aStringAttribute(
                                                    UUID.fromString("11111111-2222-3333-4444-555555555557"),
                                                    "data_delegatedFormattingAttr", "value")))
                                    .build())
                            .build());

            // then
            assertThatThrownBy(create)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(
                            "signatureFormattingConnectorAttributes must be omitted for delegated content signing");
        }

        @Test
        void managedScheme_contentSigningWorkflowWithoutAFamily_throwsValidationException() {
            // when
            ThrowableAssert.ThrowingCallable create = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-managed-content-no-family")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                    .withMaxLevel(SignatureLevel.SIGNED)
                                    .build())
                            .build());

            // then
            assertThatThrownBy(create)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Signature family is required");
        }

        @Test
        void managedScheme_contentSigningWorkflowWithoutAMaxLevel_throwsValidationException() {
            // when
            ThrowableAssert.ThrowingCallable create = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-managed-content-no-max-level")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                    .withFamily(SignatureFamily.PADES)
                                    .build())
                            .build());

            // then
            assertThatThrownBy(create)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("maxLevel is required");
        }

        @Test
        void delegatedScheme_timestampingWorkflow_setsExpectedAttributes()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-delegated-timestamping")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(timestampingFormattingConnector.getUuid()))
                                    .withDefaultPolicyId("1.2.3.4.5")
                                    .withAllowedPolicyIds(List.of("1.2.3.4.5", "1.2.3.4.6"))
                                    .withAllowedDigestAlgorithms(
                                            List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_384))
                                    .withQualifiedTimestamp(false)
                                    .withValidateTokenSignature(true)
                                    .build())
                            .build());
            SigningProfileDto getDto = signingProfileService
                    .getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-delegated-timestamping", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            DelegatedSigningDto scheme = assertInstanceOf(DelegatedSigningDto.class, createdProfile.getSigningScheme());
            assertEquals(signerConnector.getUuid(), scheme.getConnector().getUuid());

            TimestampingWorkflowDto workflow = assertInstanceOf(TimestampingWorkflowDto.class,
                    createdProfile.getWorkflow());
            assertEquals(timestampingFormattingConnector.getUuid(),
                    workflow.getSignatureFormattingConnector().getUuid());
            assertEquals("1.2.3.4.5", workflow.getDefaultPolicyId());
            assertEquals(List.of("1.2.3.4.5", "1.2.3.4.6"), workflow.getAllowedPolicyIds());
            assertEquals(List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_384),
                    workflow.getAllowedDigestAlgorithms());
            assertFalse(workflow.getQualifiedTimestamp());
            assertTrue(workflow.getValidateTokenSignature());
        }

        @Test
        void staticKeyManagedScheme_rawWorkflow_setsExpectedAttributes()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-static-raw")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withRawSigning()
                            .build());
            SigningProfileDto getDto = signingProfileService
                    .getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-static-raw", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            StaticKeyManagedSigningDto scheme = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    createdProfile.getSigningScheme());
            assertEquals(defaultSigningCertificate.getUuid(), scheme.getCertificate().getUuid());
            assertFalse(scheme.getSigningOperationAttributes().isEmpty());

            assertInstanceOf(RawSigningWorkflowDto.class, createdProfile.getWorkflow());
        }

        @Test
        void staticKeyManagedScheme_contentSigningWorkflow_setsExpectedAttributes()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-static-content")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withManagedContentSigning(UUID.fromString(contentSigningFormattingConnector.getUuid()))
                            .build());
            SigningProfileDto getDto = signingProfileService
                    .getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-static-content", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            StaticKeyManagedSigningDto scheme = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    createdProfile.getSigningScheme());
            assertEquals(defaultSigningCertificate.getUuid(), scheme.getCertificate().getUuid());
            assertFalse(scheme.getSigningOperationAttributes().isEmpty());

            ContentSigningWorkflowDto workflow = assertInstanceOf(ContentSigningWorkflowDto.class,
                    createdProfile.getWorkflow());
            assertEquals(contentSigningFormattingConnector.getUuid(),
                    workflow.getSignatureFormattingConnector().getUuid());
        }

        @Test
        void staticKeyManagedScheme_timestampingWorkflow_setsExpectedAttributes()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // when
            SigningProfileDto createdProfile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ct-static-timestamping")
                            .withStaticKeyManagedSigning(defaultTimestampingCertificate.getUuid())
                            .withTimestamping(UUID.fromString(timestampingFormattingConnector.getUuid()))
                            .build());
            SigningProfileDto getDto = signingProfileService
                    .getSigningProfile(SecuredUUID.fromString(createdProfile.getUuid()), null);

            // then: create and get agree
            assertEquals(createdProfile, getDto);

            // and: expected values are present
            assertNotNull(createdProfile.getUuid());
            assertEquals("ct-static-timestamping", createdProfile.getName());
            assertEquals(1, createdProfile.getVersion());
            assertFalse(createdProfile.isEnabled());

            StaticKeyManagedSigningDto scheme = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    createdProfile.getSigningScheme());
            assertEquals(defaultTimestampingCertificate.getUuid(), scheme.getCertificate().getUuid());
            assertFalse(scheme.getSigningOperationAttributes().isEmpty());

            TimestampingWorkflowDto workflow = assertInstanceOf(TimestampingWorkflowDto.class,
                    createdProfile.getWorkflow());
            assertEquals(timestampingFormattingConnector.getUuid(),
                    workflow.getSignatureFormattingConnector().getUuid());
        }

        @Test
        void staticKeyManaged_incompleteChain_throwsValidationException() throws Exception {
            // given: a certificate whose chain cannot be verified (issuing CA is not in the inventory)
            Certificate incompleteChainCert = testCertificateAuthority.issueUntrustedCertificate();

            // when
            Executable createProfile = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
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
        void update_schemeFromStaticKeyManagedToDelegated()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile with static-key-managed scheme
            SigningProfileDto profile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("scheme-change-profile")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withRawSigning()
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(profile.getUuid());
            assertInstanceOf(StaticKeyManagedSigningDto.class, profile.getSigningScheme());

            // when: update to delegated scheme
            SigningProfileDto updated = signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(profile)
                                    .withDelegatedSigning(signerConnector.getUuid())
                                    .build());

            // then
            DelegatedSigningDto scheme = assertInstanceOf(DelegatedSigningDto.class, updated.getSigningScheme());
            assertEquals(signerConnector.getUuid(), scheme.getConnector().getUuid());
        }

        @Test
        void update_workflowFromRawToContentSigning()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile with RAW workflow
            SigningProfileDto profile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("workflow-raw-to-content")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(profile.getUuid());
            assertInstanceOf(RawSigningWorkflowDto.class, profile.getWorkflow());

            // when: update to content-signing workflow
            SigningProfileDto updated = signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(profile).withDelegatedContentSigning().build());

            // then: the workflow switched, and a delegated profile persists no formatting connector
            ContentSigningWorkflowDto workflow = assertInstanceOf(ContentSigningWorkflowDto.class,
                    updated.getWorkflow());
            assertThat(workflow.getSignatureFormattingConnector()).isNull();
        }

        @Test
        void update_workflowFromRawToTimestamping()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile with RAW workflow backed by a general signing certificate
            SigningProfileDto profile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("workflow-raw-to-timestamping")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withRawSigning()
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(profile.getUuid());
            assertInstanceOf(RawSigningWorkflowDto.class, profile.getWorkflow());

            // when: update to timestamping workflow
            SigningProfileDto updated = signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(profile)
                                    .withStaticKeyManagedSigning(defaultTimestampingCertificate.getUuid())
                                    .withTimestamping(UUID.fromString(timestampingFormattingConnector.getUuid()))
                                    .build());

            // then
            TimestampingWorkflowDto workflow = assertInstanceOf(TimestampingWorkflowDto.class, updated.getWorkflow());
            assertEquals(timestampingFormattingConnector.getUuid(),
                    workflow.getSignatureFormattingConnector().getUuid());
        }

        @Test
        void signingProfileCanBeUpdated() throws Exception {
            // given
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            Certificate qualifiedCert = testCertificateAuthority
                    .createTrustedCa("CN=Qualified Root CA")
                    .issueQualifiedTimestampingCertificate(keyPair, "CN=Test Qualified TSA");

            // when
            signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(defaultTimestampingProfile)
                                    .withName("updated-timestamping-profile")
                                    .withDescription("Updated description for timestamping profile")
                                    .withStaticKeyManagedSigning(qualifiedCert.getUuid())
                                    .withTimestamping(aTimestampingWorkflow()
                                            .withSignatureFormattingConnector(
                                                    UUID.fromString(timestampingFormattingConnector.getUuid()))
                                            .withDefaultPolicyId("1.2.3.4.5")
                                            .withAllowedPolicyIds(List.of("1.2.3.4.5", "1.2.3.4.6"))
                                            .withAllowedDigestAlgorithms(
                                                    List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_384))
                                            .withQualifiedTimestamp(true)
                                            .withValidateTokenSignature(true)
                                            .build())
                                    .build());

            // then
            SigningProfileDto updated = signingProfileService.getSigningProfile(profileUuid, null);
            assertEquals("updated-timestamping-profile", updated.getName());
            assertEquals("Updated description for timestamping profile", updated.getDescription());

            TimestampingWorkflowDto workflow = assertInstanceOf(TimestampingWorkflowDto.class, updated.getWorkflow());
            assertEquals(timestampingFormattingConnector.getUuid(),
                    workflow.getSignatureFormattingConnector().getUuid());
            assertEquals("1.2.3.4.5", workflow.getDefaultPolicyId());
            assertEquals(List.of("1.2.3.4.5", "1.2.3.4.6"), workflow.getAllowedPolicyIds());
            assertEquals(List.of(DigestAlgorithm.SHA_256, DigestAlgorithm.SHA_384),
                    workflow.getAllowedDigestAlgorithms());
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
            SigningProfileDto dto = signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                                    .withName("profile-with-bump")
                                    .build());

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
            SigningProfileDto dto = signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                                    .withName("profile-without-bump")
                                    .build());

            // then: version stays at 1 — no bump because no signing records reference it
            assertEquals(1, dto.getVersion());
            assertEquals(1, signingProfileService.getSigningProfile(profileUuid, null).getVersion());
            assertThrows(NotFoundException.class, () -> signingProfileService.getSigningProfile(profileUuid, 2),
                    "No version 2 snapshot should exist when no signing record was present");
        }

        @Test
        void withSigningRecordsOnFirstVersion_firstUpdateBumps_secondUpdateOverwritesLatest()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a signing record linked to version 1
            createSigningRecordFor(defaultDelegatedSigningProfile);
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());

            // when: first update — signing record on v1 forces a version bump
            signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                                    .withName("profile-after-first-update")
                                    .build());
            assertEquals(2, signingProfileService.getSigningProfile(profileUuid, null).getVersion());

            // when: second update — no signing records on v2, so it is overwritten in-place
            SigningProfileDto dto = signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(defaultDelegatedSigningProfile)
                                    .withName("profile-after-second-update")
                                    .build());

            // then: version stays at 2; no version 3 snapshot is created
            assertEquals(2, dto.getVersion());
            assertEquals("profile-after-second-update",
                    signingProfileService.getSigningProfile(profileUuid, null).getName());
            assertThrows(NotFoundException.class, () -> signingProfileService.getSigningProfile(profileUuid, 3),
                    "No version 3 snapshot should exist when v2 had no signing records");
        }

        @Test
        void versionBump_workflowFormattingAttributesDifferBetweenVersions()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: stub the formatting connector to expose a single configurable attribute
            UUID formattingAttrUuid = UUID.fromString("11111111-2222-3333-4444-555555555555");
            String formattingAttrName = "data_testPolicy";
            timestampingFormattingMock.stubFormattingAttributeDefinition(formattingAttrUuid, formattingAttrName, true);

            SigningProfileDto v1Profile = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("formatting-attrs-versioned")
                            .withStaticKeyManagedSigning(defaultTimestampingCertificate.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(timestampingFormattingConnector.getUuid()))
                                    .withSignatureFormattingConnectorAttributes(List
                                            .of(aStringAttribute(formattingAttrUuid, formattingAttrName, "policy-v1")))
                                    .build())
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(v1Profile.getUuid());
            createSigningRecordFor(v1Profile);

            // when: bump to v2 with a different attribute value
            signingProfileService
                    .updateSigningProfile(profileUuid, aSigningProfileRequestFromExistingProfile(v1Profile)
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(timestampingFormattingConnector.getUuid()))
                                    .withSignatureFormattingConnectorAttributes(List
                                            .of(aStringAttribute(formattingAttrUuid, formattingAttrName, "policy-v2")))
                                    .build())
                            .build());

            // then: each version exposes its own formatting attribute value
            TimestampingWorkflowDto v1Workflow = assertInstanceOf(TimestampingWorkflowDto.class,
                    signingProfileService.getSigningProfile(profileUuid, 1).getWorkflow());
            TimestampingWorkflowDto v2Workflow = assertInstanceOf(TimestampingWorkflowDto.class,
                    signingProfileService.getSigningProfile(profileUuid, 2).getWorkflow());

            assertEquals("policy-v1",
                    extractStringAttrValue(v1Workflow.getSignatureFormattingConnectorAttributes(), formattingAttrName));
            assertEquals("policy-v2",
                    extractStringAttrValue(v2Workflow.getSignatureFormattingConnectorAttributes(), formattingAttrName));
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
            tspProfileService
                    .createTspProfile(aTspProfileRequest()
                            .withName("expected-tsp-name")
                            .withDefaultSigningProfile(timestampingProfileUuid.getValue())
                            .build(), BASE_URL);

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

        @Test
        void namedAsATimestampSource_throwsValidationExceptionWithTheReferencingProfileName() throws Exception {
            // given: a content-signing profile naming the timestamping profile as its timestamp source
            SecuredUUID timestampingProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            ContentSigningFormattingMock formattingMock = connectorMockFactory.startContentSigningFormatting();
            try {
                ConnectorDetailDto connector = registerTimestampedRungConnector(formattingMock,
                        "content-signing-formatting-timestamped-rung");
                createProfileNamingTimestampSource("expected-content-signing-name", connector,
                        timestampingProfileUuid.getValue());

                // when
                ThrowableAssert.ThrowingCallable deleteProfile = () -> signingProfileService
                        .deleteSigningProfile(timestampingProfileUuid);

                // then: the reference is explained rather than surfacing as a constraint violation
                assertThatThrownBy(deleteProfile)
                        .isInstanceOf(ValidationException.class)
                        .satisfies(thrown -> assertThat(firstErrorMessage((ValidationException) thrown))
                                .contains("expected-content-signing-name", "timestamp source")
                                .contains("repoint them, or lower their maxLevel to SIGNED")
                                .doesNotContain("superseded version(s)"));
            } finally {
                formattingMock.stop();
            }
        }

        /**
         * Superseded version rows are retained and the foreign key spans every version, so the guard reports the
         * reference a repointed profile still holds in its history rather than letting the delete look available.
         */
        @Test
        void namedAsATimestampSourceByASupersededVersionOnly_stillRefusesTheDelete() throws Exception {
            // given: a profile repointed away from the timestamp source in a new version
            SecuredUUID timestampingProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            ContentSigningFormattingMock formattingMock = connectorMockFactory.startContentSigningFormatting();
            try {
                ConnectorDetailDto connector = registerTimestampedRungConnector(formattingMock,
                        "content-signing-formatting-repointed");
                SigningProfileDto referencing = createProfileNamingTimestampSource("repointed-content-signing-profile",
                        connector, timestampingProfileUuid.getValue());
                // A signing record on the current version is what makes the next save bump rather than overwrite.
                createSigningRecordFor(referencing);
                signingProfileService
                        .updateSigningProfile(SecuredUUID.fromString(referencing.getUuid()),
                                aSigningProfileRequest()
                                        .withName(referencing.getName())
                                        .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                                        .withContentSigning(aContentSigningWorkflow()
                                                .withSignatureFormattingConnector(UUID.fromString(connector.getUuid()))
                                                .withFamily(SignatureFamily.PADES)
                                                .withMaxLevel(SignatureLevel.SIGNED)
                                                .build())
                                        .build());

                // when
                ThrowableAssert.ThrowingCallable deleteProfile = () -> signingProfileService
                        .deleteSigningProfile(timestampingProfileUuid);

                // then
                assertThatThrownBy(deleteProfile)
                        .isInstanceOf(ValidationException.class)
                        .satisfies(thrown -> assertThat(firstErrorMessage((ValidationException) thrown))
                                .contains("repointed-content-signing-profile")
                                .contains("only in superseded version(s)")
                                .contains("deleting the referencing profile")
                                .contains("deleting its signing records")
                                .doesNotContain("repoint them"));
            } finally {
                formattingMock.stop();
            }
        }

        /**
         * The two buckets carry different remedies, so a timestamp source held live by one profile and only
         * historically by another has to report both rather than collapsing every name into one list.
         */
        @Test
        void namedAsATimestampSourceLiveAndBySupersededVersionOnly_reportsEachRemedyWithItsOwnNames() throws Exception {
            // given: one profile still naming the timestamp source, one repointed away from it in a new version
            SecuredUUID timestampingProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            ContentSigningFormattingMock formattingMock = connectorMockFactory.startContentSigningFormatting();
            try {
                ConnectorDetailDto connector = registerTimestampedRungConnector(formattingMock,
                        "content-signing-formatting-both-buckets");
                createProfileNamingTimestampSource("live-reference-profile", connector,
                        timestampingProfileUuid.getValue());
                SigningProfileDto repointed = createProfileNamingTimestampSource("history-only-profile", connector,
                        timestampingProfileUuid.getValue());
                // A signing record on the current version is what makes the next save bump rather than overwrite.
                createSigningRecordFor(repointed);
                signingProfileService
                        .updateSigningProfile(SecuredUUID.fromString(repointed.getUuid()),
                                aSigningProfileRequest()
                                        .withName(repointed.getName())
                                        .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                                        .withContentSigning(aContentSigningWorkflow()
                                                .withSignatureFormattingConnector(UUID.fromString(connector.getUuid()))
                                                .withFamily(SignatureFamily.PADES)
                                                .withMaxLevel(SignatureLevel.SIGNED)
                                                .build())
                                        .build());

                // when
                ThrowableAssert.ThrowingCallable deleteProfile = () -> signingProfileService
                        .deleteSigningProfile(timestampingProfileUuid);

                // then: each name sits under the remedy that applies to it, in that order
                assertThatThrownBy(deleteProfile)
                        .isInstanceOf(ValidationException.class)
                        .satisfies(thrown -> assertThat(firstErrorMessage((ValidationException) thrown))
                                .containsSubsequence("repoint them, or lower their maxLevel to SIGNED",
                                        "live-reference-profile", "only in superseded version(s)",
                                        "history-only-profile"));
            } finally {
                formattingMock.stop();
            }
        }

        @Nested
        class BulkDelete {

            @Test
            void removesAllEntities() {
                // given: an existing signing profiles
                SecuredUUID firstUuid = SecuredUUID.fromString(defaultDelegatedSigningProfile.getUuid());
                SecuredUUID secondUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());

                // when
                List<BulkActionMessageDto> messages = signingProfileService
                        .bulkDeleteSigningProfiles(List.of(firstUuid, secondUuid));

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
                List<BulkActionMessageDto> messages = signingProfileService
                        .bulkDeleteSigningProfiles(List.of(blockedProfileUuid, notBlockedProfileUuid));

                // then: defaultDelegatedSigningProfile blocked due to signing record, second deleted
                assertFalse(messages.isEmpty());
                assertTrue(messages.stream().anyMatch(m -> blockedProfileUuid.toString().equals(m.getUuid())));

                // and then: a blocked signing profile must still exist
                assertDoesNotThrow(() -> signingProfileService.getSigningProfile(blockedProfileUuid, null),
                        "Blocked profile must still exist");

                // and then: the second profile must be deleted
                assertThrows(NotFoundException.class,
                        () -> signingProfileService.getSigningProfile(notBlockedProfileUuid, null));
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
                List<BulkActionMessageDto> messages = signingProfileService
                        .bulkDeleteSigningProfiles(List.of(unknownProfileUuid, knownProfileUuid));

                // then
                assertFalse(messages.isEmpty(), "An error message should be returned for the non-existent UUID");
                assertTrue(messages.stream().anyMatch(m -> unknownProfileUuid.toString().equals(m.getUuid())));
                assertThrows(NotFoundException.class,
                        () -> signingProfileService.getSigningProfile(knownProfileUuid, null));
            }

            @Test
            void withTspProfileDependency_returnsErrorAndLeavesBlockedProfileIntact()
                    throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
                // given: defaultTimestampingProfile is the default of a TSP profile (blocked), plus an unblocked second
                // profile
                SecuredUUID blockedUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
                tspProfileService
                        .createTspProfile(aTspProfileRequest()
                                .withName("blocking-tsp")
                                .withDefaultSigningProfile(UUID.fromString(defaultTimestampingProfile.getUuid()))
                                .build(), BASE_URL);
                SigningProfileDto second = signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("unblocked-profile")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withRawSigning()
                                .build());
                SecuredUUID secondUuid = SecuredUUID.fromString(second.getUuid());

                // when
                List<BulkActionMessageDto> messages = signingProfileService
                        .bulkDeleteSigningProfiles(List.of(blockedUuid, secondUuid));

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
            void enable_afterCreate_persistsState()
                    throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
                // given: a newly created profile (disabled by default)
                SigningProfileDto dto = signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("profile-to-enable")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withRawSigning()
                                .build());
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
                List<BulkActionMessageDto> messages = signingProfileService
                        .bulkEnableSigningProfiles(List.of(unknownUuid, knownUuid));

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
                List<BulkActionMessageDto> messages = signingProfileService
                        .bulkDisableSigningProfiles(List.of(unknownUuid, knownUuid));

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
            TspProfileDto tsp = tspProfileService
                    .createTspProfile(aTspProfileRequest().withName("test-tsp-profile").build(), BASE_URL);
            SecuredUUID tspUuid = SecuredUUID.fromString(tsp.getUuid());

            // when
            TspActivationDetailDto activationDto = signingProfileService
                    .activateTsp(timestampingProfileUuid, tspUuid, BASE_URL);

            // then
            assertTrue(activationDto.isAvailable());
            assertNotNull(activationDto.getSigningUrl());
            assertTrue(signingProfileService
                    .getSigningProfile(timestampingProfileUuid, null)
                    .getEnabledProtocols()
                    .contains(SigningProtocol.TSP));
        }

        @Test
        void activate_tspProfileNotFound_throwsNotFoundException() {
            // given: a signing profile, and a TSP UUID that does not exist
            SecuredUUID timestampingProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            SecuredUUID nonExistentTspUuid = SecuredUUID.fromString("00000000-0000-0000-0000-000000000002");

            // when
            Executable activate = () -> signingProfileService
                    .activateTsp(timestampingProfileUuid, nonExistentTspUuid, BASE_URL);

            // then
            assertThrows(NotFoundException.class, activate);
        }

        @Test
        void activate_replacesExistingLink() throws AlreadyExistException, AttributeException, NotFoundException {
            // given: a signing profile linked to tsp1
            SecuredUUID timestampingProfileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            TspProfileDto tsp1 = tspProfileService
                    .createTspProfile(aTspProfileRequest().withName("tsp-profile-1").build(), BASE_URL);
            TspProfileDto tsp2 = tspProfileService
                    .createTspProfile(aTspProfileRequest().withName("tsp-profile-2").build(), BASE_URL);
            SecuredUUID tsp1Uuid = SecuredUUID.fromString(tsp1.getUuid());
            SecuredUUID tsp2Uuid = SecuredUUID.fromString(tsp2.getUuid());
            signingProfileService.activateTsp(timestampingProfileUuid, tsp1Uuid, BASE_URL);

            // when: replace with tsp2
            signingProfileService.activateTsp(timestampingProfileUuid, tsp2Uuid, BASE_URL);

            // then: tsp2 is the active TSP (signing URL references its UUID, not tsp1's)
            assertTrue(
                    signingProfileService
                            .getSigningProfile(timestampingProfileUuid, null)
                            .getEnabledProtocols()
                            .contains(SigningProtocol.TSP),
                    "TSP should remain active after replacing the linked TSP profile");
        }

        @Test
        void activate_rawWorkflow_throwsValidationException() {
            // given: a signing profile with RAW_SIGNING workflow (does not support TSP)
            SecuredUUID rawSingingProfileUuid = SecuredUUID.fromString(defaultRawSigningProfile.getUuid());
            SecuredUUID tspUuid = SecuredUUID.fromString(defaultTspProtocol.getUuid());

            // when
            Executable activate = () -> signingProfileService.activateTsp(rawSingingProfileUuid, tspUuid, BASE_URL);

            // then
            assertThrows(ValidationException.class, activate);
        }

        @Test
        void activate_contentSigningWorkflow_throwsValidationException() {
            // given: a signing profile with CONTENT_SIGNING workflow (does not support TSP)
            SecuredUUID contentSigningProfileUuid = SecuredUUID.fromString(defaultContentSigningProfile.getUuid());
            SecuredUUID tspUuid = SecuredUUID.fromString(defaultTspProtocol.getUuid());

            // when
            Executable activate = () -> signingProfileService.activateTsp(contentSigningProfileUuid, tspUuid, BASE_URL);

            // then
            assertThrows(ValidationException.class, activate);
        }

        @Test
        void deactivate_removesFromEnabledProtocols() throws NotFoundException {
            // given: a TIMESTAMPING signing profile linked to a TSP profile
            SecuredUUID profileUuid = SecuredUUID.fromString(defaultTimestampingProfile.getUuid());
            signingProfileService
                    .activateTsp(profileUuid, SecuredUUID.fromString(defaultTspProtocol.getUuid()), BASE_URL);
            assertTrue(signingProfileService
                    .getSigningProfile(profileUuid, null)
                    .getEnabledProtocols()
                    .contains(SigningProtocol.TSP));

            // when
            signingProfileService.deactivateTsp(profileUuid);

            // then: TSP is no longer in enabled protocols
            assertFalse(
                    signingProfileService
                            .getSigningProfile(profileUuid, null)
                            .getEnabledProtocols()
                            .contains(SigningProtocol.TSP),
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
            StaticKeyManagedSigningDto schemeDto = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    dto.getSigningScheme());
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
            SigningProfileDto persisted = signingProfileService
                    .getSigningProfile(SecuredUUID.fromString(dto.getUuid()), null);
            assertEquals(dto, persisted);
        }

        @Test
        void update_staticKey_attributesReplacedOnUpdate()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a static-key profile created with PKCS1_v1_5/SHA_256 signing attributes
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("static-key-update-sign-attrs")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                    rsaSignatureAttributes()
                                            .withScheme(RsaSignatureScheme.PKCS1_v1_5)
                                            .withDigest(DigestAlgorithm.SHA_256)
                                            .build())
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when: update to PSS/SHA_384
            SigningProfileDto updated = signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(created)
                                    .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                            rsaSignatureAttributes()
                                                    .withScheme(RsaSignatureScheme.PSS)
                                                    .withDigest(DigestAlgorithm.SHA_384)
                                                    .build())
                                    .build());

            // then: both attributes must reflect the new values, not the old ones
            StaticKeyManagedSigningDto schemeDto = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    updated.getSigningScheme());
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
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("static-key-to-delegated")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                    rsaSignatureAttributes()
                                            .withScheme(RsaSignatureScheme.PKCS1_v1_5)
                                            .withDigest(DigestAlgorithm.SHA_256)
                                            .build())
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when: switch to DELEGATED
            SigningProfileDto updated = signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(created)
                                    .withDelegatedSigning(signerConnector.getUuid())
                                    .build());

            // then: the returned DTO has a delegated scheme with no signing operation attributes
            assertInstanceOf(DelegatedSigningDto.class, updated.getSigningScheme());

            // and re-fetching confirms the scheme change persisted
            SigningProfileDto fetched = signingProfileService.getSigningProfile(profileUuid, null);
            assertInstanceOf(DelegatedSigningDto.class, fetched.getSigningScheme());

            // and the AttributeEngine holds no SIGN rows for this profile version (no stale engine data)
            List<ResponseAttribute> remaining = attributeEngine
                    .getObjectDataAttributesContent(ObjectAttributeContentInfo
                            .builder(Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()))
                            .operation(AttributeOperation.SIGN)
                            .version(1)
                            .build());
            assertTrue(remaining.isEmpty(),
                    "SIGN attributes should be cleared from the engine when scheme changes away from STATIC_KEY");

        }

        @Test
        void delete_profileNoLongerAccessible()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a static-key profile with signing operation attributes
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("delete-clears-sign-attrs")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                    rsaSignatureAttributes()
                                            .withScheme(RsaSignatureScheme.PSS)
                                            .withDigest(DigestAlgorithm.SHA_256)
                                            .build())
                            .withRawSigning()
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());

            // when
            signingProfileService.deleteSigningProfile(profileUuid);

            // then: the profile is gone — attributes are inaccessible along with it
            assertThrows(NotFoundException.class, () -> signingProfileService.getSigningProfile(profileUuid, null));

            // and the AttributeEngine holds no SIGN rows for this profile version (no stale engine data)
            List<ResponseAttribute> remaining = attributeEngine
                    .getObjectDataAttributesContent(ObjectAttributeContentInfo
                            .builder(Resource.SIGNING_PROFILE, UUID.fromString(created.getUuid()))
                            .operation(AttributeOperation.SIGN)
                            .version(1)
                            .build());
            assertTrue(remaining.isEmpty(),
                    "SIGN attributes should be cleared from the engine when Signig Profile gets deleted");
        }

        @Test
        void getSpecificVersion_returnsVersionedAttributes()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: v1 with PSS/SHA_256, signing record locks v1 so the next update bumps to v2
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("versioned-get-sign-attrs")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                    rsaSignatureAttributes()
                                            .withScheme(RsaSignatureScheme.PSS)
                                            .withDigest(DigestAlgorithm.SHA_256)
                                            .build())
                            .build());
            SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());
            createSigningRecordFor(created);

            // when: bump to v2 with PKCS1_v1_5/SHA_384
            signingProfileService
                    .updateSigningProfile(profileUuid,
                            aSigningProfileRequestFromExistingProfile(created)
                                    .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid(),
                                            rsaSignatureAttributes()
                                                    .withScheme(RsaSignatureScheme.PKCS1_v1_5)
                                                    .withDigest(DigestAlgorithm.SHA_384)
                                                    .build())
                                    .build());

            // then: each version returns its own attribute values through the DTO
            // v1
            StaticKeyManagedSigningDto v1Scheme = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    signingProfileService.getSigningProfile(profileUuid, 1).getSigningScheme());
            assertEquals(RsaSignatureScheme.PSS.getCode(), extractStringAttrValue(
                    v1Scheme.getSigningOperationAttributes(), RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME));
            assertEquals(DigestAlgorithm.SHA_256.getCode(), extractStringAttrValue(
                    v1Scheme.getSigningOperationAttributes(), RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST));
            // v2
            StaticKeyManagedSigningDto v2Scheme = assertInstanceOf(StaticKeyManagedSigningDto.class,
                    signingProfileService.getSigningProfile(profileUuid, 2).getSigningScheme());
            assertEquals(RsaSignatureScheme.PKCS1_v1_5.getCode(), extractStringAttrValue(
                    v2Scheme.getSigningOperationAttributes(), RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME));
            assertEquals(DigestAlgorithm.SHA_384.getCode(), extractStringAttrValue(
                    v2Scheme.getSigningOperationAttributes(), RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST));

            // and: the engine holds separate rows for each version
            UUID profileUuidRaw = UUID.fromString(created.getUuid());
            assertFalse(attributeEngine
                    .getObjectDataAttributesContent(ObjectAttributeContentInfo
                            .builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                            .operation(AttributeOperation.SIGN)
                            .version(1)
                            .build())
                    .isEmpty(), "Engine must hold SIGN rows for version 1");
            assertFalse(attributeEngine
                    .getObjectDataAttributesContent(ObjectAttributeContentInfo
                            .builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                            .operation(AttributeOperation.SIGN)
                            .version(2)
                            .build())
                    .isEmpty(), "Engine must hold SIGN rows for version 2");
        }
    }

    @Nested
    class FormattingAttributes {

        @Test
        void create_contentSigning_attributesPersistedAndReturned()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: stub the content signing formatting to expose a single configurable attribute
            UUID attrUuid = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
            String attrName = "data_testFormattingAttr";
            contentSigningFormattingMock.stubPerOperationFormattingAttributeDefinition(attrUuid, attrName);

            // when
            SigningProfileDto dto = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("doc-profile-with-formatting-attrs")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                    .withFamily(SignatureFamily.PADES)
                                    .withMaxLevel(SignatureLevel.SIGNED)
                                    .withSignatureFormattingConnectorAttributes(
                                            List.of(aStringAttribute(attrUuid, attrName, "testValue")))
                                    .build())
                            .build());

            // then: the attribute is returned in the DTO and its value matches what was sent
            ContentSigningWorkflowDto wfDto = assertInstanceOf(ContentSigningWorkflowDto.class, dto.getWorkflow());
            List<ResponseAttribute> attrs = wfDto.getSignatureFormattingConnectorAttributes();
            assertFalse(attrs.isEmpty(), "Signature Formatting Provider attributes should be populated after create");
            assertEquals("testValue", extractStringAttrValue(attrs, attrName));
        }

        @Test
        void update_contentSigningConnectorChanged_oldFormattingAttributesCleared()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: stub the existing content signing formatting connector with a specific attribute definition
            UUID attrUuid = UUID.fromString("11111111-2222-3333-4444-555555555556");
            String attrName = "data_formattingSwitchTest";
            contentSigningFormattingMock.stubPerOperationFormattingAttributeDefinition(attrUuid, attrName);

            // and: a second content signing formatting connector (formattingB)
            ContentSigningFormattingMock formattingBMock = connectorMockFactory.startContentSigningFormatting();
            formattingBMock.stubPerOperationFormattingAttributeDefinition(attrUuid, attrName);
            ConnectorDetailDto formattingBConnector = connectorService
                    .createConnector(aV2ConnectorRequest()
                            .withName("content-signing-formatting-b")
                            .withUrl(formattingBMock.getUrl())
                            .build());

            try {
                // and: a profile using formattingA (contentSigningFormattingConnector) with attribute "valueA"
                SigningProfileDto created = signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("formatting-switch-test")
                                .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                                .withContentSigning(aContentSigningWorkflow()
                                        .withSignatureFormattingConnector(
                                                UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                        .withFamily(SignatureFamily.PADES)
                                        .withMaxLevel(SignatureLevel.SIGNED)
                                        .withSignatureFormattingConnectorAttributes(
                                                List.of(aStringAttribute(attrUuid, attrName, "valueA")))
                                        .build())
                                .build());
                SecuredUUID profileUuid = SecuredUUID.fromString(created.getUuid());
                UUID profileUuidRaw = UUID.fromString(created.getUuid());

                // when: update to formattingB with attribute "valueB"
                signingProfileService
                        .updateSigningProfile(profileUuid,
                                aSigningProfileRequestFromExistingProfile(created)
                                        .withContentSigning(aContentSigningWorkflow()
                                                .withSignatureFormattingConnector(
                                                        UUID.fromString(formattingBConnector.getUuid()))
                                                .withFamily(SignatureFamily.PADES)
                                                .withMaxLevel(SignatureLevel.SIGNED)
                                                .withSignatureFormattingConnectorAttributes(
                                                        List.of(aStringAttribute(attrUuid, attrName, "valueB")))
                                                .build())
                                        .build());

                // then: formattingA's engine rows are gone (no stale attributes for the old connector)
                List<ResponseAttribute> oldAttrs = attributeEngine
                        .getObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                                .connector(UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                .operation(AttributeOperation.WORKFLOW_FORMATTING)
                                .version(1)
                                .build());
                assertTrue(oldAttrs.isEmpty(),
                        "Attributes for the replaced formatting connector should be cleared from the engine");

                // then: formattingB's attributes are stored with the correct value
                List<ResponseAttribute> newAttrs = attributeEngine
                        .getObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(Resource.SIGNING_PROFILE, profileUuidRaw)
                                .connector(UUID.fromString(formattingBConnector.getUuid()))
                                .operation(AttributeOperation.WORKFLOW_FORMATTING)
                                .version(1)
                                .build());
                assertFalse(newAttrs.isEmpty(),
                        "Attributes for the new formatting connector should be persisted after the update");
                assertEquals("valueB", extractStringAttrValue(newAttrs, attrName));
            } finally {
                formattingBMock.stop();
            }
        }

        @Test
        void delete_removesFormattingAttributesFromEngine()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a content signing profile with a formatting attribute
            UUID attrUuid = UUID.fromString("cccccccc-dddd-eeee-ffff-000000000001");
            String attrName = "data_deleteFormattingAttr";
            contentSigningFormattingMock.stubPerOperationFormattingAttributeDefinition(attrUuid, attrName);

            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("delete-clears-formatting-attrs")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                    .withFamily(SignatureFamily.PADES)
                                    .withMaxLevel(SignatureLevel.SIGNED)
                                    .withSignatureFormattingConnectorAttributes(
                                            List.of(aStringAttribute(attrUuid, attrName, "toDelete")))
                                    .build())
                            .build());
            UUID profileUuid = UUID.fromString(created.getUuid());

            // when
            signingProfileService.deleteSigningProfile(SecuredUUID.fromUUID(profileUuid));

            // then: no stale engine rows remain for the deleted profile
            List<ResponseAttribute> remaining = attributeEngine
                    .getObjectDataAttributesContent(ObjectAttributeContentInfo
                            .builder(Resource.SIGNING_PROFILE, profileUuid)
                            .connector(UUID.fromString(contentSigningFormattingConnector.getUuid()))
                            .operation(AttributeOperation.WORKFLOW_FORMATTING)
                            .version(1)
                            .build());
            assertTrue(remaining.isEmpty(),
                    "Formatting attributes should be cleared from the engine when the profile is deleted");
        }

    }

    @Nested
    class FormattingAttributeValidation {

        @Test
        void create_contentSigning_requiredAttributeMissing_throwsValidationException() {
            // given: the formatting connector advertises a required attribute
            UUID attrUuid = UUID.fromString("00000000-dead-beef-0002-000000000001");
            String attrName = "req_content_attr";
            contentSigningFormattingMock.stubPerOperationFormattingAttributeDefinition(attrUuid, attrName, true);

            // when: create a profile omitting the required attribute
            Executable create = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("content-missing-required-attr")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withManagedContentSigning(UUID.fromString(contentSigningFormattingConnector.getUuid()))
                            .build());

            // then
            assertThrows(ValidationException.class, create,
                    "createSigningProfile must reject a missing required formatting attribute");
        }

        @Test
        void create_managedContentSigning_noFormattingConnector_throwsValidationExceptionWithoutCallingAConnector() {
            // given: an ILM-managed profile naming no signature formatting connector at all
            // when
            ThrowableAssert.ThrowingCallable create = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("content-signing-no-formatting-connector")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withFamily(SignatureFamily.PADES)
                                    .withMaxLevel(SignatureLevel.SIGNED)
                                    .build())
                            .build());

            // then: rejected before any connector is contacted, not with a lookup failure on a null UUID
            assertThatThrownBy(create)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Signature formatting connector is required");
        }

        @Test
        void create_timestamping_requiredAttributeMissing_throwsValidationException() {
            // given: the formatting connector advertises a required attribute
            UUID attrUuid = UUID.fromString("00000000-dead-beef-0002-000000000001");
            String attrName = "req_timestamping_attr";
            timestampingFormattingMock.stubFormattingAttributeDefinition(attrUuid, attrName, true);

            // when: create a profile omitting the required attribute
            Executable create = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("timestamping-missing-required-attr")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(timestampingFormattingConnector.getUuid()))
                                    .build())
                            .build());

            // then
            ValidationException exception = assertThrows(ValidationException.class, create,
                    "createSigningProfile must reject a missing required formatting attribute");
            assertTrue(exception.getMessage().contains(attrName),
                    "ValidationException must identify the missing required formatting attribute, but was: "
                            + exception.getMessage());
        }
    }

    @Nested
    class ContentSigningFormattingAttributeDiscovery {

        @Test
        void timestampingDiscovery_stillServesItsOwnDescriptors()
                throws AttributeException, ConnectorException, NotFoundException {
            // given
            UUID attrUuid = UUID.fromString("0000ffff-1111-2222-3333-777777777777");
            String attrName = "data_timestampingFormattingAttr";
            timestampingFormattingMock.stubFormattingAttributeDefinition(attrUuid, attrName, false);

            // when
            List<BaseAttribute> discovered = signingProfileService
                    .listSignatureFormattingConnectorAttributes(
                            UUID.fromString(timestampingFormattingConnector.getUuid()), SecuredUUID.fromUUID(null));

            // then
            assertThat(discovered).extracting(BaseAttribute::getName).containsExactly(attrName);
        }

        @Test
        void discovery_servesTheAggregateAProfileSaveThenAccepts()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: the provider declares one attribute on every content-signing operation
            UUID attrUuid = UUID.fromString("0000dddd-1111-2222-3333-444444444444");
            String attrName = "data_discoveredFormattingAttr";
            contentSigningFormattingMock.stubPerOperationFormattingAttributeDefinition(attrUuid, attrName);

            // when: a create-time form asks what it may configure, naming no profile of its own yet
            List<BaseAttribute> discovered = signingProfileService
                    .listContentSigningFormattingConnectorAttributes(
                            UUID.fromString(contentSigningFormattingConnector.getUuid()), SignatureFamily.PADES,
                            SignatureLevel.SIGNED, SecuredUUID.fromUUID(null));

            // then: the operations declaring one shared name merge into one entry
            assertThat(discovered).extracting(BaseAttribute::getName).containsExactly(attrName);

            // and: a profile built from that answer saves, which is the whole contract of the endpoint
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("profile-built-from-discovery")
                            .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                    .withFamily(SignatureFamily.PADES)
                                    .withMaxLevel(SignatureLevel.SIGNED)
                                    .withSignatureFormattingConnectorAttributes(
                                            List.of(aStringAttribute(attrUuid, attrName, "discoveredValue")))
                                    .build())
                            .build());
            ContentSigningWorkflowDto workflow = assertInstanceOf(ContentSigningWorkflowDto.class,
                    created.getWorkflow());
            assertEquals("discoveredValue",
                    extractStringAttrValue(workflow.getSignatureFormattingConnectorAttributes(), attrName));
        }

        @Test
        void discovery_atALevelTheProviderDoesNotReach_isRefusedTheWaySaveWouldRefuseIt() {
            // given: the registered provider advertises content signing but no timestamped rung
            // when: the form asks for the descriptors of a TIMESTAMPED ceiling
            ThrowableAssert.ThrowingCallable discover = () -> signingProfileService
                    .listContentSigningFormattingConnectorAttributes(
                            UUID.fromString(contentSigningFormattingConnector.getUuid()), SignatureFamily.PADES,
                            SignatureLevel.TIMESTAMPED, SecuredUUID.fromUUID(null));

            // then: the operator learns at form-build time, not at save
            assertThatThrownBy(discover)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not reach level TIMESTAMPED");
        }

        @Test
        void discovery_atATimestampedCeiling_reachesTheTimestampOperationsToo()
                throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
            // given: a provider that reaches TIMESTAMPED and declares one attribute on every operation
            ContentSigningFormattingMock timestampedMock = connectorMockFactory.startContentSigningFormatting();
            try {
                String baselineAttr = "data_baselineRungAttr";
                String timestampOnlyAttr = "data_timestampRungOnlyAttr";
                ConnectorDetailDto timestamped = registerTimestampedRungConnector(timestampedMock,
                        "content-signing-formatting-timestamped-discovery");
                timestampedMock
                        .stubPerOperationFormattingAttributeDefinition(
                                UUID.fromString("0000eeee-1111-2222-3333-555555555555"), baselineAttr);
                timestampedMock
                        .stubFormattingAttributeDefinitionFor(
                                ContentSigningFormattingOperation.EMBED_SIGNATURE_TIMESTAMP,
                                UUID.fromString("0000eeee-1111-2222-3333-666666666666"), timestampOnlyAttr);

                // when
                List<BaseAttribute> discovered = signingProfileService
                        .listContentSigningFormattingConnectorAttributes(UUID.fromString(timestamped.getUuid()),
                                SignatureFamily.PADES, SignatureLevel.TIMESTAMPED, SecuredUUID.fromUUID(null));

                // then: the aggregate carries the name only a timestamp operation declares
                assertThat(discovered)
                        .extracting(BaseAttribute::getName)
                        .containsExactlyInAnyOrder(baselineAttr, timestampOnlyAttr);
            } finally {
                timestampedMock.stop();
            }
        }

        @Test
        void discovery_forAFamilyTheProviderDoesNotServe_isRefusedTheWaySaveWouldRefuseIt()
                throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
            // given: a provider advertising no content-signing feature on the PAdES interface
            ContentSigningFormattingMock featurelessMock = connectorMockFactory.startContentSigningFormatting();
            try {
                featurelessMock.advertiseNoContentSigningFeature();
                ConnectorDetailDto featureless = connectorService
                        .createConnector(aV2ConnectorRequest()
                                .withName("content-signing-formatting-featureless-discovery")
                                .withUrl(featurelessMock.getUrl())
                                .build());

                // when
                ThrowableAssert.ThrowingCallable discover = () -> signingProfileService
                        .listContentSigningFormattingConnectorAttributes(UUID.fromString(featureless.getUuid()),
                                SignatureFamily.PADES, SignatureLevel.SIGNED, SecuredUUID.fromUUID(null));

                // then: refused with save's own message, before the provider is asked for any schema
                assertThatThrownBy(discover)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining(
                                "does not advertise the 'Content Signing' feature on its 'PAdES Formatting' interface");
            } finally {
                featurelessMock.stop();
            }
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
        void create_withCustomAttributes_returnedInDto()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            RequestAttributeV3 customAttr = aCustomAttribute()
                    .withUuid(CUSTOM_ATTR_UUID)
                    .withName(CUSTOM_ATTR_NAME)
                    .withStringContent("profile-value-on-create")
                    .build();

            // when
            SigningProfileDto dto = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("profile-with-custom-attr")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .withCustomAttributes(List.of(customAttr))
                            .build());

            // then — DTO reflects the created value
            assertNotNull(dto.getCustomAttributes());
            assertFalse(dto.getCustomAttributes().isEmpty(), "Custom attributes should be returned in the create DTO");
            assertEquals("profile-value-on-create",
                    ((ResponseAttributeV3) dto.getCustomAttributes().getFirst()).getContent().getFirst().getData());

            // and — attribute engine agrees with the DTO (no stale cache / divergence)
            List<ResponseAttribute> engineAttrs = attributeEngine
                    .getObjectCustomAttributesContent(Resource.SIGNING_PROFILE, UUID.fromString(dto.getUuid()));
            assertFalse(engineAttrs.isEmpty());
            assertEquals("profile-value-on-create",
                    ((ResponseAttributeV3) engineAttrs.getFirst()).getContent().getFirst().getData());
        }

        @Test
        void update_withCustomAttributes_returnedInDtoAndPersisted()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given: a profile created with a custom attribute set to "initial-value"
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("profile-update-custom-attr")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .withRawSigning()
                            .withCustomAttributes(List
                                    .of(aCustomAttribute()
                                            .withUuid(CUSTOM_ATTR_UUID)
                                            .withName(CUSTOM_ATTR_NAME)
                                            .withStringContent("initial-value")
                                            .build()))
                            .build());

            // when: update with "updated-value"
            SigningProfileDto updated = signingProfileService
                    .updateSigningProfile(SecuredUUID.fromString(created.getUuid()),
                            aSigningProfileRequestFromExistingProfile(created)
                                    .withCustomAttributes(List
                                            .of(aCustomAttribute()
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
            List<ResponseAttribute> engineAttrs = attributeEngine
                    .getObjectCustomAttributesContent(Resource.SIGNING_PROFILE, UUID.fromString(updated.getUuid()));
            assertFalse(engineAttrs.isEmpty());
            assertEquals("updated-value",
                    ((ResponseAttributeV3) engineAttrs.getFirst()).getContent().getFirst().getData());
        }

    }

    @Nested
    class NameUniqueness {

        @Test
        void create_duplicateName_throwsAlreadyExistException()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("duplicate-name")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            // when
            Executable createDuplicate = () -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("duplicate-name")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            // then
            assertThrows(AlreadyExistException.class, createDuplicate);
        }

        @Test
        void update_toExistingNameOfAnotherProfile_throwsAlreadyExistException()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("profile-alpha")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());
            SigningProfileDto beta = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("profile-beta")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            // when
            Executable updateToExistingName = () -> signingProfileService
                    .updateSigningProfile(SecuredUUID.fromString(beta.getUuid()),
                            aSigningProfileRequest()
                                    .withName("profile-alpha")
                                    .withDelegatedSigning(signerConnector.getUuid())
                                    .build());

            // then: renaming beta to alpha collides with the existing profile
            assertThrows(AlreadyExistException.class, updateToExistingName);
        }

        @Test
        void update_keepingSameName_succeeds()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("keep-same-name")
                            .withDelegatedSigning(signerConnector.getUuid())
                            .build());

            // when
            SigningProfileDto updated = signingProfileService
                    .updateSigningProfile(SecuredUUID.fromString(created.getUuid()),
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
            signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ts-managed-model")
                            .withStaticKeyManagedSigning(defaultTimestampingCertificate.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(timestampingFormattingConnector.getUuid()))
                                    .build())
                            .build());

            // when
            SigningProfileModel<?, ?> model = signingProfileInternalService.getSigningProfileModel("ts-managed-model");

            // then
            assertInstanceOf(ManagedTimestampingWorkflow.class, model.workflow());
            assertInstanceOf(StaticKeyManagedSigning.class, model.signingScheme());
            StaticKeyManagedSigning schemeModel = (StaticKeyManagedSigning) model.signingScheme();
            assertEquals(defaultTimestampingCertificate.getUuid(), schemeModel.certificateUuid());
        }

        @Test
        void validationPropertiesRoundTrip()
                throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
            // given
            signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ts-managed-validation-props")
                            .withStaticKeyManagedSigning(defaultTimestampingCertificate.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(timestampingFormattingConnector.getUuid()))
                                    .withDefaultPolicyId("1.2.3.4.5")
                                    .withAllowedPolicyIds(List.of("1.2.3.4.5", "1.2.3.4.6"))
                                    .withAllowedDigestAlgorithms(List.of(DigestAlgorithm.SHA_256))
                                    .withValidateTokenSignature(true)
                                    .build())
                            .build());

            // when
            SigningProfileModel<?, ?> model = signingProfileInternalService
                    .getSigningProfileModel("ts-managed-validation-props");

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
            SigningProfileDto created = signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("ts-managed-base-fields")
                            .withDescription("expected ts description")
                            .withStaticKeyManagedSigning(defaultTimestampingCertificate.getUuid())
                            .withTimestamping(aTimestampingWorkflow()
                                    .withSignatureFormattingConnector(
                                            UUID.fromString(timestampingFormattingConnector.getUuid()))
                                    .build())
                            .build());

            // when
            SigningProfileModel<?, ?> model = signingProfileInternalService
                    .getSigningProfileModel("ts-managed-base-fields");

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
                                aTimeQualityConfigurationRequest().withName("tqc-for-create-link").build());

                // when
                SigningProfileDto dto = signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("ts-with-tqc")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormattingConnector(
                                                UUID.fromString(timestampingFormattingConnector.getUuid()))
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
                Executable create = () -> signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("ts-bad-tqc")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormattingConnector(
                                                UUID.fromString(timestampingFormattingConnector.getUuid()))
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
                                aTimeQualityConfigurationRequest().withName("tqc-for-clear-test").build());

                SigningProfileDto created = signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("ts-to-raw-profile")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormattingConnector(
                                                UUID.fromString(timestampingFormattingConnector.getUuid()))
                                        .withTimeQualityConfiguration(UUID.fromString(tqc.getUuid()))
                                        .build())
                                .build());

                assertNotNull(((TimestampingWorkflowDto) created.getWorkflow()).getTimeQualityConfiguration(),
                        "precondition: TQC must be linked before the update");

                // when: update to RAW_SIGNING — TQC must be cleared
                SigningProfileDto updated = signingProfileService
                        .updateSigningProfile(SecuredUUID.fromString(created.getUuid()),
                                aSigningProfileRequestFromExistingProfile(created).withRawSigning().build());

                // then: re-fetched profile has RAW workflow
                SigningProfileDto fetched = signingProfileService
                        .getSigningProfile(SecuredUUID.fromString(updated.getUuid()), null);
                assertInstanceOf(RawSigningWorkflowDto.class, fetched.getWorkflow(),
                        "TimeQualityConfiguration must be cleared when workflow changes away from TIMESTAMPING");
            }

            @Test
            void listAssociated_returnsAssociatedProfiles()
                    throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
                // given: two TIMESTAMPING profiles linked to the same TQC
                TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                        .createTimeQualityConfiguration(
                                aTimeQualityConfigurationRequest().withName("tqc-for-list-test").build());
                UUID tqcUuid = UUID.fromString(tqc.getUuid());

                SigningProfileDto p1 = signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("list-ts-profile-one")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormattingConnector(
                                                UUID.fromString(timestampingFormattingConnector.getUuid()))
                                        .withTimeQualityConfiguration(tqcUuid)
                                        .build())
                                .build());
                SigningProfileDto p2 = signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("list-ts-profile-two")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormattingConnector(
                                                UUID.fromString(timestampingFormattingConnector.getUuid()))
                                        .withTimeQualityConfiguration(tqcUuid)
                                        .build())
                                .build());

                // when
                List<SimplifiedSigningProfileDto> result = signingProfileService
                        .listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID.fromUUID(tqcUuid),
                                SecurityFilter.create());

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
                        .createTimeQualityConfiguration(aTimeQualityConfigurationRequest().withName("tqc-A").build());
                TimeQualityConfigurationDto tqcB = timeQualityConfigurationService
                        .createTimeQualityConfiguration(aTimeQualityConfigurationRequest().withName("tqc-B").build());

                SigningProfileDto profileA = signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("profile-linked-to-tqc-A")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormattingConnector(
                                                UUID.fromString(timestampingFormattingConnector.getUuid()))
                                        .withTimeQualityConfiguration(UUID.fromString(tqcA.getUuid()))
                                        .build())
                                .build());
                signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("profile-linked-to-tqc-B")
                                .withDelegatedSigning(signerConnector.getUuid())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormattingConnector(
                                                UUID.fromString(timestampingFormattingConnector.getUuid()))
                                        .withTimeQualityConfiguration(UUID.fromString(tqcB.getUuid()))
                                        .build())
                                .build());

                // when: query for TQC-A only
                List<SimplifiedSigningProfileDto> result = signingProfileService
                        .listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID.fromString(tqcA.getUuid()),
                                SecurityFilter.create());

                // then
                assertEquals(1, result.size());
                assertEquals(profileA.getUuid(), result.getFirst().getUuid(),
                        "Only the profile linked to TQC-A should be returned");
            }

            @Test
            void listAssociated_emptyWhenNoneAssociated()
                    throws AlreadyExistException, AttributeException, NotFoundException {
                // given
                TimeQualityConfigurationDto tqc = timeQualityConfigurationService
                        .createTimeQualityConfiguration(
                                aTimeQualityConfigurationRequest().withName("tqc-no-profiles").build());

                // when
                List<SimplifiedSigningProfileDto> result = signingProfileService
                        .listSigningProfilesAssociatedTimeQualityConfiguration(SecuredUUID.fromString(tqc.getUuid()),
                                SecurityFilter.create());

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
                Executable getProfile = () -> signingProfileInternalService
                        .getSigningProfileModel(nonExistentSigningProfileName);

                // then
                assertThrows(NotFoundException.class, getProfile);
            }
        }

        @Nested
        class ManagedContentSigningModel {

            @Test
            void contentSigning_staticKeyScheme_returnsTypedModel()
                    throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
                // given
                signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("cs-managed-model")
                                .withStaticKeyManagedSigning(defaultSigningCertificate.getUuid())
                                .withManagedContentSigning(UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                .build());

                // when
                SigningProfileModel<?, ?> model = signingProfileInternalService
                        .getSigningProfileModel("cs-managed-model");

                // then
                assertThat(model.workflow()).isInstanceOf(ManagedContentSigningWorkflow.class);
                assertThat(model.signingScheme()).isInstanceOf(StaticKeyManagedSigning.class);
                ManagedContentSigningWorkflow workflow = (ManagedContentSigningWorkflow) model.workflow();
                assertThat(workflow.signatureFormattingConnectorUuid())
                        .isEqualTo(UUID.fromString(contentSigningFormattingConnector.getUuid()));
            }
        }

        @Test
        void rawSigningProfile_throwsIllegalArgumentException() {
            // given: a pre-configured raw-signing profile — RAW_SIGNING has no model mapper yet (core#2004)
            String rawProfileName = defaultRawSigningProfile.getName();

            // when / then
            assertThatThrownBy(() -> signingProfileInternalService.getSigningProfileModel(rawProfileName))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("does not support model retrieval yet");
        }

    }
}
