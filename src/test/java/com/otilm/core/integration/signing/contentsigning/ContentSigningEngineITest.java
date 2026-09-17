package com.otilm.core.integration.signing.contentsigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.SigningProfileRequestDto;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPolicyRequestDto;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingOperation;
import com.otilm.api.model.connector.signatures.contentsigning.common.InlineDocumentTransferDto;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.TestCertificateAuthority;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.SigningProfileExternalService;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.service.SigningRecordExternalService;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.v2.ConnectorExternalService;
import com.otilm.core.signing.contentsigning.ContentSigningRequest;
import com.otilm.core.signing.contentsigning.DocumentDigest;
import com.otilm.core.signing.contentsigning.ManagedContentSigningEngine;
import com.otilm.core.signing.contentsigning.SignedContent;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.SigningProfileResolverFactory;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.ContentSigningFormattingMock;
import com.otilm.core.util.mocks.CryptographyProviderConnectorMock;
import com.otilm.core.util.mocks.TimestampingFormattingConnectorMock;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV1ConnectorRequest;
import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV2ConnectorRequest;
import static com.otilm.core.util.builders.ContentSigningWorkflowRequestDtoBuilder.aContentSigningWorkflow;
import static com.otilm.core.util.builders.KeyPairRequestDtoBuilder.aKeyPairRequest;
import static com.otilm.core.util.builders.SearchRequestDtoBuilder.aSearchRequest;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequest;
import static com.otilm.core.util.builders.SigningRecordPolicyRequestDtoBuilder.aSigningRecordPolicyRequest;
import static com.otilm.core.util.builders.TimestampingWorkflowRequestDtoBuilder.aTimestampingWorkflow;
import static com.otilm.core.util.builders.TokenInstanceRequestDtoBuilder.aTokenInstanceRequest;
import static com.otilm.core.util.builders.TokenProfileRequestDtoBuilder.aTokenProfileRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * End-to-end test of a managed content-signing run over a real Spring context and Postgres.
 */
class ContentSigningEngineITest extends BaseSpringBootTest {

    private static final String DEFAULT_POLICY_ID = "1.2.3";

    @Autowired
    private ManagedContentSigningEngine engine;

    @Autowired
    private SigningProfileExternalService signingProfileService;

    @Autowired
    private SigningProfileInternalService signingProfileInternalService;

    @Autowired
    private SigningProfileResolverFactory resolverFactory;

    @Autowired
    private SigningRecordExternalService signingRecordService;

    @Autowired
    private SigningRecordRepository signingRecordRepository;

    @Autowired
    private ConnectorExternalService connectorService;

    @Autowired
    private TokenInstanceExternalService tokenInstanceService;

    @Autowired
    private TokenProfileExternalService tokenProfileService;

    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;

    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    @Autowired
    private TestCertificateAuthority testCertificateAuthority;

    private CryptographyProviderConnectorMock cryptographyProviderMock;
    private TimestampingFormattingConnectorMock timestampingFormattingMock;
    private ContentSigningFormattingMock contentSigningFormattingMock;
    private ConnectorDetailDto timestampingFormattingConnector;
    private ConnectorDetailDto contentSigningFormattingConnector;
    private Certificate signingCertificate;
    private Certificate timestampingCertificate;
    private TokenInstanceDetailDto tokenInstance;
    private TokenProfileDetailDto tokenProfile;
    private TestCertificateAuthority.TrustedCa trustedCa;

    private record PostQuantumKey(SignatureAlgorithm signatureAlgorithm, KeyAlgorithm keyAlgorithm,
            AlgorithmParameterSpec keyParameterSpec, DigestAlgorithm expectedDigest) {
    }

    private static final List<PostQuantumKey> POST_QUANTUM_KEYS = List
            .of(new PostQuantumKey(SignatureAlgorithm.ML_DSA_65, KeyAlgorithm.MLDSA, MLDSAParameterSpec.ml_dsa_65,
                    DigestAlgorithm.SHA_512),
                    new PostQuantumKey(SignatureAlgorithm.SLH_DSA_SHA2_128F, KeyAlgorithm.SLHDSA,
                            SLHDSAParameterSpec.slh_dsa_sha2_128f, DigestAlgorithm.SHA_256));

    private final Map<SignatureAlgorithm, Certificate> postQuantumSigningCertificates = new EnumMap<>(
            SignatureAlgorithm.class);

    @BeforeEach
    void registerConnectorsAndSigningMaterial() throws Exception {
        cryptographyProviderMock = connectorMockFactory.startCryptographyProvider();
        timestampingFormattingMock = connectorMockFactory.startTimestampingFormatting();
        contentSigningFormattingMock = connectorMockFactory
                .startContentSigningFormatting()
                .advertiseTimestampedRung()
                .stubPerOperationFormattingAttributes()
                .stubBaselineAndTimestampOperations();

        ConnectorDetailDto cryptographyProviderConnector = connectorService
                .createConnector(aV1ConnectorRequest()
                        .withName("soft-cryptography-provider")
                        .withUrl(cryptographyProviderMock.getUrl())
                        .build());
        timestampingFormattingConnector = connectorService
                .createConnector(aV2ConnectorRequest()
                        .withName("timestamping-formatting")
                        .withUrl(timestampingFormattingMock.getUrl())
                        .build());
        contentSigningFormattingConnector = connectorService
                .createConnector(aV2ConnectorRequest()
                        .withName("content-signing-formatting")
                        .withUrl(contentSigningFormattingMock.getUrl())
                        .build());

        cryptographyProviderMock.stubTokenInstanceCreation(UUID.randomUUID());
        tokenInstance = tokenInstanceService
                .createTokenInstance(aTokenInstanceRequest()
                        .withName("soft-token")
                        .withConnector(cryptographyProviderConnector.getUuid())
                        .build());

        cryptographyProviderMock.stubTokenProfileCreation();
        tokenProfile = tokenProfileService
                .createTokenProfile(SecuredParentUUID.fromString(tokenInstance.getUuid()),
                        aTokenProfileRequest().withName("soft-token-profile").build());

        KeyPair keyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        cryptographyProviderMock
                .stubKeyPairCreation(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        cryptographicKeyService
                .createKey(UUID.fromString(tokenInstance.getUuid()),
                        SecuredParentUUID.fromString(tokenProfile.getUuid()), KeyRequestType.KEY_PAIR,
                        aKeyPairRequest().withName("soft-key-pair").build());

        trustedCa = testCertificateAuthority.createTrustedCa("CN=Test Root CA");
        signingCertificate = trustedCa.issueSigningCertificate(keyPair, "CN=Test Signing");
        timestampingCertificate = trustedCa.issueTimestampingCertificate(keyPair, "CN=Test TSA");

        cryptographyProviderMock.stubSignData("connector-signature".getBytes(StandardCharsets.UTF_8));
        timestampingFormattingMock.stubFormattingAttributes().stubFormatDtbs().stubFormatResponse();
    }

    @AfterEach
    void stopConnectorMocks() {
        if (cryptographyProviderMock != null) {
            cryptographyProviderMock.stop();
        }
        if (timestampingFormattingMock != null) {
            timestampingFormattingMock.stop();
        }
        if (contentSigningFormattingMock != null) {
            contentSigningFormattingMock.stop();
        }
    }

    @ParameterizedTest
    @EnumSource(SignatureFamily.class)
    void signsADocumentToTimestampedLevelAndTracesToItsTimestampRecord(SignatureFamily family) throws Exception {
        // given: a profile of this family whose ceiling is TIMESTAMPED, pointing at an ILM-managed TSA profile
        SigningProfileDto tsaProfile = createTimestampingProfile("timestamped-run-tsa");
        SigningProfileDto contentProfile = createContentSigningProfile(profileName("timestamped-run", family), family,
                SignatureLevel.TIMESTAMPED, UUID.fromString(tsaProfile.getUuid()));
        byte[] document = "a document to sign".getBytes(StandardCharsets.UTF_8);

        // when
        SignedContent signed = engine
                .sign(signingRequest(SignatureLevel.TIMESTAMPED, document), modelOf(contentProfile),
                        resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API);

        // then: the document came back timestamped, with a serial that names a real timestamp record
        assertThat(signed.level()).isEqualTo(SignatureLevel.TIMESTAMPED);
        assertThat(documentText(signed)).isEqualTo("timestamped-document");
        assertThat(signed.timestampSerials()).hasSize(1);
        String serialHex = signed.timestampSerials().getFirst().toString(16);
        assertThat(recordsFor(tsaProfile.getName()))
                .anySatisfy(signingRecord -> assertThat(signingRecord.getName()).contains(serialHex));

        // and: the join key survives whatever the record-policy toggles are set to
        assertThat(recordEntitiesFor(contentProfile))
                .singleElement()
                .satisfies(signingRecord -> assertThat(signingRecord.getTimestampTokenSerialNumbers())
                        .containsExactly(serialHex));
        assertThat(recordEntitiesFor(tsaProfile))
                .anySatisfy(signingRecord -> assertThat(signingRecord.getTimestampTokenSerialNumbers())
                        .containsExactly(serialHex));
    }

    @ParameterizedTest
    @EnumSource(SignatureFamily.class)
    void signsADocumentToSignedLevelAndLeavesARecord(SignatureFamily family) throws Exception {
        // given: a profile of this family whose ceiling is SIGNED, which names no timestamp source
        SigningProfileDto contentProfile = createContentSigningProfile(profileName("signed-run", family), family,
                SignatureLevel.SIGNED, null);
        byte[] document = "a baseline document".getBytes(StandardCharsets.UTF_8);

        // when
        SignedContent signed = engine
                .sign(signingRequest(SignatureLevel.SIGNED, document), modelOf(contentProfile),
                        resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API);

        // then: the run stopped at SIGNED, embedded no timestamp, and still left its record
        assertThat(signed.level()).isEqualTo(SignatureLevel.SIGNED);
        assertThat(documentText(signed)).isEqualTo("signed-document");
        assertThat(signed.timestampSerials()).isEmpty();
        assertThat(recordsFor(contentProfile.getName())).hasSize(1);
    }

    /** The unit test mocks the algorithm; here a real key and a real cryptographic provider resolve it. */
    @Test
    void tellsTheConnectorTheResolvedSignersAlgorithmOnBothHalvesOfThePair() throws Exception {
        // given
        SigningProfileDto contentProfile = createContentSigningProfile("algorithm-pades", SignatureFamily.PADES,
                SignatureLevel.SIGNED, null);
        byte[] document = "a document signed with a resolved algorithm".getBytes(StandardCharsets.UTF_8);

        // when
        engine
                .sign(signingRequest(SignatureLevel.SIGNED, document), modelOf(contentProfile),
                        resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API);

        // then
        List<String> computed = contentSigningFormattingMock
                .signatureAlgorithmsReceivedBy(ContentSigningFormattingOperation.COMPUTE_DTBS);
        List<String> embedded = contentSigningFormattingMock
                .signatureAlgorithmsReceivedBy(ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE);
        assertThat(computed).containsExactly(SignatureAlgorithm.SHA256_WITH_RSA.getCode());
        assertThat(embedded).isEqualTo(computed);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("postQuantumKeys")
    void tellsTheConnectorThePostQuantumParameterSetOfTheResolvedSigner(PostQuantumKey postQuantumKey)
            throws Exception {
        // given: a profile over a key of this parameter set, authorized under the digest the row pins
        SigningProfileDto contentProfile = createPostQuantumContentSigningProfile(postQuantumKey);
        byte[] document = "a document signed with a post-quantum key".getBytes(StandardCharsets.UTF_8);

        // when
        engine
                .sign(signingRequest(SignatureLevel.SIGNED, document, postQuantumKey.expectedDigest()),
                        modelOf(contentProfile), resolvedContentSigningProfile(contentProfile),
                        SigningProtocol.CSC_API);

        // then
        List<String> computed = contentSigningFormattingMock
                .signatureAlgorithmsReceivedBy(ContentSigningFormattingOperation.COMPUTE_DTBS);
        List<String> embedded = contentSigningFormattingMock
                .signatureAlgorithmsReceivedBy(ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE);
        assertThat(computed).containsExactly(postQuantumKey.signatureAlgorithm().getCode());
        assertThat(embedded).isEqualTo(computed);
    }

    static Stream<Named<PostQuantumKey>> postQuantumKeys() {
        return POST_QUANTUM_KEYS.stream().map(key -> Named.of(key.signatureAlgorithm().getCode(), key));
    }

    @Test
    void refusesToSignWhenTheConnectorEchoesADigestOfAnotherDocument() throws Exception {
        // given: the connector commits to content other than the document that was authorized
        SigningProfileDto contentProfile = createContentSigningProfile("foreign-echo-pades", SignatureFamily.PADES,
                SignatureLevel.SIGNED, null);
        contentSigningFormattingMock.stubComputeDtbsEchoingForeignDigest();
        byte[] document = "the authorized document".getBytes(StandardCharsets.UTF_8);

        // when
        SigningEngineException failure = catchThrowableOfType(SigningEngineException.class,
                () -> engine
                        .sign(signingRequest(SignatureLevel.SIGNED, document), modelOf(contentProfile),
                                resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API));

        // then: the key was never released, so nothing was signed and nothing was recorded
        assertThat(failure.failure()).isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
        cryptographyProviderMock.verifyNoDataWasSigned();
        assertThat(recordsFor(contentProfile.getName())).isEmpty();
    }

    @Test
    void refusesALevelAboveTheProfileCeiling() throws Exception {
        // given: a profile whose ceiling is SIGNED
        SigningProfileDto contentProfile = createContentSigningProfile("ceiling-pades", SignatureFamily.PADES,
                SignatureLevel.SIGNED, null);
        byte[] document = "a document asked to be timestamped".getBytes(StandardCharsets.UTF_8);

        // when
        SigningEngineException failure = catchThrowableOfType(SigningEngineException.class,
                () -> engine
                        .sign(signingRequest(SignatureLevel.TIMESTAMPED, document), modelOf(contentProfile),
                                resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API));

        // then: the ceiling is checked before anything is asked of the connector
        assertThat(failure.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
        assertThat(failure).hasMessageContaining("exceeds the maximum this Signing Profile permits");
        cryptographyProviderMock.verifyNoDataWasSigned();
        assertThat(recordsFor(contentProfile.getName())).isEmpty();
    }

    @Test
    void refusesAProfileSaveWhoseConnectorDoesNotReachTheRequestedCeiling() throws Exception {
        // given: a connector advertising content signing but no rung above SIGNED
        SigningProfileDto tsaProfile = createTimestampingProfile("unreachable-ceiling-tsa");
        ContentSigningFormattingMock baselineOnlyMock = connectorMockFactory
                .startContentSigningFormatting()
                .stubPerOperationFormattingAttributes();
        try {
            ConnectorDetailDto baselineOnlyConnector = connectorService
                    .createConnector(aV2ConnectorRequest()
                            .withName("content-signing-formatting-baseline-only")
                            .withUrl(baselineOnlyMock.getUrl())
                            .build());

            SigningProfileRequestDto request = aSigningProfileRequest()
                    .withName("unreachable-ceiling-pades")
                    .withStaticKeyManagedSigning(signingCertificate.getUuid())
                    .withContentSigning(aContentSigningWorkflow()
                            .withSignatureFormattingConnector(UUID.fromString(baselineOnlyConnector.getUuid()))
                            .withFamily(SignatureFamily.PADES)
                            .withMaxLevel(SignatureLevel.TIMESTAMPED)
                            .withInternalTimestampSource(UUID.fromString(tsaProfile.getUuid()))
                            .build())
                    .withRecordPolicy(recordingEverything())
                    .build();

            // when / then: a TIMESTAMPED ceiling is refused at save, not at signing time
            assertThatThrownBy(() -> signingProfileService.createSigningProfile(request))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not reach level TIMESTAMPED");
        } finally {
            baselineOnlyMock.stop();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String documentText(SignedContent signed) {
        return new String(signed.signedDocument(), StandardCharsets.UTF_8);
    }

    private static ContentSigningRequest signingRequest(SignatureLevel targetLevel, byte[] document) throws Exception {
        return signingRequest(targetLevel, document, DigestAlgorithm.SHA_256);
    }

    private static ContentSigningRequest signingRequest(SignatureLevel targetLevel, byte[] document,
            DigestAlgorithm authorizedDigest) throws Exception {
        return new ContentSigningRequest(targetLevel, new InlineDocumentTransferDto(document), new DocumentDigest(
                authorizedDigest, MessageDigest.getInstance(authorizedDigest.getCode()).digest(document)));
    }

    private SigningProfileModel<?, ?> modelOf(SigningProfileDto profile) throws NotFoundException {
        return signingProfileInternalService.getSigningProfileModel(profile.getName());
    }

    private ResolvedManagedContentSigningProfile resolvedContentSigningProfile(SigningProfileDto profile)
            throws SigningEngineException, NotFoundException {
        return (ResolvedManagedContentSigningProfile) resolverFactory.resolve(modelOf(profile));
    }

    private SigningProfileDto createTimestampingProfile(String name) throws Exception {
        SigningProfileDto profile = signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName(name)
                        .withStaticKeyManagedSigning(timestampingCertificate.getUuid())
                        .withTimestamping(aTimestampingWorkflow()
                                .withSignatureFormattingConnector(
                                        UUID.fromString(timestampingFormattingConnector.getUuid()))
                                .withDefaultPolicyId(DEFAULT_POLICY_ID)
                                .withValidateTokenSignature(false)
                                .withQualifiedTimestamp(false)
                                .withAllowedDigestAlgorithms(List.of())
                                .withAllowedPolicyIds(List.of())
                                .build())
                        .withRecordPolicy(recordingEverything())
                        .build());
        signingProfileService.enableSigningProfile(SecuredUUID.fromString(profile.getUuid()));
        return profile;
    }

    private SigningProfileDto createContentSigningProfile(String name, SignatureFamily family, SignatureLevel maxLevel,
            UUID timestampSourceProfileUuid) throws Exception {
        var workflow = aContentSigningWorkflow()
                .withSignatureFormattingConnector(UUID.fromString(contentSigningFormattingConnector.getUuid()))
                .withFamily(family)
                .withMaxLevel(maxLevel);
        if (timestampSourceProfileUuid != null) {
            workflow.withInternalTimestampSource(timestampSourceProfileUuid);
        }
        SigningProfileDto profile = signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName(name)
                        .withStaticKeyManagedSigning(signingCertificate.getUuid())
                        .withContentSigning(workflow.build())
                        .withRecordPolicy(recordingEverything())
                        .build());
        signingProfileService.enableSigningProfile(SecuredUUID.fromString(profile.getUuid()));
        return profile;
    }

    private SigningProfileDto createPostQuantumContentSigningProfile(PostQuantumKey postQuantumKey) throws Exception {
        SignatureAlgorithm signatureAlgorithm = postQuantumKey.signatureAlgorithm();
        SigningProfileDto profile = signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName("pqc-signed-run-" + signatureAlgorithm.getCode().toLowerCase())
                        .withStaticKeyManagedSigning(postQuantumSigningCertificateFor(postQuantumKey).getUuid(),
                                List.of())
                        .withContentSigning(aContentSigningWorkflow()
                                .withSignatureFormattingConnector(
                                        UUID.fromString(contentSigningFormattingConnector.getUuid()))
                                .withFamily(SignatureFamily.PADES)
                                .withMaxLevel(SignatureLevel.SIGNED)
                                .build())
                        .withRecordPolicy(recordingEverything())
                        .build());
        signingProfileService.enableSigningProfile(SecuredUUID.fromString(profile.getUuid()));
        return profile;
    }

    private Certificate postQuantumSigningCertificateFor(PostQuantumKey postQuantumKey) throws Exception {
        SignatureAlgorithm signatureAlgorithm = postQuantumKey.signatureAlgorithm();
        Certificate existing = postQuantumSigningCertificates.get(signatureAlgorithm);
        if (existing != null) {
            return existing;
        }

        KeyPair postQuantumKeyPair = CertificateGeneratorHelper
                .generateKeyPair(postQuantumKey.keyAlgorithm(), postQuantumKey.keyParameterSpec());
        cryptographyProviderMock
                .stubKeyPairCreation(Base64.getEncoder().encodeToString(postQuantumKeyPair.getPublic().getEncoded()),
                        postQuantumKey.keyAlgorithm(), UUID.randomUUID());
        cryptographicKeyService
                .createKey(UUID.fromString(tokenInstance.getUuid()),
                        SecuredParentUUID.fromString(tokenProfile.getUuid()), KeyRequestType.KEY_PAIR,
                        aKeyPairRequest()
                                .withName("soft-key-pair-" + signatureAlgorithm.getCode().toLowerCase())
                                .build());

        Certificate certificate = trustedCa
                .issueSigningCertificate(postQuantumKeyPair, "CN=Test Signing " + signatureAlgorithm.getCode());
        postQuantumSigningCertificates.put(signatureAlgorithm, certificate);
        return certificate;
    }

    private static String profileName(String prefix, SignatureFamily family) {
        return prefix + "-" + family.getCode();
    }

    private static SigningRecordPolicyRequestDto recordingEverything() {
        return aSigningRecordPolicyRequest()
                .withRecordingEnabled(true)
                .withRecordRequestMetadata(true)
                .withRecordSignedDocument(true)
                .withPersistenceMode(SigningRecordPersistenceMode.IMMEDIATE)
                .build();
    }

    private List<SigningRecord> recordEntitiesFor(SigningProfileDto signingProfile) {
        UUID profileUuid = UUID.fromString(signingProfile.getUuid());
        return signingRecordRepository
                .findAll()
                .stream()
                .filter(signingRecord -> profileUuid.equals(signingRecord.getSigningProfileUuid()))
                .toList();
    }

    private List<SigningRecordListDto> recordsFor(String signingProfileName) {
        return signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems()
                .stream()
                .filter(signingRecord -> signingProfileName.equals(signingRecord.getSigningProfile().getName()))
                .toList();
    }
}
