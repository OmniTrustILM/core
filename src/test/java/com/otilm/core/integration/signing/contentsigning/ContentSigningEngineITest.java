package com.otilm.core.integration.signing.contentsigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.SigningProfileRequestDto;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPolicyRequestDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingOperation;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SigningSettingsDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.config.ConnectorApiClientProperties;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.signing.SigningRecord;
import com.otilm.core.dao.repository.signing.SigningRecordRepository;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.SigningAlgorithmSpecs;
import com.otilm.core.helpers.TestCertificateAuthority;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.SigningProfileExternalService;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.service.SigningRecordExternalService;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.v2.ConnectorExternalService;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.signing.contentsigning.AugmentationRequest;
import com.otilm.core.signing.contentsigning.ContentSigningItem;
import com.otilm.core.signing.contentsigning.ContentSigningRequest;
import com.otilm.core.signing.contentsigning.ManagedContentSigningEngine;
import com.otilm.core.signing.contentsigning.SignedContent;
import com.otilm.core.signing.contentsigning.SignedItem;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.SigningProfileResolverFactory;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SignatureFamilyFixtures;
import com.otilm.core.util.builders.SigningProfileRequestDtoBuilder;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.ContentSigningFormattingMock;
import com.otilm.core.util.mocks.CryptographyProviderConnectorMock;
import com.otilm.core.util.mocks.TimestampingFormattingConnectorMock;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV1ConnectorRequest;
import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV2ConnectorRequest;
import static com.otilm.core.util.builders.ContentSigningWorkflowRequestDtoBuilder.aContentSigningWorkflow;
import static com.otilm.core.util.builders.KeyPairRequestDtoBuilder.aKeyPairRequest;
import static com.otilm.core.util.builders.SearchRequestDtoBuilder.aSearchRequest;
import static com.otilm.core.util.builders.SignatureFamilyDeclarationDtoBuilder.aFamilyDeclaration;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequest;
import static com.otilm.core.util.builders.SigningRecordPolicyRequestDtoBuilder.aSigningRecordPolicyRequest;
import static com.otilm.core.util.builders.TimestampingWorkflowRequestDtoBuilder.aTimestampingWorkflow;
import static com.otilm.core.util.builders.TokenInstanceRequestDtoBuilder.aTokenInstanceRequest;
import static com.otilm.core.util.builders.TokenProfileRequestDtoBuilder.aTokenProfileRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
    private ConnectorApiClientProperties connectorApiClientProperties;

    @Autowired
    private TestCertificateAuthority testCertificateAuthority;

    @Autowired
    private SettingExternalService settingService;

    @Autowired
    private PlatformTransactionManager transactionManager;

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
    private KeyPair signingKeyPair;
    private UUID signingKeyReference;

    private record PostQuantumKey(SignatureAlgorithm signatureAlgorithm, KeyAlgorithm keyAlgorithm,
            DigestAlgorithm expectedDigest) {

        AlgorithmParameterSpec keyParameterSpec() {
            return SigningAlgorithmSpecs.parameterSpecFor(signatureAlgorithm, keyAlgorithm);
        }
    }

    private static final List<PostQuantumKey> POST_QUANTUM_KEYS = List
            .of(new PostQuantumKey(SignatureAlgorithm.ML_DSA_65, KeyAlgorithm.MLDSA, DigestAlgorithm.SHA_512),
                    new PostQuantumKey(SignatureAlgorithm.SLH_DSA_SHA2_128F, KeyAlgorithm.SLHDSA,
                            DigestAlgorithm.SHA_256));

    @BeforeEach
    void registerConnectorsAndSigningMaterial() throws Exception {
        cryptographyProviderMock = connectorMockFactory.startCryptographyProvider();
        timestampingFormattingMock = connectorMockFactory.startTimestampingFormatting();
        contentSigningFormattingMock = connectorMockFactory
                .startContentSigningFormatting()
                .stubAdesFamiliesUpTo(SignatureLevel.TIMESTAMPED)
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

        signingKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        signingKeyReference = UUID.randomUUID();
        cryptographyProviderMock
                .stubKeyPairCreation(Base64.getEncoder().encodeToString(signingKeyPair.getPublic().getEncoded()),
                        KeyAlgorithm.RSA, signingKeyReference);
        cryptographicKeyService
                .createKey(UUID.fromString(tokenInstance.getUuid()),
                        SecuredParentUUID.fromString(tokenProfile.getUuid()), KeyRequestType.KEY_PAIR,
                        aKeyPairRequest().withName("soft-key-pair").build());

        trustedCa = testCertificateAuthority.createTrustedCa("CN=Test Root CA");
        signingCertificate = trustedCa.issueSigningCertificate(signingKeyPair, "CN=Test Signing");
        timestampingCertificate = trustedCa.issueTimestampingCertificate(signingKeyPair, "CN=Test TSA");

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

    // ── SignatureLevels ───────────────────────────────────────────────────────

    @Nested
    class SignatureLevels {

        @ParameterizedTest
        @ValueSource(strings = {"pades", "xades", "cades", "jades"})
        void signsToTimestampedLevel_whenTheProfileSignsAtTimestamped(String family) throws Exception {
            // given: a profile of this family that signs at TIMESTAMPED, pointing at an ILM-managed TSA profile
            SigningProfileDto tsaProfile = createTimestampingProfile("timestamped-run-tsa");
            SigningProfileDto contentProfile = createContentSigningProfile(profileName("timestamped-run", family),
                    family, SignatureLevel.TIMESTAMPED, UUID.fromString(tsaProfile.getUuid()));
            byte[] document = "a document to sign".getBytes(StandardCharsets.UTF_8);

            // when
            SignedContent signed = engine
                    .sign(signingRequest(document), modelOf(contentProfile),
                            resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API)
                    .getFirst()
                    .content();

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
        @ValueSource(strings = {"pades", "xades", "cades", "jades"})
        void signsToSignedLevel_whenTheProfileSignsAtSigned(String family) throws Exception {
            // given: a profile of this family that signs at SIGNED, which names no timestamp source
            SigningProfileDto contentProfile = createContentSigningProfile(profileName("signed-run", family), family,
                    SignatureLevel.SIGNED, null);
            byte[] document = "a baseline document".getBytes(StandardCharsets.UTF_8);

            // when
            SignedContent signed = engine
                    .sign(signingRequest(document), modelOf(contentProfile),
                            resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API)
                    .getFirst()
                    .content();

            // then: the run stopped at SIGNED, embedded no timestamp, and still left its record
            assertThat(signed.level()).isEqualTo(SignatureLevel.SIGNED);
            assertThat(documentText(signed)).isEqualTo("signed-document");
            assertThat(signed.timestampSerials()).isEmpty();
            assertThat(recordsFor(contentProfile.getName())).hasSize(1);
        }

        @Test
        void refusesTheProfileSave_whenTheConnectorDoesNotReachTheRequestedLevel() throws Exception {
            // given: a connector advertising content signing but no rung above SIGNED
            SigningProfileDto tsaProfile = createTimestampingProfile("unreachable-level-tsa");
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
                        .withName("unreachable-level-pades")
                        .withStaticKeyManagedSigning(signingCertificate.getUuid())
                        .withContentSigning(aContentSigningWorkflow()
                                .withSignatureFormattingConnector(UUID.fromString(baselineOnlyConnector.getUuid()))
                                .withFamily(SignatureFamilyFixtures.PADES)
                                .withLevel(SignatureLevel.TIMESTAMPED)
                                .withInternalTimestampSource(UUID.fromString(tsaProfile.getUuid()))
                                .build())
                        .withRecordPolicy(recordingEverything())
                        .build();

                // when
                ThrowingCallable createSigningProfile = () -> signingProfileService.createSigningProfile(request);

                // then: a TIMESTAMPED level is refused at save, not at signing time
                assertThatThrownBy(createSigningProfile)
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("does not reach level TIMESTAMPED");
            } finally {
                baselineOnlyMock.stop();
            }
        }
    }

    // ── SignerAlgorithm ───────────────────────────────────────────────────────

    @Nested
    class SignerAlgorithm {

        /** The unit test mocks the algorithm; here a real key and a real cryptographic provider resolve it. */
        @Test
        void tellsBothHalvesOfThePairTheResolvedSignersAlgorithm_whenSigningContent() throws Exception {
            // given
            SigningProfileDto contentProfile = createContentSigningProfile("algorithm-pades",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            byte[] document = "a document signed with a resolved algorithm".getBytes(StandardCharsets.UTF_8);

            // when
            engine
                    .sign(signingRequest(document), modelOf(contentProfile),
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
        void tellsTheConnectorThePostQuantumParameterSet_whenTheSignerHoldsAPostQuantumKey(
                PostQuantumKey postQuantumKey) throws Exception {
            // given: a profile over a key of this parameter set, authorized under the digest the row pins
            SigningProfileDto contentProfile = createPostQuantumContentSigningProfile(postQuantumKey);
            byte[] document = "a document signed with a post-quantum key".getBytes(StandardCharsets.UTF_8);

            // when
            engine
                    .sign(signingRequest(document, postQuantumKey.expectedDigest()), modelOf(contentProfile),
                            resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API);

            // then
            List<String> computed = contentSigningFormattingMock
                    .signatureAlgorithmsReceivedBy(ContentSigningFormattingOperation.COMPUTE_DTBS);
            List<String> embedded = contentSigningFormattingMock
                    .signatureAlgorithmsReceivedBy(ContentSigningFormattingOperation.EMBED_SIGNATURE_VALUE);
            assertThat(computed).containsExactly(postQuantumKey.signatureAlgorithm().getCode());
            assertThat(embedded).isEqualTo(computed);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Named<PostQuantumKey>> postQuantumKeys() {
            return POST_QUANTUM_KEYS.stream().map(key -> Named.of(key.signatureAlgorithm().getCode(), key));
        }
    }

    // ── DigestBinding ─────────────────────────────────────────────────────────

    @Nested
    class DigestBinding {

        @Test
        void refusesToSign_whenTheConnectorEchoesADigestOfAnotherDocument() throws Exception {
            // given: the connector commits to content other than the document that was authorized
            SigningProfileDto contentProfile = createContentSigningProfile("foreign-echo-pades",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            contentSigningFormattingMock.stubComputeDtbsEchoingForeignDigest();
            byte[] document = "the authorized document".getBytes(StandardCharsets.UTF_8);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(signingRequest(document), modelOf(contentProfile),
                            resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API);

            // then: the key was never released, so nothing was signed and nothing was recorded
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            failure -> assertThat(failure.failure()).isEqualTo(SigningEngineFailure.BINDING_VIOLATION));
            cryptographyProviderMock.verifyNoDataWasSigned();
            assertThat(recordsFor(contentProfile.getName())).isEmpty();
        }
    }

    // ── ConnectorRefusals ─────────────────────────────────────────────────────

    @Nested
    class ConnectorRefusals {

        private static final byte[] DOCUMENT = "the document to sign".getBytes(StandardCharsets.UTF_8);

        @Test
        void reportsMalformedInput_whenTheFormatterRefusesTheDocumentAsMalformed() throws Exception {
            // given
            SigningProfileDto contentProfile = createContentSigningProfile("malformed-document-pades",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            contentSigningFormattingMock.stubComputeDtbsRefusal(ErrorCode.DOCUMENT_MALFORMED);

            // when
            ThrowingCallable sign = () -> signDocument(contentProfile);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, failure -> {
                assertThat(failure.failure()).isEqualTo(SigningEngineFailure.MALFORMED_INPUT);
                assertThat(failure.clientMessage()).isEqualTo(ErrorCode.DOCUMENT_MALFORMED.getTitle());
            });
            cryptographyProviderMock.verifyNoDataWasSigned();
        }

        @Test
        void reportsMisconfigured_whenTheSignerAnswersALegacy422() throws Exception {
            // given
            SigningProfileDto contentProfile = createContentSigningProfile("legacy-refusal-pades",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            cryptographyProviderMock.stubSignDataLegacyRefusal("Signature attribute is not supported");

            // when
            ThrowingCallable sign = () -> signDocument(contentProfile);

            // then
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            failure -> assertThat(failure.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED));
        }

        @Test
        void reportsInvalidInput_whenTheFormattedDocumentExceedsTheReadLimit() throws Exception {
            // given
            SigningProfileDto contentProfile = createContentSigningProfile("oversized-document-pades",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            contentSigningFormattingMock.stubComputeDtbsExceeding(connectorApiClientProperties.maxInMemorySize());

            // when
            ThrowingCallable sign = () -> signDocument(contentProfile);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, failure -> {
                assertThat(failure.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            });
            cryptographyProviderMock.verifyNoDataWasSigned();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void signDocument(SigningProfileDto contentProfile) throws Exception {
            engine
                    .sign(signingRequest(DOCUMENT), modelOf(contentProfile),
                            resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API);
        }
    }

    // ── FormattingAttributes ──────────────────────────────────────────────────

    @Nested
    class FormattingAttributes {

        private static final UUID LOCATION_ATTRIBUTE_UUID = UUID.fromString("0000cccc-1111-2222-3333-444444444444");
        private static final String LOCATION_ATTRIBUTE_NAME = "data_formattingLocation";

        @Test
        void rejectsAsMisconfigured_whenTheFormatterRequiresAnAttributeTheProfileLacks() throws Exception {
            // given
            SigningProfileDto contentProfile = createContentSigningProfile("lacks-required-attribute",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            contentSigningFormattingMock
                    .stubPerOperationFormattingAttributeDefinition(LOCATION_ATTRIBUTE_UUID, LOCATION_ATTRIBUTE_NAME,
                            true);

            // when
            ThrowingCallable resolve = () -> resolvedContentSigningProfile(contentProfile);

            // then
            assertMisconfigured(resolve);
        }

        @Test
        void rejectsAsMisconfigured_whenTheProfileCarriesAnAttributeTheFormatterDoesNotDefine() throws Exception {
            // given
            contentSigningFormattingMock
                    .stubPerOperationFormattingAttributeDefinition(LOCATION_ATTRIBUTE_UUID, LOCATION_ATTRIBUTE_NAME);
            SigningProfileDto contentProfile = createEnabledSigningProfile(
                    aContentSigningProfile("carries-undefined-attribute", SignatureFamilyFixtures.PADES,
                            SignatureLevel.SIGNED, null, List.of(locationAttribute("a location the formatter dropped")))
                            .withStaticKeyManagedSigning(signingCertificate.getUuid()));
            contentSigningFormattingMock.stubPerOperationFormattingAttributes();

            // when
            ThrowingCallable resolve = () -> resolvedContentSigningProfile(contentProfile);

            // then
            assertMisconfigured(resolve);
        }

        @Test
        void sendsTheProfileValueOfARequestAttribute_whenComputingTheDtbs() throws Exception {
            // given
            var operatorsLocation = "the operator's location";
            contentSigningFormattingMock
                    .stubComputeDtbsRequestAttributeDefinition(LOCATION_ATTRIBUTE_UUID, LOCATION_ATTRIBUTE_NAME);
            SigningProfileDto contentProfile = createEnabledSigningProfile(
                    aContentSigningProfile("request-attribute-profile-value", SignatureFamilyFixtures.PADES,
                            SignatureLevel.SIGNED, null, List.of(locationAttribute(operatorsLocation)))
                            .withStaticKeyManagedSigning(signingCertificate.getUuid()));
            byte[] document = "a document signed at the operator's location".getBytes(StandardCharsets.UTF_8);

            // when
            engine
                    .sign(signingRequest(document), modelOf(contentProfile),
                            resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API);

            // then
            assertThat(contentSigningFormattingMock
                    .formattingAttributesReceivedBy(ContentSigningFormattingOperation.COMPUTE_DTBS))
                    .singleElement()
                    .satisfies(attributes -> {
                        assertThat(attributes.findValuesAsText("name")).containsExactly(LOCATION_ATTRIBUTE_NAME);
                        assertThat(attributes.findValuesAsText("data")).containsExactly(operatorsLocation);
                    });
        }

        @Test
        void asksTheFormatterForEachReachableOperationOnce_whenTheProfileIsResolvedTwice() throws Exception {
            // given — a SIGNED profile reaches the two baseline operations
            SigningProfileDto contentProfile = createContentSigningProfile("asks-once-per-operation",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            int baselineOperations = 2;
            int listingsBeforeResolving = contentSigningFormattingMock.attributeDefinitionListings();

            // when
            resolvedContentSigningProfile(contentProfile);
            resolvedContentSigningProfile(contentProfile);

            // then
            assertThat(contentSigningFormattingMock.attributeDefinitionListings())
                    .isEqualTo(listingsBeforeResolving + baselineOperations);
        }

        @Test
        void asksTheFormatterAgain_whenTheConnectorIsReconnected() throws Exception {
            // given — the first resolution has cached the formatter's definitions
            SigningProfileDto contentProfile = createContentSigningProfile("asks-after-reconnect",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            int baselineOperations = 2;
            resolvedContentSigningProfile(contentProfile);
            connectorService.reconnect(SecuredUUID.fromString(contentSigningFormattingConnector.getUuid()));
            int listingsAfterReconnect = contentSigningFormattingMock.attributeDefinitionListings();

            // when
            resolvedContentSigningProfile(contentProfile);

            // then
            assertThat(contentSigningFormattingMock.attributeDefinitionListings())
                    .isEqualTo(listingsAfterReconnect + baselineOperations);
        }

        @Test
        void resolvesTheProfile_whenItIsUpdatedWithAnAttributeTheFormatterStartedPublishing() throws Exception {
            // given — a resolution has cached the formatter's definitions from before it published the attribute
            SigningProfileDto contentProfile = createContentSigningProfile("updated-with-new-attribute",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            resolvedContentSigningProfile(contentProfile);
            contentSigningFormattingMock
                    .stubPerOperationFormattingAttributeDefinition(LOCATION_ATTRIBUTE_UUID, LOCATION_ATTRIBUTE_NAME);
            updateFormattingAttributes(contentProfile, List.of(locationAttribute("a location just published")));

            // when
            ResolvedManagedContentSigningProfile resolved = resolvedContentSigningProfile(contentProfile);

            // then
            assertThat(resolved.signatureFormattingConnectorAttributes())
                    .extracting(RequestAttribute::getName)
                    .containsExactly(LOCATION_ATTRIBUTE_NAME);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void updateFormattingAttributes(SigningProfileDto contentProfile,
                List<RequestAttribute> formattingAttributes) throws Exception {
            signingProfileService
                    .updateSigningProfile(SecuredUUID.fromString(contentProfile.getUuid()),
                            aContentSigningProfile(contentProfile.getName(), SignatureFamilyFixtures.PADES,
                                    SignatureLevel.SIGNED, null, formattingAttributes)
                                    .withStaticKeyManagedSigning(signingCertificate.getUuid())
                                    .withRecordPolicy(recordingEverything())
                                    .build());
        }

        private static RequestAttribute locationAttribute(String value) {
            RequestAttributeV2 attribute = new RequestAttributeV2();
            attribute.setUuid(LOCATION_ATTRIBUTE_UUID);
            attribute.setName(LOCATION_ATTRIBUTE_NAME);
            attribute.setContentType(AttributeContentType.STRING);
            attribute.setContent(List.of(new StringAttributeContentV2(value, value)));
            return attribute;
        }

        private static void assertMisconfigured(ThrowingCallable resolve) {
            assertThatThrownBy(resolve)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            refusal -> assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED));
        }
    }

    // ── Batches ───────────────────────────────────────────────────────────────

    @Nested
    class Batches {

        private PlatformSettingsDto originalPlatformSettings;

        @BeforeEach
        void registerTheSigningKeyAndRememberThePlatformSettings() {
            cryptographyProviderMock
                    .stubRealSigning()
                    .registerSigningKey(signingKeyReference, signingKeyPair.getPrivate(),
                            SignatureAlgorithm.SHA256_WITH_RSA);
            originalPlatformSettings = SettingsCache.getSettings(SettingsSection.PLATFORM);
        }

        /** The settings cache outlives the test. A lowered cap left in it would refuse the next test's batch. */
        @AfterEach
        void restoreThePlatformSettings() {
            new SettingsCache()
                    .cacheSettings(SettingsSection.PLATFORM,
                            originalPlatformSettings != null ? originalPlatformSettings : new PlatformSettingsDto());
        }

        @Test
        void signsEveryDocumentWithOneSignRequest() throws Exception {
            // given
            SigningProfileDto contentProfile = createContentSigningProfile("batch-pades", SignatureFamilyFixtures.PADES,
                    SignatureLevel.SIGNED, null);
            ContentSigningRequest batch = batchOf("first", "second", "third");

            // when
            List<SignedItem> signed = engine
                    .sign(batch, modelOf(contentProfile), resolvedContentSigningProfile(contentProfile),
                            SigningProtocol.CSC_API);

            // then
            assertThat(signed).extracting(SignedItem::identifier).containsExactly("first", "second", "third");
            cryptographyProviderMock.verifySignRequests(1);
        }

        @Test
        void returnsEachDocumentsRecordReference_whenTheProfileRecords() throws Exception {
            // given
            SigningProfileDto contentProfile = createContentSigningProfile("recorded-batch-pades",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            ContentSigningRequest batch = batchOf("first", "second", "third");

            // when
            List<SignedItem> signed = engine
                    .sign(batch, modelOf(contentProfile), resolvedContentSigningProfile(contentProfile),
                            SigningProtocol.CSC_API);

            // then
            List<UUID> recordUuids = recordEntitiesFor(contentProfile).stream().map(SigningRecord::getUuid).toList();
            assertThat(signed)
                    .extracting(SignedItem::signingRecordUuid)
                    .containsExactlyInAnyOrderElementsOf(recordUuids);
        }

        @Test
        void namesTheDocument_whenItsBindingFails() throws Exception {
            // given
            SigningProfileDto contentProfile = createContentSigningProfile("foreign-echo-batch-pades",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            var foreignEchoed = "second";
            contentSigningFormattingMock.stubComputeDtbsEchoingForeignDigestFor(documentNamed(foreignEchoed));
            ContentSigningRequest batch = batchOf("first", foreignEchoed, "third");

            // when
            ThrowingCallable sign = () -> engine
                    .sign(batch, modelOf(contentProfile), resolvedContentSigningProfile(contentProfile),
                            SigningProtocol.CSC_API);

            // then: the run stopped before the key and the record store
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, e -> {
                assertThat(e.failure()).isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
                assertThat(e.itemIdentifier()).isEqualTo(foreignEchoed);
            });
            cryptographyProviderMock.verifyNoDataWasSigned();
            assertThat(recordsFor(contentProfile.getName())).isEmpty();
        }

        @Test
        void refusesTheBatch_whenItCarriesMoreDocumentsThanTheCap() throws Exception {
            // given
            SigningProfileDto contentProfile = createContentSigningProfile("capped-batch-pades",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            var cap = 2;
            settingService.updatePlatformSettings(signingCapUpdate(cap));
            ContentSigningRequest batch = batchOf("first", "second", "third");

            // when
            ThrowingCallable sign = () -> engine
                    .sign(batch, modelOf(contentProfile), resolvedContentSigningProfile(contentProfile),
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, e -> {
                assertThat(e.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
                assertThat(e.clientMessage()).contains("at most " + cap + " items");
            });
            cryptographyProviderMock.verifyNoDataWasSigned();
            assertThat(recordsFor(contentProfile.getName())).isEmpty();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static PlatformSettingsUpdateDto signingCapUpdate(int maxItemsPerRequest) {
            SigningSettingsDto signing = new SigningSettingsDto();
            signing.setMaxItemsPerRequest(maxItemsPerRequest);
            PlatformSettingsUpdateDto update = new PlatformSettingsUpdateDto();
            update.setSigning(signing);
            return update;
        }
    }

    // ── CallersTransaction ────────────────────────────────────────────────────

    @Nested
    class CallersTransaction {

        @Test
        void keepsTheSigningRecord_whenTheCallersTransactionRollsBack() throws Exception {
            // given
            SigningProfileDto contentProfile = createContentSigningProfile("caller-rollback-signed-pades",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            ContentSigningRequest request = signingRequest("a document to sign".getBytes(StandardCharsets.UTF_8));
            SigningProfileModel<?, ?> signingProfile = modelOf(contentProfile);
            ResolvedManagedContentSigningProfile resolvedProfile = resolvedContentSigningProfile(contentProfile);

            // when
            List<SignedItem> signed = inACallersTransactionThatRollsBack(
                    () -> engine.sign(request, signingProfile, resolvedProfile, SigningProtocol.CSC_API));

            // then
            assertThat(recordEntitiesFor(contentProfile))
                    .extracting(SigningRecord::getUuid)
                    .containsExactly(signed.getFirst().signingRecordUuid());
        }

        @Test
        void keepsTheAugmentationRecord_whenTheCallersTransactionRollsBack() throws Exception {
            // given
            SigningProfileDto tsaProfile = createTimestampingProfile("caller-rollback-tsa");
            SigningProfileDto contentProfile = createContentSigningProfile("caller-rollback-augmented-pades",
                    SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, UUID.fromString(tsaProfile.getUuid()));
            var augmentation = new AugmentationRequest("a document signed elsewhere".getBytes(StandardCharsets.UTF_8),
                    null);
            SigningProfileModel<?, ?> signingProfile = modelOf(contentProfile);
            ResolvedManagedContentSigningProfile resolvedProfile = resolvedContentSigningProfile(contentProfile);

            // when
            inACallersTransactionThatRollsBack(
                    () -> engine.augment(augmentation, signingProfile, resolvedProfile, SigningProtocol.CSC_API));

            // then
            assertThat(recordEntitiesFor(contentProfile)).hasSize(1);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private <T> T inACallersTransactionThatRollsBack(Callable<T> work) {
            return new TransactionTemplate(transactionManager).execute(callersTransaction -> {
                callersTransaction.setRollbackOnly();
                try {
                    return work.call();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
        }
    }

    // ── ConnectorDeclaration ──────────────────────────────────────────────────

    @Nested
    class ConnectorDeclaration {

        private static final String CONNECTOR_ONLY_FAMILY = "mrtd";

        @Test
        void signsAFamilyThePlatformDoesNotKnow_whenTheConnectorDeclaresIt() throws Exception {
            // given
            contentSigningFormattingMock
                    .stubDeclaration(aFamilyDeclaration(CONNECTOR_ONLY_FAMILY)
                            .withHighestLevel(SignatureLevel.SIGNED)
                            .buildDeclaration());
            reconnectContentSigningFormatting();
            SigningProfileDto contentProfile = createContentSigningProfile("connector-only-family",
                    CONNECTOR_ONLY_FAMILY, SignatureLevel.SIGNED, null);
            byte[] document = "a travel document".getBytes(StandardCharsets.UTF_8);

            // when
            SignedContent signed = engine
                    .sign(signingRequest(document), modelOf(contentProfile),
                            resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API)
                    .getFirst()
                    .content();

            // then
            assertThat(signed.level()).isEqualTo(SignatureLevel.SIGNED);
            assertThat(recordsFor(contentProfile.getName())).hasSize(1);
        }

        @Test
        void refusesTheRun_whenAReconnectNarrowedTheFamilysAlgorithms() throws Exception {
            // given — the profile was saved while PAdES accepted every algorithm
            SigningProfileDto contentProfile = createContentSigningProfile("narrowed-algorithms",
                    SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null);
            var onlyAcceptedAlgorithm = SignatureAlgorithm.SHA512_WITH_RSA;
            contentSigningFormattingMock
                    .stubDeclaration(aFamilyDeclaration(SignatureFamilyFixtures.PADES)
                            .withHighestLevel(SignatureLevel.SIGNED)
                            .withSignatureAlgorithms(Set.of(onlyAcceptedAlgorithm))
                            .buildDeclaration());
            reconnectContentSigningFormatting();
            byte[] document = "a document".getBytes(StandardCharsets.UTF_8);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(signingRequest(document), modelOf(contentProfile),
                            resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            refusal -> assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED));
            cryptographyProviderMock.verifyNoDataWasSigned();
        }

        @Test
        void refusesTheRun_whenAReconnectLoweredTheFamilysLevels() throws Exception {
            // given — the profile was saved while PAdES reached TIMESTAMPED
            SigningProfileDto tsaProfile = createTimestampingProfile("lowered-levels-tsa");
            SigningProfileDto contentProfile = createContentSigningProfile("lowered-levels",
                    SignatureFamilyFixtures.PADES, SignatureLevel.TIMESTAMPED, UUID.fromString(tsaProfile.getUuid()));
            contentSigningFormattingMock.stubAdesFamiliesUpTo(SignatureLevel.SIGNED);
            reconnectContentSigningFormatting();
            byte[] document = "a document".getBytes(StandardCharsets.UTF_8);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(signingRequest(document), modelOf(contentProfile),
                            resolvedContentSigningProfile(contentProfile), SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            refusal -> assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED));
            cryptographyProviderMock.verifyNoDataWasSigned();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void reconnectContentSigningFormatting() throws Exception {
            connectorService.reconnect(SecuredUUID.fromString(contentSigningFormattingConnector.getUuid()));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String documentText(SignedContent signed) {
        return new String(signed.signedDocument(), StandardCharsets.UTF_8);
    }

    private static ContentSigningRequest signingRequest(byte[] document) throws Exception {
        return signingRequest(document, DigestAlgorithm.SHA_256);
    }

    private static ContentSigningRequest signingRequest(byte[] document, DigestAlgorithm authorizedDigest)
            throws Exception {
        ContentSigningItem item = new ContentSigningItem("document-1", document,
                MessageDigest.getInstance(authorizedDigest.getCode()).digest(document));
        return new ContentSigningRequest(DocumentTransferMode.INLINE, authorizedDigest, List.of(item));
    }

    private static ContentSigningRequest batchOf(String... identifiers) throws Exception {
        List<ContentSigningItem> items = new ArrayList<>();
        for (String identifier : identifiers) {
            byte[] document = documentNamed(identifier);
            byte[] authorizedDigest = MessageDigest.getInstance("SHA-256").digest(document);
            items.add(new ContentSigningItem(identifier, document, authorizedDigest));
        }
        return new ContentSigningRequest(DocumentTransferMode.INLINE, DigestAlgorithm.SHA_256, items);
    }

    private static byte[] documentNamed(String identifier) {
        return ("document " + identifier).getBytes(StandardCharsets.UTF_8);
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

    private SigningProfileDto createContentSigningProfile(String name, String family, SignatureLevel level,
            UUID timestampSourceProfileUuid) throws Exception {
        return createEnabledSigningProfile(aContentSigningProfile(name, family, level, timestampSourceProfileUuid)
                .withStaticKeyManagedSigning(signingCertificate.getUuid()));
    }

    private SigningProfileDto createPostQuantumContentSigningProfile(PostQuantumKey postQuantumKey) throws Exception {
        SignatureAlgorithm signatureAlgorithm = postQuantumKey.signatureAlgorithm();
        // Attributes are given explicitly and empty: the one-argument scheme defaults them to an RSA
        // signature, which is validated against the key algorithm and rejected for a post-quantum key.
        return createEnabledSigningProfile(
                aContentSigningProfile("pqc-signed-run-" + signatureAlgorithm.getCode().toLowerCase(),
                        SignatureFamilyFixtures.PADES, SignatureLevel.SIGNED, null)
                        .withStaticKeyManagedSigning(postQuantumSigningCertificateFor(postQuantumKey).getUuid(),
                                List.of()));
    }

    /** The content-signing half of a profile request; the caller adds the signing scheme its key needs. */
    private SigningProfileRequestDtoBuilder aContentSigningProfile(String name, String family, SignatureLevel level,
            UUID timestampSourceProfileUuid) {
        return aContentSigningProfile(name, family, level, timestampSourceProfileUuid, List.of());
    }

    private SigningProfileRequestDtoBuilder aContentSigningProfile(String name, String family, SignatureLevel level,
            UUID timestampSourceProfileUuid, List<RequestAttribute> formattingAttributes) {
        var workflow = aContentSigningWorkflow()
                .withSignatureFormattingConnector(UUID.fromString(contentSigningFormattingConnector.getUuid()))
                .withFamily(family)
                .withLevel(level)
                .withSignatureFormattingConnectorAttributes(formattingAttributes);
        if (timestampSourceProfileUuid != null) {
            workflow.withInternalTimestampSource(timestampSourceProfileUuid);
        }
        return aSigningProfileRequest().withName(name).withContentSigning(workflow.build());
    }

    private SigningProfileDto createEnabledSigningProfile(SigningProfileRequestDtoBuilder request) throws Exception {
        SigningProfileDto profile = signingProfileService
                .createSigningProfile(request.withRecordPolicy(recordingEverything()).build());
        signingProfileService.enableSigningProfile(SecuredUUID.fromString(profile.getUuid()));
        return profile;
    }

    private Certificate postQuantumSigningCertificateFor(PostQuantumKey postQuantumKey) throws Exception {
        SignatureAlgorithm signatureAlgorithm = postQuantumKey.signatureAlgorithm();
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

        return trustedCa.issueSigningCertificate(postQuantumKeyPair, "CN=Test Signing " + signatureAlgorithm.getCode());
    }

    private static String profileName(String prefix, String family) {
        return prefix + "-" + family;
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
