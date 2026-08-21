package com.otilm.core.integration.signing.contentsigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPolicyRequestDto;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.InlineDocumentTransferDto;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.dao.entity.Certificate;
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
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
 * End-to-end test of a managed content-signing run over a real Spring context and Postgres: the profile is saved
 * through the service, resolved exactly as a request would resolve it, and driven through
 * {@link ManagedContentSigningEngine} — including the in-process timestamp the {@code TIMESTAMPED} rung needs and the
 * signing records both profiles leave behind.
 *
 * <p>
 * The only mocks are the external connectors, served by WireMock: the content-signing formatting connector, the
 * cryptography provider that signs, and the timestamping formatting connector that assembles the RFC 3161 token. No
 * formatting connector implementation exists yet, so that half is a mock by necessity — the documents it returns are
 * opaque markers, not real PAdES structures.
 * </p>
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
        TokenInstanceDetailDto tokenInstance = tokenInstanceService
                .createTokenInstance(aTokenInstanceRequest()
                        .withName("soft-token")
                        .withConnector(cryptographyProviderConnector.getUuid())
                        .build());

        cryptographyProviderMock.stubTokenProfileCreation();
        TokenProfileDetailDto tokenProfile = tokenProfileService
                .createTokenProfile(SecuredParentUUID.fromString(tokenInstance.getUuid()),
                        aTokenProfileRequest().withName("soft-token-profile").build());

        KeyPair keyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        cryptographyProviderMock
                .stubKeyPairCreation(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        cryptographicKeyService
                .createKey(UUID.fromString(tokenInstance.getUuid()),
                        SecuredParentUUID.fromString(tokenProfile.getUuid()), KeyRequestType.KEY_PAIR,
                        aKeyPairRequest().withName("soft-key-pair").build());

        // One token-backed leaf serves both profiles: the timestamping rules are the stricter of the two, and content
        // signing defines no certificate-purpose rule of its own.
        signingCertificate = testCertificateAuthority
                .createTrustedCa("CN=Test Root CA")
                .issueTimestampingCertificate(keyPair, "CN=Test TSA");

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

    @Test
    void signsAPadesDocumentToTimestampedLevelAndTracesToItsTimestampRecord() throws Exception {
        // given: a PAdES profile whose ceiling is TIMESTAMPED, pointing at an ILM-managed TSA profile
        SigningProfileDto tsaProfile = createTimestampingProfile("timestamped-run-tsa");
        SigningProfileDto contentProfile = createContentSigningProfile("timestamped-run-pades", SignatureFamily.PADES,
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
                .anySatisfy(record -> assertThat(record.getName()).contains(serialHex));
        assertThat(recordsFor(contentProfile.getName())).isNotEmpty();
    }

    @Test
    void signsAPadesDocumentToSignedLevelAndLeavesARecord() throws Exception {
        // given: a PAdES profile whose ceiling is SIGNED, which names no timestamp source
        SigningProfileDto contentProfile = createContentSigningProfile("signed-run-pades", SignatureFamily.PADES,
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

            // when / then: a TIMESTAMPED ceiling is refused at save, not at signing time
            assertThatThrownBy(() -> signingProfileService
                    .createSigningProfile(aSigningProfileRequest()
                            .withName("unreachable-ceiling-pades")
                            .withStaticKeyManagedSigning(signingCertificate.getUuid())
                            .withContentSigning(aContentSigningWorkflow()
                                    .withSignatureFormattingConnector(UUID.fromString(baselineOnlyConnector.getUuid()))
                                    .withFamily(SignatureFamily.PADES)
                                    .withMaxLevel(SignatureLevel.TIMESTAMPED)
                                    .withInternalTimestampSource(UUID.fromString(tsaProfile.getUuid()))
                                    .build())
                            .withRecordPolicy(recordingEverything())
                            .build()))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("does not reach level TIMESTAMPED");
        } finally {
            baselineOnlyMock.stop();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** The marker each embed operation returns, which names the operation whose output the run actually delivered. */
    private static String documentText(SignedContent signed) {
        return new String(signed.signedDocument(), StandardCharsets.UTF_8);
    }

    private static ContentSigningRequest signingRequest(SignatureLevel targetLevel, byte[] document) throws Exception {
        return new ContentSigningRequest(targetLevel, new InlineDocumentTransferDto(document),
                new DocumentDigest(DigestAlgorithm.SHA_256, MessageDigest.getInstance("SHA-256").digest(document)));
    }

    private SigningProfileModel<?, ?> modelOf(SigningProfileDto profile) throws NotFoundException {
        return signingProfileInternalService.getSigningProfileModel(profile.getName());
    }

    private ResolvedManagedContentSigningProfile resolvedContentSigningProfile(SigningProfileDto profile)
            throws SigningEngineException, NotFoundException {
        return (ResolvedManagedContentSigningProfile) resolverFactory.resolve(modelOf(profile));
    }

    /**
     * Creates the ILM-managed TIMESTAMPING profile a content-signing profile names as its timestamp source. No TSP
     * profile is attached: in-process issuance goes below the TSP protocol layer.
     */
    private SigningProfileDto createTimestampingProfile(String name) throws Exception {
        SigningProfileDto profile = signingProfileService
                .createSigningProfile(aSigningProfileRequest()
                        .withName(name)
                        .withStaticKeyManagedSigning(signingCertificate.getUuid())
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

    private static SigningRecordPolicyRequestDto recordingEverything() {
        return aSigningRecordPolicyRequest()
                .withRecordingEnabled(true)
                .withRecordRequestMetadata(true)
                .withRecordSignedDocument(true)
                .withPersistenceMode(SigningRecordPersistenceMode.IMMEDIATE)
                .build();
    }

    private List<SigningRecordListDto> recordsFor(String signingProfileName) {
        return signingRecordService
                .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                .getItems()
                .stream()
                .filter(record -> signingProfileName.equals(record.getSigningProfile().getName()))
                .toList();
    }
}
