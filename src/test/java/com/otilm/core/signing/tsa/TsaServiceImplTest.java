package com.otilm.core.signing.tsa;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.signing.profile.SigningProfileDto;
import com.otilm.api.model.client.signing.profile.record.SigningRecordPersistenceMode;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordDto;
import com.otilm.api.model.core.signing.signingrecord.SigningRecordListDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.TestCertificateAuthority;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicKeyService;
import com.otilm.core.service.SigningProfileExternalService;
import com.otilm.core.service.SigningRecordExternalService;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.TspProfileExternalService;
import com.otilm.core.service.v2.ConnectorExternalService;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.messages.TspResponse;
import com.otilm.core.signing.tsa.validator.TspRequestValidationException;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderConnectorMock;
import com.otilm.core.util.mocks.TimestampingFormattingConnectorMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static com.otilm.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV1ConnectorRequest;
import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV2ConnectorRequest;
import static com.otilm.core.util.builders.KeyPairRequestDtoBuilder.aKeyPairRequest;
import static com.otilm.core.util.builders.SearchRequestDtoBuilder.aSearchRequest;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequest;
import static com.otilm.core.util.builders.SigningRecordPolicyRequestDtoBuilder.aSigningRecordPolicyRequest;
import static com.otilm.core.util.builders.TimestampingWorkflowRequestDtoBuilder.aTimestampingWorkflow;
import static com.otilm.core.util.builders.TokenInstanceRequestDtoBuilder.aTokenInstanceRequest;
import static com.otilm.core.util.builders.TokenProfileRequestDtoBuilder.aTokenProfileRequest;
import static com.otilm.core.util.builders.TspProfileRequestDtoBuilder.aTspProfileRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * End-to-end test of the TSP timestamp flow over a real Spring context and Postgres: request validation,
 * signing-profile resolution, the {@link ManagedTimestampEngine}, token assembly, and signing-record
 * persistence all run for real. The only mocks are the external connectors — the cryptography provider (signs
 * the DTBS) and the timestamping signature formatting (assembles the RFC 3161 token) — served by WireMock.
 *
 * <p>The formatting returns a pre-built, structurally valid timestamp token; the profiles disable
 * token-signature validation, so the token need not cryptographically verify against the signing certificate.
 */
class TsaServiceImplTest extends BaseSpringBootTest {

    @Autowired
    private TsaService tsaService;

    @Autowired
    private SigningProfileExternalService signingProfileService;

    @Autowired
    private TspProfileExternalService tspProfileService;

    @Autowired
    private SigningRecordExternalService signingRecordService;

    @Autowired
    private ConnectorExternalService connectorService;

    @Autowired
    private TokenInstanceExternalService tokenInstanceService;

    @Autowired
    private TokenProfileExternalService tokenProfileService;

    @Autowired
    private CryptographicKeyService cryptographicKeyService;

    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    @Autowired
    private TestCertificateAuthority testCertificateAuthority;

    private CryptographyProviderConnectorMock cryptographyProviderMock;
    private TimestampingFormattingConnectorMock timestampingFormattingMock;
    private ConnectorDetailDto timestampingFormattingConnector;
    private Certificate signingCertificate;
    private byte[] timestampTokenBytes;

    @BeforeEach
    void setUp() throws Exception {
        cryptographyProviderMock = connectorMockFactory.startCryptographyProvider();
        timestampingFormattingMock = connectorMockFactory.startTimestampingFormatting();

        ConnectorDetailDto cryptographyProviderConnector = connectorService.createConnector(
                aV1ConnectorRequest().withName("soft-cryptography-provider").withUrl(cryptographyProviderMock.getUrl()).build());
        timestampingFormattingConnector = connectorService.createConnector(
                aV2ConnectorRequest().withName("timestamping-formatting").withUrl(timestampingFormattingMock.getUrl()).build());

        cryptographyProviderMock.stubTokenInstanceCreation(UUID.randomUUID());
        TokenInstanceDetailDto tokenInstance = tokenInstanceService.createTokenInstance(
                aTokenInstanceRequest().withName("soft-token").withConnector(cryptographyProviderConnector.getUuid()).build());

        cryptographyProviderMock.stubTokenProfileCreation();
        TokenProfileDetailDto tokenProfile = tokenProfileService.createTokenProfile(
                SecuredParentUUID.fromString(tokenInstance.getUuid()),
                aTokenProfileRequest().withName("soft-token-profile").build());

        KeyPair keyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        cryptographyProviderMock.stubKeyPairCreation(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        cryptographicKeyService.createKey(
                UUID.fromString(tokenInstance.getUuid()),
                SecuredParentUUID.fromString(tokenProfile.getUuid()),
                KeyRequestType.KEY_PAIR,
                aKeyPairRequest().withName("soft-key-pair").build());

        // TSA leaf signed by a trusted root, built from the token-backed key pair so the static-key managed
        // signing scheme resolves to a usable signing certificate + key.
        signingCertificate = testCertificateAuthority.createTrustedCa("CN=Test Root CA")
                .issueTimestampingCertificate(keyPair, "CN=Test TSA");

        // The connector signs the DTBS and assembles the token; the assembled token is a real RFC 3161 token.
        timestampTokenBytes = TimestampTokenTestUtil.createTimestampToken().getEncoded();
        cryptographyProviderMock.stubSignData("connector-signature".getBytes(StandardCharsets.UTF_8));
        timestampingFormattingMock.stubFormattingAttributes().stubTokenAssembly(timestampTokenBytes);
    }

    @AfterEach
    void stopConnectorMocks() {
        if (cryptographyProviderMock != null) {
            cryptographyProviderMock.stop();
        }
        if (timestampingFormattingMock != null) {
            timestampingFormattingMock.stop();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SigningProfileDto createTimestampingSigningProfile(String name) throws Exception {
        return createTimestampingSigningProfile(name, List.of(), List.of());
    }

    /**
     * Creates a timestamping signing profile, then enables it and activates it against a freshly created and
     * enabled TSP profile — the preconditions {@code TsaServiceImpl} now enforces before granting timestamps.
     */
    private SigningProfileDto createTimestampingSigningProfile(String name,
                                                              List<DigestAlgorithm> allowedDigestAlgorithms,
                                                              List<String> allowedPolicyIds) throws Exception {
        SigningProfileDto signingProfile = signingProfileService.createSigningProfile(
                aSigningProfileRequest()
                        .withName(name)
                        .withStaticKeyManagedSigning(signingCertificate.getUuid())
                        .withTimestamping(aTimestampingWorkflow()
                                .withSignatureFormattingConnector(UUID.fromString(timestampingFormattingConnector.getUuid()))
                                .withValidateTokenSignature(false)
                                .withQualifiedTimestamp(false)
                                .withAllowedDigestAlgorithms(allowedDigestAlgorithms)
                                .withAllowedPolicyIds(allowedPolicyIds)
                                .build())
                        .withRecordPolicy(aSigningRecordPolicyRequest()
                                .withRecordingEnabled(true)
                                .withRecordRequestMetadata(true)
                                .withRecordSignedDocument(true)
                                .withPersistenceMode(SigningRecordPersistenceMode.IMMEDIATE)
                                .build())
                        .build());

        SecuredUUID signingProfileUuid = SecuredUUID.fromString(signingProfile.getUuid());
        signingProfileService.enableSigningProfile(signingProfileUuid);

        SecuredUUID tspProfileUuid = SecuredUUID.fromString(tspProfileService.createTspProfile(
                aTspProfileRequest().withName(name + "-tsp").build(), "http://localhost").getUuid());
        tspProfileService.enableTspProfile(tspProfileUuid);
        signingProfileService.activateTsp(signingProfileUuid, tspProfileUuid, "http://localhost");

        return signingProfile;
    }

    // ── processTspRequestForTspProfile ────────────────────────────────────────

    @Nested
    class ProcessTspRequestForTspProfile {

        @Test
        void throwsNotFound_whenTspProfileDoesNotExist() {
            // given — no TSP profile in the database

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForTspProfile("nonexistent", aTspRequest().build()))
                    .isInstanceOf(NotFoundException.class);
        }

        @Test
        void grantsTimestamp_viaDefaultSigningProfile_ofTspProfile() throws Exception {
            // given
            SigningProfileDto signingProfile = createTimestampingSigningProfile("sp-for-tsp");
            SecuredUUID tspProfileUuid = SecuredUUID.fromString(tspProfileService.createTspProfile(aTspProfileRequest()
                    .withName("my-tsp-profile")
                    .withDefaultSigningProfile(UUID.fromString(signingProfile.getUuid()))
                    .build(), "http://localhost").getUuid());
            tspProfileService.enableTspProfile(tspProfileUuid);

            // when
            TspResponse response = tsaService.processTspRequestForTspProfile("my-tsp-profile", aTspRequest().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Granted.class);
        }
    }

    // ── processTspRequestForSigningProfile ────────────────────────────────────

    @Nested
    class ProcessTspRequestForSigningProfile {

        @Test
        void throwsNotFound_whenSigningProfileDoesNotExist() {
            // given — no signing profile in the database

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForSigningProfile("nonexistent", aTspRequest().build()))
                    .isInstanceOf(NotFoundException.class);
        }

        @Test
        void grantsTimestamp_whenRequestValid() throws Exception {
            // given
            SigningProfileDto profile = createTimestampingSigningProfile("unconstrained-sp");

            // when
            TspResponse response = tsaService.processTspRequestForSigningProfile(profile.getName(), aTspRequest().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Granted.class);
            assertThat(((TspResponse.Granted) response).timestampBytes()).isNotEmpty();
        }

        @Test
        void persistsSigningRecord_whenTimestampGranted() throws Exception {
            // given
            SigningProfileDto profile = createTimestampingSigningProfile("recording-sp");

            // when
            TspResponse response = tsaService.processTspRequestForSigningProfile(profile.getName(), aTspRequest().build());

            // then — the granted token is persisted as a signing record carrying the token's bytes and metadata
            assertThat(response).isInstanceOf(TspResponse.Granted.class);
            byte[] grantedBytes = ((TspResponse.Granted) response).timestampBytes();

            List<SigningRecordListDto> records = signingRecordService
                    .listSigningRecords(aSearchRequest().build(), SecurityFilter.create())
                    .getItems();
            assertThat(records).hasSize(1);

            SigningRecordDto signingRecord = signingRecordService
                    .getSigningRecord(SecuredUUID.fromString(records.getFirst().getUuid()));
            assertThat(signingRecord.getSignedDocument()).isEqualTo(grantedBytes);
            assertThat(signingRecord.getName()).startsWith(profile.getName() + " #");
            assertThat(signingRecord.getSigningTime()).isNotNull();
            // jsonb re-renders whitespace, so assert on content rather than byte-exact JSON
            assertThat(signingRecord.getRequestMetadataJson())
                    .contains("\"signingProfileName\"")
                    .contains(profile.getName());
            // The TSP path stores only the self-contained token; signature and dtbs are recoverable from it.
            assertThat(signingRecord.getSignatureValue()).isNull();
            assertThat(signingRecord.getDtbs()).isNull();
        }

        @Test
        void throwsValidationException_whenHashAlgorithmNotAllowed() throws Exception {
            // given — profile only accepts SHA-256; request uses SHA-512
            SigningProfileDto profile = createTimestampingSigningProfile(
                    "sp-sha256-only",
                    List.of(DigestAlgorithm.SHA_256),
                    List.of());
            TspRequest sha512Request = aTspRequest()
                    .hashAlgorithm(DigestAlgorithm.SHA_512)
                    .hashedMessage(new byte[64])
                    .build();

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForSigningProfile(profile.getName(), sha512Request))
                    .isInstanceOf(TspRequestValidationException.class)
                    .satisfies(ex -> assertThat(((TspRequestValidationException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.BAD_ALG));
        }

        @Test
        void throwsValidationException_whenPolicyNotAllowed() throws Exception {
            // given — profile only accepts policy "1.2.3"; request uses "9.9.9"
            SigningProfileDto profile = createTimestampingSigningProfile(
                    "sp-restricted-policy",
                    List.of(),
                    List.of("1.2.3"));
            TspRequest wrongPolicyRequest = aTspRequest()
                    .policy("9.9.9")
                    .build();

            // when / then
            assertThatThrownBy(() -> tsaService.processTspRequestForSigningProfile(profile.getName(), wrongPolicyRequest))
                    .isInstanceOf(TspRequestValidationException.class)
                    .satisfies(ex -> assertThat(((TspRequestValidationException) ex).getFailureInfo())
                            .isEqualTo(TspFailureInfo.UNACCEPTED_POLICY));
        }

        @Test
        void rejectsWithSystemFailure_whenFormattingConnectorFails() throws Exception {
            // given — the signature formatting is unavailable during token assembly
            SigningProfileDto profile = createTimestampingSigningProfile("sp-formatting-down");
            timestampingFormattingMock.stubTokenAssemblyFailure();

            // when
            TspResponse response = tsaService.processTspRequestForSigningProfile(profile.getName(), aTspRequest().build());

            // then
            assertThat(response).isInstanceOf(TspResponse.Rejected.class);
            assertThat(((TspResponse.Rejected) response).failureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
        }
    }
}
