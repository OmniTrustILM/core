package com.otilm.core.integration.api.tsp;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.core.api.tsp.TspSigningProfileControllerImpl;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.SigningAlgorithmSpecs;
import com.otilm.core.helpers.TestCertificateAuthority;
import com.otilm.core.helpers.TsaSigningMaterial;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.SigningProfileExternalService;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.TspProfileExternalService;
import com.otilm.core.service.v2.ConnectorExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderConnectorMock;
import com.otilm.core.util.mocks.TimestampingFormattingConnectorMock;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.util.UUID;
import java.util.stream.Stream;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV1ConnectorRequest;
import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV2ConnectorRequest;
import static com.otilm.core.util.builders.RawTspRequestBuilder.aRawTspRequest;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequest;
import static com.otilm.core.util.builders.TimestampingWorkflowRequestDtoBuilder.aTimestampingWorkflow;
import static com.otilm.core.util.builders.TokenInstanceRequestDtoBuilder.aTokenInstanceRequest;
import static com.otilm.core.util.builders.TokenProfileRequestDtoBuilder.aTokenProfileRequest;
import static com.otilm.core.util.builders.TspProfileRequestDtoBuilder.aTspProfileRequest;

/**
 * End-to-end integration test for the RFC 3161 timestamp path that resolves by <em>signing profile</em> name, via
 * {@link TspSigningProfileControllerImpl#timestamp}.
 *
 * <p>
 * The shared downstream of profile resolution — request validation, the managed timestamp engine, token assembly, and
 * the real cryptographic signature verify — is exhaustively covered (per-algorithm matrix, policy override, imprint
 * algorithms, certReq handling, nonce echo, signature-mismatch rejection) by {@link TspControllerITest}. This test
 * therefore proves only what is specific to the signing-profile entry point: that a request resolves end-to-end through
 * {@code processTspRequestForSigningProfile} to a real granted token, and the branch unique to this path — a signing
 * profile without the TSP protocol activated must be rejected.
 *
 * <p>
 * Infrastructure setup (connectors, token instance/profile, keys, TSA certificates, signing profiles) is built through
 * the real service layer; the cryptography-provider mock signs each request's DTBS with a real per-algorithm private
 * key, and the timestamping-formatting mock assembles a genuine {@code TimeStampToken} from that live signature — so
 * the {@code withSignatureValidation} variant performs a real verify.
 */
public class TspSigningProfileControllerITest extends BaseSpringBootTest {

    private static final String BASE_URL = "http://localhost";
    private static final String TSP_IMPRINT_INPUT = "Hello, Timestamp!";
    private static final String DEFAULT_POLICY_ID = "1.2.3.4.5";
    private static final boolean REQUEST_SIGNER_CERTIFICATE = true;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Autowired
    private TspSigningProfileControllerImpl tspSigningProfileController;
    @Autowired
    private SigningProfileExternalService signingProfileService;
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
    private ConnectorMockFactory connectorMockFactory;
    @Autowired
    private TestCertificateAuthority testCertificateAuthority;

    private CryptographyProviderConnectorMock cryptographyProviderMock;
    private TimestampingFormattingConnectorMock timestampingFormattingMock;
    private ConnectorDetailDto formattingConnector;
    private TsaSigningMaterial tsaSigningMaterial;

    @BeforeEach
    public void setUp() throws Exception {
        // Assign each mock field immediately after its server starts — before stubbing — so a stub step
        // that throws still leaves the started server reachable for tearDown() to stop (avoiding a port leak
        // and a masking NPE on a null field).
        cryptographyProviderMock = connectorMockFactory.startCryptographyProvider();
        cryptographyProviderMock
                .stubTokenInstanceCreation(UUID.randomUUID())
                .stubTokenProfileCreation()
                .stubRealSigning();
        timestampingFormattingMock = connectorMockFactory.startTimestampingFormatting();
        timestampingFormattingMock.stubFormattingAttributes().stubFormatDtbs().stubFormatResponse();

        ConnectorDetailDto cryptographyProviderConnector = connectorService
                .createConnector(aV1ConnectorRequest()
                        .withName("tsp-sp-cryptography-provider")
                        .withUrl(cryptographyProviderMock.getUrl())
                        .build());
        formattingConnector = connectorService
                .createConnector(aV2ConnectorRequest()
                        .withName("tsp-sp-timestamping-formatting")
                        .withUrl(timestampingFormattingMock.getUrl())
                        .build());

        TokenInstanceDetailDto tokenInstance = tokenInstanceService
                .createTokenInstance(aTokenInstanceRequest()
                        .withName("tsp-sp-token-instance")
                        .withConnector(cryptographyProviderConnector.getUuid())
                        .build());
        TokenProfileDetailDto tokenProfile = tokenProfileService
                .createTokenProfile(SecuredParentUUID.fromString(tokenInstance.getUuid()),
                        aTokenProfileRequest().withName("tsp-sp-token-profile").build());

        tsaSigningMaterial = new TsaSigningMaterial(cryptographyProviderMock, cryptographicKeyService, tokenInstance,
                tokenProfile, testCertificateAuthority.createTrustedCa("CN=TSP SP Test Root CA"), "tsp-sp-key-",
                "CN=Test SP TSA ");
    }

    @AfterEach
    public void tearDown() {
        if (cryptographyProviderMock != null) {
            cryptographyProviderMock.stop();
        }
        if (timestampingFormattingMock != null) {
            timestampingFormattingMock.stop();
        }
    }

    /**
     * Parameterized happy path without token signature validation: for each supported signing algorithm, resolving by
     * signing-profile name returns PKI status GRANTED with a SHA-256 imprint algorithm.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("allSigningAlgorithms")
    public void withoutSignatureValidation(SignatureAlgorithm signatureAlgorithm) throws Exception {
        // given
        boolean validateTokenSignature = false;
        String signingProfileName = createEnabledTspSigningProfile(signatureAlgorithm, validateTokenSignature);
        byte[] requestWithSha256Imprint = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .build();

        // when
        ResponseEntity<byte[]> response = tspSigningProfileController
                .timestamp(signingProfileName, requestWithSha256Imprint);

        // then
        assertGrantedSha256Response(response);
    }

    /**
     * Parameterized happy path with token signature validation enabled: the engine cryptographically verifies the
     * assembled token's signature against the TSA certificate before granting — a real verify, since the formatting
     * mock embeds the live signature.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("allSigningAlgorithms")
    public void withSignatureValidation(SignatureAlgorithm signatureAlgorithm) throws Exception {
        // given
        boolean validateTokenSignature = true;
        String signingProfileName = createEnabledTspSigningProfile(signatureAlgorithm, validateTokenSignature);
        byte[] requestWithSha256Imprint = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .build();

        // when
        ResponseEntity<byte[]> response = tspSigningProfileController
                .timestamp(signingProfileName, requestWithSha256Imprint);

        // then
        assertGrantedSha256Response(response);
    }

    static Stream<SignatureAlgorithm> allSigningAlgorithms() {
        return SigningAlgorithmSpecs.timestampingAlgorithms();
    }

    // ── Edge cases specific to the signing-profile entry point ──────────────────

    /**
     * Branch unique to the signing-profile path: a signing profile that exists and is enabled but was never activated
     * for a TSP profile ({@code tspProfileUuid == null}) must be rejected as BAD_REQUEST, not granted. The TSP-profile
     * entry point cannot reach this state.
     */
    @Test
    public void rejectsBadRequest_whenSigningProfileHasTspProtocolDisabled() throws Exception {
        // given: an enabled signing profile that was NOT activated for any TSP profile
        boolean validateTokenSignature = false;
        String signingProfileName = createEnabledSigningProfileWithoutTspActivation(SignatureAlgorithm.SHA256_WITH_RSA,
                validateTokenSignature);
        byte[] requestWithSha256Imprint = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .build();

        // when
        ResponseEntity<byte[]> response = tspSigningProfileController
                .timestamp(signingProfileName, requestWithSha256Imprint);

        // then
        TimeStampResponse tsResponse = parseTspResponse(response);
        assertBadRequestRejection(tsResponse,
                "Signing profile '%s' does not have the TSP protocol enabled.".formatted(signingProfileName),
                "A signing profile without the TSP protocol enabled must be rejected");
    }

    /**
     * An unknown signing-profile name resolves to a real {@code NotFoundException} in the service layer; the controller
     * renders it as the generic BAD_REQUEST rejection (enumeration defense — no leak of existence).
     */
    @Test
    public void rejectsBadRequest_whenSigningProfileNameUnknown() throws Exception {
        // given
        String unknownSigningProfileName = "no-such-signing-profile";
        byte[] requestWithSha256Imprint = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .build();

        // when
        ResponseEntity<byte[]> response = tspSigningProfileController
                .timestamp(unknownSigningProfileName, requestWithSha256Imprint);

        // then
        TimeStampResponse tsResponse = parseTspResponse(response);
        assertBadRequestRejection(tsResponse, "Resource not found. See logs for details.",
                "An unknown signing profile must be rejected");
    }

    /**
     * Regression guard for the signature-validation path being a real verify and not a no-op, asserted through the
     * signing-profile entry point: with {@code validateTokenSignature} enabled, a token whose signer key does not match
     * the TSA certificate must be rejected. Mirrors
     * {@code TspControllerITest#withSignatureValidation_rejectsToken_whenSignerKeyDoesNotMatchCertificate} so this file
     * no longer depends on the sibling to prove the verify discriminates.
     */
    @Test
    public void withSignatureValidation_rejectsToken_whenSignerKeyDoesNotMatchCertificate() throws Exception {
        // given: the signer mock signs with a freshly generated key unrelated to the TSA certificate
        boolean validateTokenSignature = true;
        String signingProfileName = createEnabledTspSigningProfile(SignatureAlgorithm.SHA256_WITH_RSA,
                validateTokenSignature);
        KeyPair keyNotMatchingCertificate = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        cryptographyProviderMock
                .registerSigningKey(tsaSigningMaterial.privateKeyReferenceUuid(SignatureAlgorithm.SHA256_WITH_RSA),
                        keyNotMatchingCertificate.getPrivate(), SignatureAlgorithm.SHA256_WITH_RSA);
        byte[] requestWithSha256Imprint = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .build();

        // when
        ResponseEntity<byte[]> response = tspSigningProfileController
                .timestamp(signingProfileName, requestWithSha256Imprint);

        // then
        TimeStampResponse tsResponse = parseTspResponse(response);
        Assertions
                .assertEquals(PKIStatus.REJECTION, tsResponse.getStatus(),
                        "Token signed by a mismatched key must be rejected, but got status: " + tsResponse.getStatus());
        Assertions.assertEquals("Timestamp signature validation failed", tsResponse.getStatusString());
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    /**
     * Creates and enables a signing profile (static-key-managed scheme over the algorithm's TSA certificate,
     * timestamping workflow), then creates+enables a TSP profile and activates the signing profile for it so the TSP
     * protocol is reachable by signing-profile name. Returns the signing profile name.
     */
    private String createEnabledTspSigningProfile(SignatureAlgorithm signatureAlgorithm, boolean validateTokenSignature)
            throws Exception {
        String label = signatureAlgorithm.getCode();
        String signingProfileName = "tsp-sp-signing-profile-" + label;
        UUID signingProfileUuid = createEnabledSigningProfile(signingProfileName, signatureAlgorithm,
                validateTokenSignature);

        String tspProfileName = "tsp-sp-profile-" + label;
        UUID tspProfileUuid = UUID
                .fromString(tspProfileService
                        .createTspProfile(aTspProfileRequest()
                                .withName(tspProfileName)
                                .withDefaultSigningProfile(signingProfileUuid)
                                .build(), BASE_URL)
                        .getUuid());
        tspProfileService.enableTspProfile(SecuredUUID.fromUUID(tspProfileUuid));
        signingProfileService
                .activateTsp(SecuredUUID.fromUUID(signingProfileUuid), SecuredUUID.fromUUID(tspProfileUuid), BASE_URL);
        return signingProfileName;
    }

    /**
     * Creates and enables a signing profile but does NOT activate it for any TSP profile, leaving
     * {@code tspProfileUuid == null}. Returns the signing profile name.
     */
    private String createEnabledSigningProfileWithoutTspActivation(SignatureAlgorithm signatureAlgorithm,
            boolean validateTokenSignature) throws Exception {
        String signingProfileName = "tsp-sp-inactive-signing-profile-" + signatureAlgorithm.getCode();
        createEnabledSigningProfile(signingProfileName, signatureAlgorithm, validateTokenSignature);
        return signingProfileName;
    }

    private UUID createEnabledSigningProfile(String signingProfileName, SignatureAlgorithm signatureAlgorithm,
            boolean validateTokenSignature) throws Exception {
        UUID signingProfileUuid = UUID
                .fromString(signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName(signingProfileName)
                                .withStaticKeyManagedSigning(
                                        tsaSigningMaterial.issueTimestampingCertificate(signatureAlgorithm).getUuid(),
                                        SigningAlgorithmSpecs.specFor(signatureAlgorithm).signingAttributes())
                                .withTimestamping(aTimestampingWorkflow()
                                        .withSignatureFormattingConnector(
                                                UUID.fromString(formattingConnector.getUuid()))
                                        .withDefaultPolicyId(DEFAULT_POLICY_ID)
                                        .withQualifiedTimestamp(false)
                                        .withValidateTokenSignature(validateTokenSignature)
                                        .build())
                                .build())
                        .getUuid());
        signingProfileService.enableSigningProfile(SecuredUUID.fromUUID(signingProfileUuid));
        return signingProfileUuid;
    }

    private static byte[] sha256(String input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Asserts HTTP 200, PKIStatus GRANTED, token present, and SHA-256 imprint algorithm.
     */
    private static void assertGrantedSha256Response(ResponseEntity<byte[]> response) throws Exception {
        TimeStampResponse tsResponse = parseTspResponse(response);
        Assertions
                .assertEquals(PKIStatus.GRANTED, tsResponse.getStatus(), "Expected PKIStatus GRANTED (0) but got: "
                        + tsResponse.getStatus() + " - " + tsResponse.getStatusString());
        Assertions.assertNotNull(tsResponse.getTimeStampToken(), "TimeStampToken must be present");
        String imprintAlg = tsResponse.getTimeStampToken().getTimeStampInfo().getMessageImprintAlgOID().getId();
        Assertions.assertEquals(TSPAlgorithms.SHA256.getId(), imprintAlg, "Message imprint algorithm must be SHA-256");
    }

    /**
     * Asserts an RFC 3161 rejection that carries the BAD_REQUEST failure-info bit (not merely
     * {@link PKIStatus#REJECTION}) plus the exact {@code statusString}. In RFC 3161 BAD_REQUEST is a
     * {@code PKIFailureInfo} bit, encoded separately from the {@code PKIStatus} value, so verifying the decoded bit is
     * what actually proves the BAD_REQUEST classification.
     */
    private static void assertBadRequestRejection(TimeStampResponse tsResponse, String expectedStatusString,
            String rejectionMessage) {
        Assertions
                .assertEquals(PKIStatus.REJECTION, tsResponse.getStatus(),
                        rejectionMessage + ", but got status: " + tsResponse.getStatus());
        Assertions.assertNotNull(tsResponse.getFailInfo(), "Rejection must carry a failure-info field");
        Assertions
                .assertEquals(PKIFailureInfo.badRequest, tsResponse.getFailInfo().intValue(),
                        "Rejection must carry the BAD_REQUEST failure-info bit");
        Assertions.assertEquals(expectedStatusString, tsResponse.getStatusString());
    }

    /**
     * Asserts HTTP 200 with a non-empty body and parses it as an RFC 3161 {@link TimeStampResponse}.
     */
    private static TimeStampResponse parseTspResponse(ResponseEntity<byte[]> response) throws Exception {
        Assertions.assertEquals(200, response.getStatusCode().value());
        byte[] responseBytes = response.getBody();
        Assertions.assertNotNull(responseBytes);
        Assertions.assertTrue(responseBytes.length > 0, "Response body must not be empty");
        return new TimeStampResponse(responseBytes);
    }
}
