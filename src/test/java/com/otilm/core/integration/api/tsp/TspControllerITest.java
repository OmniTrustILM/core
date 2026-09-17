package com.otilm.core.integration.api.tsp;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.core.api.tsp.TspControllerImpl;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.helpers.TestCertificateAuthority;
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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
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
import static com.otilm.core.util.builders.EcdsaSignatureAttributesBuilder.ecdsaSignatureAttributes;
import static com.otilm.core.util.builders.KeyPairRequestDtoBuilder.aKeyPairRequest;
import static com.otilm.core.util.builders.RawTspRequestBuilder.aRawTspRequest;
import static com.otilm.core.util.builders.RsaSignatureAttributesBuilder.rsaSignatureAttributes;
import static com.otilm.core.util.builders.SigningProfileRequestDtoBuilder.aSigningProfileRequest;
import static com.otilm.core.util.builders.TimestampingWorkflowRequestDtoBuilder.aTimestampingWorkflow;
import static com.otilm.core.util.builders.TokenInstanceRequestDtoBuilder.aTokenInstanceRequest;
import static com.otilm.core.util.builders.TokenProfileRequestDtoBuilder.aTokenProfileRequest;
import static com.otilm.core.util.builders.TspProfileRequestDtoBuilder.aTspProfileRequest;

/**
 * End-to-end integration test for the RFC 3161 Timestamp Protocol implementation.
 *
 * <p>
 * Exercises the full timestamp-token production path via {@link TspControllerImpl#timestamp}: infrastructure is created
 * through the real service layer (connectors, token instance/profile, keys, TSA certificates, signing and TSP
 * profiles), the cryptography-provider mock signs each request's DTBS with a real per-algorithm private key, and the
 * timestamping-formatting mock assembles a genuine {@code TimeStampToken} from that live signature — so the
 * {@code withSignatureValidation} variant performs a real cryptographic verify.
 */
public class TspControllerITest extends BaseSpringBootTest {

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
    private TspControllerImpl tspController;
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

    /**
     * Static description of a single signing algorithm under test: the signature algorithm the platform is expected to
     * resolve and the mock connector signs with, the key algorithm and key-generation parameters the key is created
     * under, and the signing-operation attributes the profile carries (empty for post-quantum algorithms).
     *
     * <p>
     * The signature algorithm is what identifies a row, because one key algorithm covers several post-quantum parameter
     * sets and each of them is a signing configuration in its own right.
     * </p>
     */
    private record AlgorithmSpec(SignatureAlgorithm signatureAlgorithm, KeyAlgorithm keyAlgorithm,
            AlgorithmParameterSpec keyParameterSpec, List<RequestAttribute> signingAttributes) {
    }

    /**
     * The slower SLH-DSA parameter sets are covered in the unit tier; signing with them here would dominate the suite's
     * runtime without exercising a different path.
     */
    private static final List<AlgorithmSpec> ALGORITHM_SPECS = List
            .of(new AlgorithmSpec(SignatureAlgorithm.SHA256_WITH_RSA, KeyAlgorithm.RSA, null,
                    rsaSignatureAttributes().build()),
                    new AlgorithmSpec(SignatureAlgorithm.SHA256_WITH_ECDSA, KeyAlgorithm.ECDSA,
                            new ECGenParameterSpec("secp256r1"), ecdsaSignatureAttributes().build()),
                    new AlgorithmSpec(SignatureAlgorithm.FALCON_1024, KeyAlgorithm.FALCON,
                            FalconParameterSpec.falcon_1024, List.of()),
                    new AlgorithmSpec(SignatureAlgorithm.ML_DSA_44, KeyAlgorithm.MLDSA, MLDSAParameterSpec.ml_dsa_44,
                            List.of()),
                    new AlgorithmSpec(SignatureAlgorithm.ML_DSA_65, KeyAlgorithm.MLDSA, MLDSAParameterSpec.ml_dsa_65,
                            List.of()),
                    new AlgorithmSpec(SignatureAlgorithm.ML_DSA_87, KeyAlgorithm.MLDSA, MLDSAParameterSpec.ml_dsa_87,
                            List.of()),
                    new AlgorithmSpec(SignatureAlgorithm.SLH_DSA_SHA2_128S, KeyAlgorithm.SLHDSA,
                            SLHDSAParameterSpec.slh_dsa_sha2_128s, List.of()),
                    new AlgorithmSpec(SignatureAlgorithm.SLH_DSA_SHA2_128F, KeyAlgorithm.SLHDSA,
                            SLHDSAParameterSpec.slh_dsa_sha2_128f, List.of()));

    private CryptographyProviderConnectorMock cryptographyProviderMock;
    private TimestampingFormattingConnectorMock timestampingFormattingMock;
    private ConnectorDetailDto formattingConnector;
    private TokenInstanceDetailDto tokenInstance;
    private TokenProfileDetailDto tokenProfile;
    private TestCertificateAuthority.TrustedCa trustedCa;

    private final Map<SignatureAlgorithm, Certificate> tsaCertificates = new EnumMap<>(SignatureAlgorithm.class);

    /** Lets a test re-register a different private key for an algorithm's runtime signer. */
    private final Map<SignatureAlgorithm, UUID> privateKeyReferenceUuids = new EnumMap<>(SignatureAlgorithm.class);

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
                        .withName("tsp-cryptography-provider")
                        .withUrl(cryptographyProviderMock.getUrl())
                        .build());
        formattingConnector = connectorService
                .createConnector(aV2ConnectorRequest()
                        .withName("tsp-timestamping-formatting")
                        .withUrl(timestampingFormattingMock.getUrl())
                        .build());

        tokenInstance = tokenInstanceService
                .createTokenInstance(aTokenInstanceRequest()
                        .withName("tsp-token-instance")
                        .withConnector(cryptographyProviderConnector.getUuid())
                        .build());
        tokenProfile = tokenProfileService
                .createTokenProfile(SecuredParentUUID.fromString(tokenInstance.getUuid()),
                        aTokenProfileRequest().withName("tsp-token-profile").build());

        trustedCa = testCertificateAuthority.createTrustedCa("CN=TSP Test Root CA");
    }

    private Certificate tsaCertificateFor(SignatureAlgorithm signatureAlgorithm) throws Exception {
        Certificate existing = tsaCertificates.get(signatureAlgorithm);
        if (existing != null) {
            return existing;
        }

        AlgorithmSpec spec = specFor(signatureAlgorithm);
        KeyPair keyPair = CertificateGeneratorHelper.generateKeyPair(spec.keyAlgorithm(), spec.keyParameterSpec());

        // The connector reports this UUID as the private key's reference; the same UUID keys the
        // real-signer mock, so runtime sign requests reach this algorithm's live private key.
        UUID privateKeyReferenceUuid = UUID.randomUUID();
        privateKeyReferenceUuids.put(signatureAlgorithm, privateKeyReferenceUuid);
        cryptographyProviderMock
                .stubKeyPairCreation(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                        spec.keyAlgorithm(), privateKeyReferenceUuid)
                .registerSigningKey(privateKeyReferenceUuid, keyPair.getPrivate(), signatureAlgorithm);
        cryptographicKeyService
                .createKey(UUID.fromString(tokenInstance.getUuid()),
                        SecuredParentUUID.fromString(tokenProfile.getUuid()), KeyRequestType.KEY_PAIR,
                        aKeyPairRequest().withName("tsp-key-" + signatureAlgorithm.getCode().toLowerCase()).build());

        // Uploading the leaf associates it (by public-key fingerprint) with the token-backed key
        Certificate certificate = trustedCa
                .issueTimestampingCertificate(keyPair, "CN=Test TSA " + signatureAlgorithm.getCode());
        tsaCertificates.put(signatureAlgorithm, certificate);
        return certificate;
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
     * Parameterized end-to-end flow without token signature validation: for each supported signing algorithm, asserts
     * that the controller returns PKI status GRANTED with a SHA-256 imprint algorithm.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("allSigningAlgorithms")
    public void withoutSignatureValidation(SignatureAlgorithm signatureAlgorithm) throws Exception {
        // given
        boolean validateTokenSignature = false;
        String tspProfileName = createEnabledProfiles(signatureAlgorithm, validateTokenSignature);
        byte[] requestWithSha256Imprint = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .build();

        // when
        ResponseEntity<byte[]> response = tspController.timestamp(tspProfileName, requestWithSha256Imprint);

        // then
        assertGrantedSha256Response(response);
    }

    /**
     * Parameterized end-to-end flow with token signature validation enabled: for each supported signing algorithm, the
     * engine cryptographically verifies the assembled token's signature against the TSA certificate before granting — a
     * real verify, since the formatting mock embeds the live signature.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("allSigningAlgorithms")
    public void withSignatureValidation(SignatureAlgorithm signatureAlgorithm) throws Exception {
        // given
        boolean validateTokenSignature = true;
        String tspProfileName = createEnabledProfiles(signatureAlgorithm, validateTokenSignature);
        byte[] requestWithSha256Imprint = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .build();

        // when
        ResponseEntity<byte[]> response = tspController.timestamp(tspProfileName, requestWithSha256Imprint);

        // then
        assertGrantedSha256Response(response);
    }

    static Stream<SignatureAlgorithm> allSigningAlgorithms() {
        return ALGORITHM_SPECS.stream().map(AlgorithmSpec::signatureAlgorithm);
    }

    // ── Edge cases (single algorithm — the per-algorithm matrix is covered above) ─

    /**
     * Regression guard for the signature-validation path being a real verify and not a no-op: when the runtime signer's
     * key does not match the TSA certificate, the engine must reject the response.
     */
    @Test
    public void withSignatureValidation_rejectsToken_whenSignerKeyDoesNotMatchCertificate() throws Exception {
        // given: the signer mock signs with a freshly generated key unrelated to the TSA certificate
        boolean validateTokenSignature = true;
        String tspProfileName = createEnabledProfiles(SignatureAlgorithm.SHA256_WITH_RSA, validateTokenSignature);
        KeyPair keyNotMatchingCertificate = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        cryptographyProviderMock
                .registerSigningKey(privateKeyReferenceUuids.get(SignatureAlgorithm.SHA256_WITH_RSA),
                        keyNotMatchingCertificate.getPrivate(), SignatureAlgorithm.SHA256_WITH_RSA);
        byte[] requestWithSha256Imprint = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .build();

        // when
        ResponseEntity<byte[]> response = tspController.timestamp(tspProfileName, requestWithSha256Imprint);

        // then
        TimeStampResponse tsResponse = parseTspResponse(response);
        Assertions
                .assertEquals(PKIStatus.REJECTION, tsResponse.getStatus(),
                        "Token signed by a mismatched key must be rejected, but got status: " + tsResponse.getStatus());
        Assertions.assertEquals("Timestamp signature validation failed", tsResponse.getStatusString());
    }

    /**
     * Full RFC 3161 client-side conformance of a granted response: BouncyCastle's
     * {@code TimeStampResponse.validate(request)} cross-checks the nonce echo, message imprint, and certificate-request
     * consistency against the originating request.
     */
    @Test
    public void grantedResponse_passesRfc3161ClientValidation_andEchoesNonce() throws Exception {
        // given
        boolean validateTokenSignature = true;
        BigInteger requestNonce = BigInteger.valueOf(987654321L);
        String tspProfileName = createEnabledProfiles(SignatureAlgorithm.SHA256_WITH_RSA, validateTokenSignature);
        byte[] requestWithNonce = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .withNonce(requestNonce)
                .build();

        // when
        ResponseEntity<byte[]> response = tspController.timestamp(tspProfileName, requestWithNonce);

        // then
        TimeStampResponse tsResponse = assertGrantedResponse(response);
        tsResponse.validate(new TimeStampRequest(requestWithNonce));
        Assertions
                .assertEquals(requestNonce, tsResponse.getTimeStampToken().getTimeStampInfo().getNonce(),
                        "Token must echo the request nonce");
    }

    @Test
    public void grantedToken_carriesRequestedPolicy_insteadOfProfileDefault() throws Exception {
        // given: the request asks for a specific policy (the profile's empty allowed-list permits any)
        boolean validateTokenSignature = false;
        String requestedPolicyId = "1.2.3.4.6";
        String tspProfileName = createEnabledProfiles(SignatureAlgorithm.SHA256_WITH_RSA, validateTokenSignature);
        byte[] requestWithPolicy = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .withPolicyOid(requestedPolicyId)
                .build();

        // when
        ResponseEntity<byte[]> response = tspController.timestamp(tspProfileName, requestWithPolicy);

        // then
        TimeStampResponse tsResponse = assertGrantedResponse(response);
        Assertions
                .assertEquals(requestedPolicyId, tsResponse.getTimeStampToken().getTimeStampInfo().getPolicy().getId(),
                        "Token policy must be the requested one, not the profile default " + DEFAULT_POLICY_ID);
    }

    @Test
    public void grantedToken_omitsCertificates_whenCertReqIsFalse() throws Exception {
        // given
        boolean validateTokenSignature = false;
        boolean doNotRequestSignerCertificate = false;
        String tspProfileName = createEnabledProfiles(SignatureAlgorithm.SHA256_WITH_RSA, validateTokenSignature);
        byte[] requestWithoutCertReq = aRawTspRequest()
                .withCertReq(doNotRequestSignerCertificate)
                .withHashedMessage(sha256(TSP_IMPRINT_INPUT))
                .build();

        // when
        ResponseEntity<byte[]> response = tspController.timestamp(tspProfileName, requestWithoutCertReq);

        // then
        TimeStampToken token = assertGrantedResponse(response).getTimeStampToken();
        Assertions
                .assertTrue(token.getCertificates().getMatches(null).isEmpty(),
                        "Token must not embed certificates when the request did not ask for them");
    }

    @Test
    public void grantedToken_usesSha512Imprint_forSha512Request() throws Exception {
        // given: the profile's empty allowed-digest list permits any digest algorithm
        boolean validateTokenSignature = false;
        String tspProfileName = createEnabledProfiles(SignatureAlgorithm.SHA256_WITH_RSA, validateTokenSignature);
        byte[] requestWithSha512Imprint = aRawTspRequest()
                .withCertReq(REQUEST_SIGNER_CERTIFICATE)
                .withDigestAlgorithmOid(TSPAlgorithms.SHA512)
                .withHashedMessage(MessageDigest.getInstance("SHA-512").digest(TSP_IMPRINT_INPUT.getBytes()))
                .build();

        // when
        ResponseEntity<byte[]> response = tspController.timestamp(tspProfileName, requestWithSha512Imprint);

        // then
        TimeStampResponse tsResponse = assertGrantedResponse(response);
        Assertions
                .assertEquals(TSPAlgorithms.SHA512.getId(),
                        tsResponse.getTimeStampToken().getTimeStampInfo().getMessageImprintAlgOID().getId(),
                        "Message imprint algorithm must be SHA-512");
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    /**
     * Creates and enables a signing profile (static-key-managed scheme over the algorithm's TSA certificate,
     * timestamping workflow) and a TSP profile defaulting to it; returns the TSP profile name.
     */
    private String createEnabledProfiles(SignatureAlgorithm signatureAlgorithm, boolean validateTokenSignature)
            throws Exception {
        String label = signatureAlgorithm.getCode();
        UUID signingProfileUuid = UUID
                .fromString(signingProfileService
                        .createSigningProfile(aSigningProfileRequest()
                                .withName("tsp-signing-profile-" + label)
                                .withStaticKeyManagedSigning(tsaCertificateFor(signatureAlgorithm).getUuid(),
                                        specFor(signatureAlgorithm).signingAttributes())
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

        String tspProfileName = "tsp-profile-" + label;
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
        return tspProfileName;
    }

    private static AlgorithmSpec specFor(SignatureAlgorithm signatureAlgorithm) {
        return ALGORITHM_SPECS
                .stream()
                .filter(spec -> spec.signatureAlgorithm() == signatureAlgorithm)
                .findFirst()
                .orElseThrow();
    }

    private static byte[] sha256(String input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input.getBytes());
    }

    /**
     * Asserts HTTP 200, PKIStatus GRANTED, token present, and SHA-256 imprint algorithm.
     */
    private static void assertGrantedSha256Response(ResponseEntity<byte[]> response) throws Exception {
        TimeStampResponse tsResponse = assertGrantedResponse(response);
        String imprintAlg = tsResponse.getTimeStampToken().getTimeStampInfo().getMessageImprintAlgOID().getId();
        Assertions.assertEquals(TSPAlgorithms.SHA256.getId(), imprintAlg, "Message imprint algorithm must be SHA-256");
    }

    /**
     * Asserts HTTP 200, PKIStatus GRANTED, and a present token; returns the parsed response.
     */
    private static TimeStampResponse assertGrantedResponse(ResponseEntity<byte[]> response) throws Exception {
        TimeStampResponse tsResponse = parseTspResponse(response);
        Assertions
                .assertEquals(PKIStatus.GRANTED, tsResponse.getStatus(), "Expected PKIStatus GRANTED (0) but got: "
                        + tsResponse.getStatus() + " - " + tsResponse.getStatusString());
        Assertions.assertNotNull(tsResponse.getTimeStampToken(), "TimeStampToken must be present");
        return tsResponse;
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
