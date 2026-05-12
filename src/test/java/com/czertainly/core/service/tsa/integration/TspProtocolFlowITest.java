package com.czertainly.core.service.tsa.integration;

import com.czertainly.api.model.client.connector.v2.ConnectorInterface;
import com.czertainly.api.model.client.connector.v2.FeatureFlag;
import com.czertainly.api.model.client.signing.profile.SigningProfileRequestDto;
import com.czertainly.api.model.client.signing.profile.scheme.StaticKeyManagedSigningRequestDto;
import com.czertainly.api.model.client.signing.protocols.tsp.TspProfileRequestDto;
import com.czertainly.api.model.client.signing.profile.workflow.TimestampingWorkflowRequestDto;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.czertainly.api.model.connector.signatures.formatter.FormatDtbsResponseDto;
import com.czertainly.api.model.connector.signatures.formatter.FormattedResponseDto;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.oid.SystemOid;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.core.attribute.RsaSignatureAttributes;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.ConnectorInterfaceEntity;
import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.TokenInstanceReference;
import com.czertainly.core.dao.entity.TokenProfile;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.ConnectorInterfaceRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.CryptographicKeyItemRepository;
import com.czertainly.core.dao.repository.CryptographicKeyRepository;
import com.czertainly.core.dao.repository.TokenInstanceReferenceRepository;
import com.czertainly.core.dao.repository.TokenProfileRepository;
import com.czertainly.core.api.tsp.TspControllerImpl;
import com.czertainly.core.service.SigningProfileService;
import com.czertainly.core.service.TspProfileService;
import com.czertainly.core.service.tsa.ManagedTimestampEngine;
import com.czertainly.core.service.tsa.TimestampTokenTestUtil;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.MetaDefinitions;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;

/**
 * End-to-end integration test for the RFC 3161 Timestamp Protocol implementation.
 *
 * <p>Exercises the full timestamp-token production path via the service layer:
 * <ol>
 *   <li>Infrastructure setup – connector, token instance, token profile, cryptographic key,
 *       TSA certificate, signing profile, TSP profile</li>
 *   <li>TSP request construction (BouncyCastle {@link TimeStampRequestGenerator})</li>
 *   <li>{@link TspControllerImpl#timestamp} invocation</li>
 *   <li>RFC 3161 {@link TimeStampResponse} parsing and PKI status assertion</li>
 * </ol>
 *
 * <p>External connectors are stubbed with WireMock.
 */
public class TspProtocolFlowITest extends BaseSpringBootTest {

    // ── Spring beans ──────────────────────────────────────────────────────────

    @Autowired
    private TspControllerImpl tspController;
    @Autowired
    private SigningProfileService signingProfileService;
    @Autowired
    private TspProfileService tspProfileService;

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
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;

    // ── Test constants ────────────────────────────────────────────────────────

    private static final String TSP_PROFILE_NAME = "testTspProfile";
    private static final String SIGNING_PROFILE_NAME = "testSigningProfile";
    private static final String TSP_PROFILE_VALIDATED_NAME = "testTspProfileValidated";
    private static final String SIGNING_PROFILE_VALIDATED_NAME = "testSigningProfileValidated";

    // ── Per-test state ────────────────────────────────────────────────────────

    private UUID signingProfileUuid;
    private UUID signingProfileValidatedUuid;
    private WireMockServer wireMockServer;
    private final ObjectMapper objectMapper = new ObjectMapper();
    /**
     * In-memory RSA key pair used to build the TSA certificate.
     */
    private KeyPair tsaKeyPair;
    /**
     * Self-signed X.509 TSA certificate with critical id-kp-timeStamping EKU.
     */
    private X509Certificate tsaCert;
    /**
     * Pre-computed RFC 3161 TimeStampToken DER bytes returned by the formatter stub.
     */
    private byte[] precomputedTokenBytes;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @BeforeEach
    public void setUp() throws Exception {
        ensureBouncyCastleProvider();

        tsaKeyPair = generateRsaKeyPair();
        tsaCert = buildTsaCertificate(tsaKeyPair);
        precomputedTokenBytes = TimestampTokenTestUtil.createTimestampTokenSignedWith(tsaKeyPair, tsaCert).getEncoded();

        wireMockServer = new WireMockServer(
                WireMockConfiguration.options()
                        .port(0)
                        .extensions(new RealRsaSignerTransformer(tsaKeyPair.getPrivate())));
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());

        stubSignEndpoint();
        stubFormatterEndpoints();
        buildInfrastructure();
    }

    @AfterEach
    public void tearDown() {
        wireMockServer.stop();
    }

    // ── Test ──────────────────────────────────────────────────────────────────

    /**
     * Happy-path end-to-end flow: build TSP request → call controller → assert GRANTED.
     */
    @Test
    public void tspFullTimestampFlowWithNoSignatureValidation() throws Exception {
        assertGrantedSha256Response(tspController.timestamp(TSP_PROFILE_NAME, buildSha256TspRequestBytes()));
    }

    /**
     * Happy-path end-to-end flow with token signature validation enabled: build TSP request → call controller → assert GRANTED.
     */
    @Test
    public void tspFullTimestampFlowWithTokenSignatureValidation() throws Exception {
        assertGrantedSha256Response(tspController.timestamp(TSP_PROFILE_VALIDATED_NAME, buildSha256TspRequestBytes()));
    }

    private void buildInfrastructure() throws Exception {
        // tsaKeyPair and tsaCert were already built in setUp() before stub registration.

        Connector connector = persistConnector();
        Connector formatterConnector = persistFormatterConnector();
        TokenInstanceReference tokenInstance = persistTokenInstance(connector);
        TokenProfile tokenProfile = persistTokenProfile(tokenInstance);
        CryptographicKey key = persistCryptographicKey(tokenInstance, tokenProfile, tsaKeyPair);
        Certificate certificate = persistTsaCertificate(key, tsaCert);

        signingProfileUuid = createSigningProfile(
                certificate, formatterConnector,
                SIGNING_PROFILE_NAME, "TSP integration test signing profile",
                false);
        createTspProfile(TSP_PROFILE_NAME, "TSP integration test profile", signingProfileUuid);

        signingProfileValidatedUuid = createSigningProfile(
                certificate, formatterConnector,
                SIGNING_PROFILE_VALIDATED_NAME, "TSP integration test signing profile with token signature validation",
                true);
        createTspProfile(TSP_PROFILE_VALIDATED_NAME, "TSP integration test profile with token signature validation", signingProfileValidatedUuid);
    }

    /**
     * Stub: POST /v1/cryptographyProvider/tokens/{any}/keys/{any}/sign → 200 with real signature.
     *
     * <p>The {@link RealRsaSignerTransformer} extension intercepts the request, extracts the
     * base64-encoded DTBS from the JSON body, signs it with {@code SHA256withRSA} using the
     * test TSA private key, and returns the real signature so the assembled timestamp token
     * is cryptographically valid.
     */
    private void stubSignEndpoint() {
        wireMockServer.stubFor(
                post(urlPathMatching("/v1/cryptographyProvider/tokens/.+/keys/.+/sign"))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withTransformers("real-rsa-signer"))
        );
    }

    /**
     * Stubs the two-phase signature formatter connector endpoints used by
     * {@link com.czertainly.core.service.tsa.formatter.TimestampingConnectorSignatureFormatterClient}.
     *
     * <p>Phase 1 ({@code formatDtbs}): returns a fixed dummy DTBS byte array.
     * The bytes are fed to the signer stub, which produces a real RSA signature over them.
     *
     * <p>Phase 2 ({@code formatResponse}): returns the pre-computed RFC 3161 token bytes
     * generated in {@link #setUp()}.
     */
    private void stubFormatterEndpoints() throws Exception {
        // Phase 1: formatDtbs — return dummy DTBS bytes for the signer to sign
        FormatDtbsResponseDto dtbsResponse = new FormatDtbsResponseDto();
        dtbsResponse.setDtbs(new byte[]{1, 2, 3, 4, 5});
        String dtbsJson = objectMapper.writeValueAsString(dtbsResponse);
        wireMockServer.stubFor(
                post(urlPathMatching("/formatter/v1/signatureProvider/formatting/formatDtbs"))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(dtbsJson))
        );

        // Phase 2: formatResponse — return a structurally valid TimeStampToken
        FormattedResponseDto tokenResponse = new FormattedResponseDto();
        tokenResponse.setResponse(precomputedTokenBytes);
        String tokenJson = objectMapper.writeValueAsString(tokenResponse);
        wireMockServer.stubFor(
                post(urlPathMatching("/formatter/v1/signatureProvider/formatting/formatResponse"))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withBody(tokenJson))
        );

        wireMockServer.stubFor(
                WireMock.get(WireMock.urlPathMatching("/formatter/v1/signatureProvider/formatting/attributes"))
                        .willReturn(WireMock.okJson("[]"))
        );
    }

    private Connector persistConnector() {
        Connector connector = new Connector();
        connector.setName("tsp-crypto-connector");
        connector.setUrl("http://localhost:" + wireMockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.save(connector);
    }

    private Connector persistFormatterConnector() {
        Connector connector = new Connector();
        connector.setName("tsp-formatter-connector");
        connector.setUrl("http://localhost:" + wireMockServer.port() + "/formatter");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        ConnectorInterfaceEntity connectorInterface = new ConnectorInterfaceEntity();
        connectorInterface.setConnectorUuid(connector.getUuid());
        connectorInterface.setInterfaceCode(ConnectorInterface.SIGNATURE_FORMATTING);
        connectorInterface.setVersion("1.0.0");
        connectorInterface.setFeatures(List.of(FeatureFlag.TIMESTAMPING));
        connectorInterfaceRepository.save(connectorInterface);

        return connector;
    }

    private TokenInstanceReference persistTokenInstance(Connector connector) {
        TokenInstanceReference ref = new TokenInstanceReference();
        ref.setName("tsp-token-instance");
        ref.setTokenInstanceUuid(UUID.randomUUID().toString());
        ref.setConnector(connector);
        ref.setStatus(TokenInstanceStatus.CONNECTED);
        return tokenInstanceReferenceRepository.saveAndFlush(ref);
    }

    private TokenProfile persistTokenProfile(TokenInstanceReference tokenInstance) {
        TokenProfile profile = new TokenProfile();
        profile.setName("tsp-token-profile");
        profile.setTokenInstanceReference(tokenInstance);
        profile.setTokenInstanceName(tokenInstance.getName());
        profile.setEnabled(true);
        return tokenProfileRepository.saveAndFlush(profile);
    }

    private CryptographicKey persistCryptographicKey(TokenInstanceReference tokenInstance,
                                                     TokenProfile tokenProfile,
                                                     KeyPair keyPair) {
        CryptographicKey key = new CryptographicKey();
        key.setName("tsp-rsa-key");
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenInstance);
        key = cryptographicKeyRepository.saveAndFlush(key);

        // Private key item
        CryptographicKeyItem privateItem = new CryptographicKeyItem();
        privateItem.setKey(key);
        privateItem.setKeyUuid(key.getUuid());
        privateItem.setType(KeyType.PRIVATE_KEY);
        privateItem.setState(com.czertainly.api.model.core.cryptography.key.KeyState.ACTIVE);
        privateItem.setEnabled(true);
        privateItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        privateItem.setLength(2048);
        privateItem.setUsage(List.of(com.czertainly.api.model.core.cryptography.key.KeyUsage.SIGN));
        privateItem = cryptographicKeyItemRepository.saveAndFlush(privateItem);
        privateItem.setKeyReferenceUuid(privateItem.getUuid());
        cryptographicKeyItemRepository.saveAndFlush(privateItem);

        // Public key item — keyData carries the base64-encoded SubjectPublicKeyInfo (used by
        // resolveSignatureAlgorithmName for FALCON/MLDSA; for RSA it is unused but must be present)
        String pubKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        CryptographicKeyItem publicItem = new CryptographicKeyItem();
        publicItem.setKey(key);
        publicItem.setKeyUuid(key.getUuid());
        publicItem.setType(KeyType.PUBLIC_KEY);
        publicItem.setState(com.czertainly.api.model.core.cryptography.key.KeyState.ACTIVE);
        publicItem.setEnabled(true);
        publicItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        publicItem.setLength(2048);
        publicItem.setUsage(List.of(com.czertainly.api.model.core.cryptography.key.KeyUsage.SIGN));
        publicItem.setKeyData(pubKeyBase64);
        publicItem = cryptographicKeyItemRepository.saveAndFlush(publicItem);
        publicItem.setKeyReferenceUuid(publicItem.getUuid());
        cryptographicKeyItemRepository.saveAndFlush(publicItem);

        return cryptographicKeyRepository.findById(key.getUuid()).orElseThrow();
    }

    /**
     * Persists a Certificate entity with the TSA X.509 certificate content and all
     * conditions required by {@code isCertificateDigitalSigningAcceptable} for TIMESTAMPING:
     * <ul>
     *   <li>state = ISSUED, validationStatus = VALID</li>
     *   <li>key has a token profile</li>
     *   <li>extendedKeyUsage = [id-kp-timeStamping], critical = true</li>
     * </ul>
     */
    private Certificate persistTsaCertificate(CryptographicKey key, X509Certificate x509) throws Exception {
        // Persist certificate content (base64-encoded DER without PEM headers, matching normalizeCertificateContent)
        String derBase64 = Base64.getEncoder().encodeToString(x509.getEncoded());
        String fingerprint = CertificateUtil.getThumbprint(x509.getEncoded());

        CertificateContent content = new CertificateContent();
        content.setContent(derBase64);
        content.setFingerprint(fingerprint);
        content = certificateContentRepository.saveAndFlush(content);

        Certificate cert = new Certificate();
        cert.setKey(key);
        cert.setState(CertificateState.ISSUED);
        cert.setValidationStatus(CertificateValidationStatus.VALID);
        cert.setFingerprint(fingerprint);
        cert.setCertificateContent(content);
        // RFC 3161: exactly id-kp-timeStamping, critical
        cert.setExtendedKeyUsage(MetaDefinitions.serializeArrayString(List.of(SystemOid.TIME_STAMPING.getOid())));
        cert.setExtendedKeyUsageCritical(true);
        return certificateRepository.saveAndFlush(cert);
    }

    private UUID createSigningProfile(Certificate certificate, Connector formatterConnector, String name, String description,
                                      boolean validateTokenSignature) throws Exception {
        StaticKeyManagedSigningRequestDto scheme = new StaticKeyManagedSigningRequestDto();
        scheme.setCertificateUuid(certificate.getUuid());
        scheme.setSigningOperationAttributes(List.of(
                buildRsaSchemeAttribute(RsaSignatureScheme.PKCS1_v1_5),
                buildDigestAttribute(DigestAlgorithm.SHA_256)));

        TimestampingWorkflowRequestDto workflow = new TimestampingWorkflowRequestDto();
        workflow.setSignatureFormatterConnectorUuid(formatterConnector.getUuid());
        workflow.setQualifiedTimestamp(false);
        workflow.setDefaultPolicyId("1.2.3.4.5");
        workflow.setValidateTokenSignature(validateTokenSignature);

        SigningProfileRequestDto request = new SigningProfileRequestDto();
        request.setName(name);
        request.setDescription(description);
        request.setSigningScheme(scheme);
        request.setWorkflow(workflow);

        return UUID.fromString(signingProfileService.createSigningProfile(request).getUuid());
    }

    private void createTspProfile(String name, String description, UUID defaultSigningProfileUuid) throws Exception {
        TspProfileRequestDto request = new TspProfileRequestDto();
        request.setName(name);
        request.setDescription(description);
        request.setDefaultSigningProfileUuid(defaultSigningProfileUuid);

        tspProfileService.createTspProfile(request);
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    /**
     * Builds an SHA-256 TSP request over a fixed test imprint, with certReq=true.
     */
    private static byte[] buildSha256TspRequestBytes() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("Hello, Timestamp!".getBytes());
        TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
        gen.setCertReq(true);
        return gen.generate(TSPAlgorithms.SHA256, hash, BigInteger.valueOf(System.currentTimeMillis())).getEncoded();
    }

    /**
     * Asserts HTTP 200, PKIStatus GRANTED, token present, and SHA-256 imprint algorithm.
     */
    private static void assertGrantedSha256Response(ResponseEntity<byte[]> response) throws Exception {
        Assertions.assertEquals(200, response.getStatusCode().value());
        byte[] responseBytes = response.getBody();
        Assertions.assertNotNull(responseBytes);
        Assertions.assertTrue(responseBytes.length > 0, "Response body must not be empty");

        TimeStampResponse tsResponse = new TimeStampResponse(responseBytes);
        Assertions.assertEquals(PKIStatus.GRANTED, tsResponse.getStatus(),
                "Expected PKIStatus GRANTED (0) but got: " + tsResponse.getStatus() + " - " + tsResponse.getStatusString()
        );

        Assertions.assertNotNull(tsResponse.getTimeStampToken(), "TimeStampToken must be present");
        String imprintAlg = tsResponse.getTimeStampToken().getTimeStampInfo().getMessageImprintAlgOID().getId();
        Assertions.assertEquals(TSPAlgorithms.SHA256.getId(), imprintAlg,
                "Message imprint algorithm must be SHA-256");
    }

    // ── Crypto helpers ────────────────────────────────────────────────────────

    private static void ensureBouncyCastleProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    /**
     * Builds a self-signed X.509 certificate with critical id-kp-timeStamping EKU.
     * The resulting certificate satisfies the requirements checked by
     * {@link com.czertainly.core.util.CertificateUtil#isCertificateDigitalSigningAcceptable}
     * for the TIMESTAMPING workflow, as reflected in the {@code Certificate} entity's metadata fields.
     */
    private static X509Certificate buildTsaCertificate(KeyPair keyPair) throws Exception {
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        X500Principal subject = new X500Principal("CN=Test TSA, O=CZERTAINLY, C=CZ");

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, keyPair.getPublic());

        // Critical id-kp-timeStamping EKU (RFC 3161 requirement)
        certBuilder.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certBuilder.build(signer));
    }

    private static RequestAttributeV2 buildRsaSchemeAttribute(RsaSignatureScheme scheme) {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID));
        attr.setName(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME);
        attr.setContentType(AttributeContentType.STRING);
        attr.setContent(List.of(new StringAttributeContentV2(scheme.getLabel(), scheme.getCode())));
        return attr;
    }

    private static RequestAttributeV2 buildDigestAttribute(DigestAlgorithm algorithm) {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(UUID.fromString(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID));
        attr.setName(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST);
        attr.setContentType(AttributeContentType.STRING);
        attr.setContent(List.of(new StringAttributeContentV2(algorithm.getLabel(), algorithm.getCode())));
        return attr;
    }

    // ── WireMock transformer ──────────────────────────────────────────────────

    /**
     * WireMock extension that computes a real {@code SHA256withRSA} signature over the incoming
     * DTBS so the assembled timestamp token is cryptographically valid.
     *
     * <p>It parses the connector sign-request JSON ({@code data[0].data} = base64 DTBS),
     * signs the decoded bytes with the test TSA private key, and returns the signature
     * in the connector sign-response JSON ({@code signatures[0].data} = base64 signature).
     */
    private record RealRsaSignerTransformer(PrivateKey privateKey) implements ResponseDefinitionTransformerV2 {

        @Override
        public ResponseDefinition transform(ServeEvent serveEvent) {
            try {
                ObjectMapper objectMapper = new ObjectMapper();
                JsonNode body = objectMapper.readTree(serveEvent.getRequest().getBodyAsString());
                byte[] dtbs = Base64.getDecoder().decode(body.at("/data/0/data").asText());

                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initSign(privateKey);
                sig.update(dtbs);
                byte[] signature = sig.sign();

                String responseBody = objectMapper.writeValueAsString(
                        new SignDataConnectorResponse(List.of(new SignatureEntry(signature))));

                return ResponseDefinitionBuilder.responseDefinition()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(responseBody)
                        .build();
            } catch (Exception e) {
                throw new RuntimeException("Failed to compute SHA256withRSA signature in WireMock transformer", e);
            }
        }

        @Override
        public String getName() {
            return "real-rsa-signer";
        }

        @Override
        public boolean applyGlobally() {
            return false;
        }
    }

    // ── WireMock response POJOs ───────────────────────────────────────────────

    /**
     * Matches the connector-side {@code SignDataResponseDto} JSON structure.
     */
    record SignDataConnectorResponse(List<SignatureEntry> signatures) {
    }

    /**
     * Matches the connector-side {@code SignatureResponseData} JSON structure.
     */
    record SignatureEntry(byte[] data) {
    }
}
