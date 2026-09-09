package com.otilm.core.integration.service.scep;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.api.model.core.scep.MessageType;
import com.otilm.api.model.core.scep.PkiStatus;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.entity.scep.ScepTransaction;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.scep.ScepProfileRepository;
import com.otilm.core.dao.repository.scep.ScepTransactionRepository;
import com.otilm.core.service.scep.ScepExternalService;
import com.otilm.core.service.scep.ScepMessageTestData;
import com.otilm.core.service.scep.impl.ScepServiceImpl;
import com.otilm.core.service.scep.message.ScepConstants;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

import static com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec.signingPrivateKey;
import static com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec.verifyingPublicKey;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * End-to-end PKIOperation tests: a real signed CMS PKCSReq goes in, and the assertion is on what a SCEP client actually
 * receives. Issue #1887 was a renewal request answered with an {@code application/json} HTTP 500 the client cannot
 * parse, so the contract under test is that the endpoint always replies in {@code application/x-pki-message}.
 *
 * <p>
 * The profile's CA key is EC, so the request's password recipient is opened with the challenge password and no
 * connector decrypt call is needed. Signing the response does go through the token connector, which WireMock stubs —
 * the returned signature is not independently verified, so a well-formed value suffices to exercise the real
 * response-building path. Issuance is deliberately left unstubbed: these tests are about the protocol envelope, not
 * about the authority.
 * </p>
 */
class ScepPkiOperationITest extends BaseSpringBootTest {

    private static final String SCEP_PROFILE_NAME = "pkiOperationProfile";
    private static final String CA_DN = "CN=Test SCEP CA";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Autowired
    private ScepExternalService scepService;
    @Autowired
    private ScepProfileRepository scepProfileRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private ScepTransactionRepository scepTransactionRepository;
    @Autowired
    private CryptographicKeySeeder cryptographicKeySeeder;

    private WireMockServer mockServer;
    private RaProfile raProfile;
    private ScepProfile scepProfile;

    @BeforeEach
    void setUp() throws Exception {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        Connector connector = new Connector();
        connector.setName("scepTestConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setName("scepTestAuthority");
        authorityInstance.setConnector(connector);
        authorityInstance.setConnectorUuid(connector.getUuid());
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        authorityInstance = authorityInstanceReferenceRepository.save(authorityInstance);

        raProfile = new RaProfile();
        raProfile.setName("scepTestRaProfile");
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReference(authorityInstance);
        raProfile = raProfileRepository.save(raProfile);

        TokenInstanceReference tokenInstance = new TokenInstanceReference();
        tokenInstance.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstance.setName("scepTestTokenInstance");
        tokenInstance.setConnector(connector);
        tokenInstance.setConnectorUuid(connector.getUuid());
        tokenInstance.setKind("sample");
        tokenInstance.setTokenInstanceUuid("22222222-2222-2222-2222-222222222222");
        tokenInstance = tokenInstanceReferenceRepository.save(tokenInstance);

        KeyPair caKeyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        CryptographicKey caKey = cryptographicKeySeeder
                .seedKey("scepCaKey", null, tokenInstance,
                        signingPrivateKey(KeyAlgorithm.ECDSA).withMaterial(KeyFormat.PRKI, "placeholder"),
                        verifyingPublicKey(KeyAlgorithm.ECDSA)
                                .withMaterial(KeyFormat.SPKI,
                                        Base64.getEncoder().encodeToString(caKeyPair.getPublic().getEncoded())));

        Certificate caCertificate = storeCertificate(selfSignedEcCertificate(caKeyPair), caKey, null);

        scepProfile = new ScepProfile();
        scepProfile.setName(SCEP_PROFILE_NAME);
        scepProfile.setDescription("PKIOperation end-to-end profile");
        scepProfile.setEnabled(true);
        scepProfile.setRequireManualApproval(false);
        scepProfile.setIncludeCaCertificate(true);
        scepProfile.setChallengePassword(ScepMessageTestData.CHALLENGE_PASSWORD);
        scepProfile.setCaCertificate(caCertificate);
        scepProfile.setRaProfile(raProfile);
        scepProfile = scepProfileRepository.save(scepProfile);

        stubTokenSigning();
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    /**
     * The reported defect (#1887) at the entry point: a renewal PKCSReq signed with an existing certificate and
     * carrying no challengePassword must not be rejected for a missing shared secret, and must be answered in the SCEP
     * format rather than as a JSON error.
     */
    @Test
    void renewalWithoutChallengePassword_isNotRejectedForAMissingSecret() throws Exception {
        registerSignerCertificate();

        ResponseEntity<Object> response = scepService
                .handlePost(SCEP_PROFILE_NAME, ScepServiceImpl.SCEP_OPERATION_PKI_OPERATION,
                        ScepMessageTestData.passwordEnvelopedPkcsReq(null));

        assertScepFormatted(response);
        // Issuance is unstubbed, so the outcome is a failure — but it must not be the challenge password one.
        assertNotEquals(FailInfo.BAD_MESSAGE_CHECK.getValue(),
                Integer.parseInt(attribute(response, ScepConstants.id_failInfo)),
                "the renewal must get past the challenge password gate");
    }

    /** An initial enrollment with no challenge password is still rejected — with a SCEP failure, not a crash. */
    @Test
    void initialEnrollmentWithoutChallengePassword_isRejectedWithBadMessageCheck() throws Exception {
        ResponseEntity<Object> response = scepService
                .handlePost(SCEP_PROFILE_NAME, ScepServiceImpl.SCEP_OPERATION_PKI_OPERATION,
                        ScepMessageTestData.passwordEnvelopedPkcsReq(null));

        assertScepFormatted(response);
        assertEquals(String.valueOf(PkiStatus.FAILURE.getValue()), attribute(response, ScepConstants.id_pkiStatus));
        assertEquals(String.valueOf(FailInfo.BAD_MESSAGE_CHECK.getValue()),
                attribute(response, ScepConstants.id_failInfo));
    }

    /** A matching challenge password gets past the gate and is answered in the SCEP format. */
    @Test
    void initialEnrollmentWithChallengePassword_isNotRejectedForAMissingSecret() throws Exception {
        ResponseEntity<Object> response = scepService
                .handlePost(SCEP_PROFILE_NAME, ScepServiceImpl.SCEP_OPERATION_PKI_OPERATION,
                        ScepMessageTestData.passwordEnvelopedPkcsReq(ScepMessageTestData.CHALLENGE_PASSWORD));

        assertScepFormatted(response);
        assertNotEquals(FailInfo.BAD_MESSAGE_CHECK.getValue(),
                Integer.parseInt(attribute(response, ScepConstants.id_failInfo)),
                "a matching challenge password must not be reported as an integrity failure");
    }

    /**
     * A request whose transaction is already known is answered from that transaction rather than enrolled again.
     * PENDING is the discriminator: only the transaction branch can produce it for this profile, which has manual
     * approval disabled.
     */
    @Test
    void knownTransaction_isAnsweredFromTheTransaction() throws Exception {
        // A certificate unrelated to the request's signer, so the request is not classified as its renewal.
        Certificate pending = storeCertificate(
                selfSignedEcCertificate(KeyPairGenerator.getInstance("EC").generateKeyPair()), null, raProfile);
        pending.setState(CertificateState.PENDING_ISSUE);
        certificateRepository.save(pending);
        storeTransaction(pending.getUuid());

        ResponseEntity<Object> response = scepService
                .handlePost(SCEP_PROFILE_NAME, ScepServiceImpl.SCEP_OPERATION_PKI_OPERATION,
                        ScepMessageTestData.passwordEnvelopedPkcsReq(ScepMessageTestData.CHALLENGE_PASSWORD));

        assertScepFormatted(response);
        assertEquals(String.valueOf(PkiStatus.PENDING.getValue()), attribute(response, ScepConstants.id_pkiStatus));
    }

    /**
     * A request the platform cannot decrypt — enveloped to a password the profile does not hold — is answered as a SCEP
     * failure rather than escaping as a checked exception to the JSON error handler.
     */
    @Test
    void undecryptableRequest_isAnsweredAsAScepFailure() throws Exception {
        ResponseEntity<Object> response = scepService
                .handlePost(SCEP_PROFILE_NAME, ScepServiceImpl.SCEP_OPERATION_PKI_OPERATION,
                        ScepMessageTestData.pkcsReqEnvelopedWith("someOtherPassword"));

        assertScepFormatted(response);
        assertEquals(String.valueOf(PkiStatus.FAILURE.getValue()), attribute(response, ScepConstants.id_pkiStatus));
        assertEquals(String.valueOf(FailInfo.BAD_REQUEST.getValue()), attribute(response, ScepConstants.id_failInfo));
    }

    /** A CertPoll message is dispatched to polling rather than treated as an enrollment. */
    @Test
    void certPoll_isAnsweredInScepFormat() throws Exception {
        ResponseEntity<Object> response = scepService
                .handlePost(SCEP_PROFILE_NAME, ScepServiceImpl.SCEP_OPERATION_PKI_OPERATION,
                        ScepMessageTestData.passwordEnvelopedMessage(MessageType.CERT_POLL, null));

        assertScepFormatted(response);
    }

    /**
     * RENEWAL_REQ (message type 17) is validated but has no issuance branch, so it is reported as an unsupported
     * operation — tracked for implementation in #1901.
     */
    @Test
    void renewalReqMessageType_isReportedUnsupported() throws Exception {
        ResponseEntity<Object> response = scepService
                .handlePost(SCEP_PROFILE_NAME, ScepServiceImpl.SCEP_OPERATION_PKI_OPERATION, ScepMessageTestData
                        .passwordEnvelopedMessage(MessageType.RENEWAL_REQ, ScepMessageTestData.CHALLENGE_PASSWORD));

        assertScepFormatted(response);
        assertEquals(String.valueOf(FailInfo.BAD_REQUEST.getValue()), attribute(response, ScepConstants.id_failInfo));
    }

    private void storeTransaction(UUID certificateUuid) {
        ScepTransaction transaction = new ScepTransaction();
        transaction.setTransactionId(ScepMessageTestData.TRANSACTION_ID);
        transaction.setCertificateUuid(certificateUuid);
        transaction.setScepProfile(scepProfile);
        scepTransactionRepository.save(transaction);
    }

    private void assertScepFormatted(ResponseEntity<Object> response) throws Exception {
        assertEquals("application/x-pki-message", response.getHeaders().getFirst("Content-Type"),
                "a SCEP client can only parse application/x-pki-message");
        assertNotNull(response.getBody());
        assertNotNull(new CMSSignedData((byte[]) response.getBody()).getSignerInfos().getSigners());
    }

    /** Reads a SCEP attribute out of the signed response. */
    private String attribute(ResponseEntity<Object> response, String oid) throws Exception {
        CMSSignedData signedData = new CMSSignedData((byte[]) response.getBody());
        SignerInformation signer = signedData.getSignerInfos().getSigners().iterator().next();
        ASN1Primitive value = signer
                .getSignedAttributes()
                .get(new ASN1ObjectIdentifier(oid))
                .getAttrValues()
                .getObjectAt(0)
                .toASN1Primitive();
        return ((ASN1String) value).getString();
    }

    /**
     * Registers the request's signer certificate as an issued certificate of this RA profile, with the subject the
     * request asks for and a validity inside the default half-life renewal window.
     */
    private void registerSignerCertificate() throws Exception {
        X509Certificate signerCertificate = ScepMessageTestData.signerCertificate();
        Certificate certificate = storeCertificate(signerCertificate, null, raProfile);
        certificate.setSubjectDn(new X500Name(ScepMessageTestData.SUBJECT_DN).toString());
        certificate.setNotBefore(new Date(System.currentTimeMillis() - 30L * 24 * 3600 * 1000));
        certificate.setNotAfter(new Date(System.currentTimeMillis() + 10L * 24 * 3600 * 1000));
        certificateRepository.save(certificate);
    }

    private Certificate storeCertificate(X509Certificate x509Certificate, CryptographicKey key, RaProfile owner)
            throws Exception {
        String encoded = Base64.getEncoder().encodeToString(x509Certificate.getEncoded());
        String fingerprint = CertificateUtil.getThumbprint(x509Certificate);

        CertificateContent content = new CertificateContent();
        content.setContent(encoded);
        content.setFingerprint(fingerprint);
        content = certificateContentRepository.save(content);

        Certificate certificate = new Certificate();
        certificate.setCertificateContent(content);
        certificate.setCertificateContentId(content.getId());
        certificate.setFingerprint(fingerprint);
        certificate.setSubjectDn(x509Certificate.getSubjectX500Principal().getName());
        certificate.setIssuerDn(x509Certificate.getIssuerX500Principal().getName());
        certificate.setSerialNumber(x509Certificate.getSerialNumber().toString(16));
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setNotBefore(x509Certificate.getNotBefore());
        certificate.setNotAfter(x509Certificate.getNotAfter());
        if (key != null) {
            certificate.setKey(key);
        }
        if (owner != null) {
            certificate.setRaProfile(owner);
        }
        return certificateRepository.save(certificate);
    }

    private static X509Certificate selfSignedEcCertificate(KeyPair keyPair) throws Exception {
        X500Name dn = new X500Name(CA_DN);
        Date notBefore = new Date(System.currentTimeMillis() - 3_600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(dn,
                BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, dn, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    /**
     * The token connector signs the response. The value is passed through without verification here, so a fixed
     * well-formed signature is enough to exercise the real response-building path.
     */
    private void stubTokenSigning() throws Exception {
        KeyPair throwaway = KeyPairGenerator.getInstance("EC").generateKeyPair();
        java.security.Signature signature = java.security.Signature.getInstance("SHA256withECDSA");
        signature.initSign(throwaway.getPrivate());
        signature.update("scep".getBytes());
        String signed = Base64.getEncoder().encodeToString(signature.sign());

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/sign"))
                        .willReturn(WireMock.okJson("""
                                {"signatures": [{"data": "%s"}]}
                                """.formatted(signed))));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/verify"))
                        .willReturn(WireMock.okJson("""
                                {"verifications": [{"result": true}]}
                                """)));
    }
}
