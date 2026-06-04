package com.czertainly.core.service.cmp.message.handler;

import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.cmp.CmpTransactionState;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.cmp.CmpProfileRepository;
import com.czertainly.core.service.cmp.CmpEntityUtil;
import com.czertainly.core.service.cmp.CmpTestUtil;
import com.czertainly.core.service.cmp.configurations.variants.CmpConfigurationContext;
import com.czertainly.core.service.cmp.configurations.variants.Mobile3gppProfileContext;
import com.czertainly.core.service.cmp.message.CertificateKeyServiceImpl;
import com.czertainly.core.service.cmp.message.CmpTransactionService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@Transactional
public class CertConfirmMessageHandlerITest extends BaseSpringBootTest {

    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CmpTransactionService cmpTransactionService;
    @Autowired
    private CmpProfileRepository cmpProfileRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private CertificateKeyServiceImpl certificateKeyService;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;

    private RaProfile raProfile;
    private CertConfirmMessageHandler testedHandler;
    private CmpProfile cmpProfileSigPrt;
    private CmpProfile cmpProfileMacPrt;//mac-protection

    private final String transactionId = "999";
    private final BigInteger serialNumber = BigInteger.valueOf(123456789);
    private final String sharedSecret = "sh@r3dS3cr3t";
    private X509CertificateHolder x509certificate;
    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() throws Exception {
        // -- GIVEN --
        mockServer = CmpTestUtil.createSigningPlatform();

        // -- IoC setting up
        testedHandler = new CertConfirmMessageHandler();
        testedHandler.setCmpTransactionService(cmpTransactionService);

        // -- create customer/client profile (signature-based)
        raProfile = raProfileRepository.save(CmpEntityUtil.createRaProfile());
        cmpProfileSigPrt = cmpProfileRepository.save(
                CmpEntityUtil.createCmpProfile(raProfile,
                        createSigningCertificateEntity(mockServer)));
        // -- create customer/client profile (macpwd-based)
        cmpProfileMacPrt = cmpProfileRepository.save(
                CmpEntityUtil.createCmpProfile(raProfile, sharedSecret));

        // -- create certificate - x509
        KeyPair kp = CmpTestUtil.generateKeyPairEC();
        x509certificate = CmpTestUtil.makeV3Certificate(serialNumber, kp, "CN=Test", kp, "CN=Test");
        // -- create issued certificate - db entity (which must be confirmed - via tested handler)
        // Real base64 cert content is required so CertConfirmMessageHandler.getFingerprint can
        // re-parse the X.509 certificate and compute its hash.
        String certBase64 = java.util.Base64.getEncoder().encodeToString(x509certificate.getEncoded());
        Certificate issuedCertificate = certificateRepository.save(CmpEntityUtil.createCertificate(
                        CmpTestUtil.createMessageDigest(x509certificate),
                        serialNumber,
                        CertificateState.ISSUED,
                        certificateContentRepository.save(
                                CmpEntityUtil.createCertContent(
                                        new DEROctetString(CmpTestUtil.createMessageDigest(x509certificate).getDigest()).toString().substring(1),
                                        certBase64))
                )
        );
        // -- transaction related to issued certificate - db entity
        cmpTransactionService.save(CmpEntityUtil.createTransaction(transactionId,
                issuedCertificate,
                cmpProfileSigPrt,
                CmpTransactionState.CERT_ISSUED));
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    public void test_handle_3gpp_signature_protection() throws Exception {
        // -- WHEN --
        PKIBody body = CmpTestUtil.createCertConfBody(x509certificate, serialNumber);
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage(
                        transactionId, CmpTestUtil.generateKeyPairEC().getPrivate(), body)
                .toASN1Structure();

        // -- test handling of message
        PKIMessage response = testedHandler.handle(request,
                new Mobile3gppProfileContext(cmpProfileSigPrt,
                        raProfile,
                        request,
                        certificateKeyService,
                        null,
                        null));
        // -- THEN --
        // (1) check structure: type, transactionId(trxId) and content (type)
        assertEquals(PKIBody.TYPE_CONFIRM, response.getBody().getType());
        assertEquals(new DEROctetString(transactionId.getBytes()).toString(),
                response.getHeader().getTransactionID().toString());
        assertInstanceOf(PKIConfirmContent.class, response.getBody().getContent());
        assertTrue(response.getExtraCerts().length > 0);

        // (2) check certificate (found by serial number) and its state
        Optional<Certificate> certificate = certificateRepository.findBySerialNumberIgnoreCase(
                serialNumber.toString(16));
        assertFalse(certificate.isEmpty());
        assertEquals(CertificateState.ISSUED, certificate.get().getState());

        // (3) check transaction (found by serial number - same as related with cert) and its state
        cmpTransactionService.findByTransactionIdAndCertificateSerialNumber(transactionId,
                        serialNumber.toString(16))
                .ifPresent(cmpTransaction -> assertEquals(CmpTransactionState.CERT_CONFIRMED, cmpTransaction.getState())
                );
    }

    @Test
    public void test_handle_rfc4210_signature_protection() throws Exception {
        // -- WHEN --
        PKIBody body = CmpTestUtil.createCertConfBody(x509certificate, serialNumber);
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage(
                        transactionId, CmpTestUtil.generateKeyPairEC().getPrivate(), body)
                .toASN1Structure();

        // -- test handling of message
        PKIMessage response = testedHandler.handle(request,
                new CmpConfigurationContext(cmpProfileSigPrt,
                        raProfile,
                        request,
                        certificateKeyService,
                        null,
                        null));
        // -- THEN --
        // (1) check structure: type, transactionId(trxId) and content (type)
        assertEquals(PKIBody.TYPE_CONFIRM, response.getBody().getType());
        assertEquals(new DEROctetString(transactionId.getBytes()).toString(),
                response.getHeader().getTransactionID().toString());
        Assertions.assertInstanceOf(PKIConfirmContent.class, response.getBody().getContent());

        // (2) check certificate (found by serial number) and its state
        Optional<Certificate> certificate = certificateRepository.findBySerialNumberIgnoreCase(
                serialNumber.toString(16));
        assertFalse(certificate.isEmpty());
        assertEquals(CertificateState.ISSUED, certificate.get().getState());
        assertTrue(response.getExtraCerts().length > 0);

        // (3) check transaction (found by serial number - same as related with cert) and its state
        cmpTransactionService.findByTransactionIdAndCertificateSerialNumber(
                transactionId, serialNumber.toString(16)
        ).ifPresent(
                cmpTransaction -> assertEquals(
                        CmpTransactionState.CERT_CONFIRMED,
                        cmpTransaction.getState())
        );
    }

    @Test
    public void test_handle_3gpp_mac_protection() throws Exception {
        // -- WHEN --
        PKIBody body = CmpTestUtil.createCertConfBody(x509certificate, serialNumber);
        PKIMessage request = CmpTestUtil.createMacBasedMessage(
                        transactionId, sharedSecret, body)
                .toASN1Structure();

        // -- test handling of message
        PKIMessage response = testedHandler.handle(request,
                new Mobile3gppProfileContext(cmpProfileMacPrt,
                        raProfile,
                        request,
                        certificateKeyService,
                        null,
                        null));
        // -- THEN --
        // (1) check structure: type, transactionId(trxId) and content (type)
        assertEquals(PKIBody.TYPE_CONFIRM, response.getBody().getType());
        assertEquals(new DEROctetString(transactionId.getBytes()).toString(),
                response.getHeader().getTransactionID().toString());
        Assertions.assertInstanceOf(PKIConfirmContent.class, response.getBody().getContent());

        // (2) check certificate (found by serial number) and its state
        Optional<Certificate> certificate = certificateRepository.findBySerialNumberIgnoreCase(
                serialNumber.toString(16));
        assertFalse(certificate.isEmpty());
        assertEquals(CertificateState.ISSUED, certificate.get().getState());

        // (3) check transaction (found by serial number - same as related with cert) and its state
        cmpTransactionService.findByTransactionIdAndCertificateSerialNumber(
                transactionId, serialNumber.toString(16)
        ).ifPresent(
                cmpTransaction -> assertEquals(
                        CmpTransactionState.CERT_CONFIRMED,
                        cmpTransaction.getState())
        );
    }

    @Test
    public void test_handle_rfc4210_mac_protection() throws Exception {
        // -- WHEN --
        PKIMessage request = CmpTestUtil.createMacBasedMessage(
                        transactionId, sharedSecret, CmpTestUtil.createCertConfBody(x509certificate, serialNumber))
                .toASN1Structure();

        // -- test handling of message
        PKIMessage response = testedHandler.handle(request,
                new CmpConfigurationContext(cmpProfileMacPrt,
                        raProfile,
                        request,
                        certificateKeyService,
                        null,
                        null));
        // -- THEN --
        // (1) check structure: type, transactionId(trxId) and content (type)
        assertEquals(PKIBody.TYPE_CONFIRM, response.getBody().getType());
        assertEquals(new DEROctetString(transactionId.getBytes()).toString(),
                response.getHeader().getTransactionID().toString());
        Assertions.assertInstanceOf(PKIConfirmContent.class, response.getBody().getContent());

        // (2) check certificate (found by serial number) and its state
        Optional<Certificate> certificate = certificateRepository.findBySerialNumberIgnoreCase(
                serialNumber.toString(16));
        assertFalse(certificate.isEmpty());
        assertEquals(CertificateState.ISSUED, certificate.get().getState());

        // (3) check transaction (found by serial number - same as related with cert) and its state
        cmpTransactionService.findByTransactionIdAndCertificateSerialNumber(
                transactionId, serialNumber.toString(16)
        ).ifPresent(
                cmpTransaction -> assertEquals(
                        CmpTransactionState.CERT_CONFIRMED,
                        cmpTransaction.getState())
        );
    }

    // ----------------------------------------------------------------------------------------------------------
    // HELPER METHODS
    // ----------------------------------------------------------------------------------------------------------

    // --  entities
    private Certificate createSigningCertificateEntity(WireMockServer mockServer) {
        Connector connector = new Connector();
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        TokenInstanceReference tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReferenceRepository.save(tokenInstanceReference);

        CryptographicKey key = new CryptographicKey();
        key.setUuid(UUID.randomUUID());
        key.setName("testKey");
        key.setDescription("initial description");
        key.setTokenInstanceReference(tokenInstanceReference);
        key = cryptographicKeyRepository.save(key);

        CryptographicKeyItem ckPrivateKey = new CryptographicKeyItem();
        ckPrivateKey.setKeyReferenceUuid(UUID.fromString("bb016fae-79b7-4284-9e77-950648dd9d26"));
        ckPrivateKey.setState(KeyState.ACTIVE);
        ckPrivateKey.setType(KeyType.PRIVATE_KEY);
        ckPrivateKey.setFingerprint("7d903217b49fcf947f9b45ba239d4236b99fb75baf7ede08ce53a55c06678f1e");
        ckPrivateKey.setEnabled(true);
        ckPrivateKey.setKey(key);
        ckPrivateKey.setKeyAlgorithm(KeyAlgorithm.ECDSA);
        cryptographicKeyItemRepository.save(ckPrivateKey);
        Set<CryptographicKeyItem> items = new HashSet<>();
        items.add((ckPrivateKey));
        key.setItems(items);
        key = cryptographicKeyRepository.save(key);
        cryptographicKeyRepository.flush();

        CertificateContent certificateContentSig = new CertificateContent();
        certificateContentSig.setFingerprint("20bfa83ea6a554a92313e62e7f897e71d8fd7406f0a80872defcce755245a63b");
        certificateContentSig.setContent("MIIEcjCCAlqgAwIBAgIUSRfTNEXeaZ+rtyTnaGLwRvzKv40wDQYJKoZIhvcNAQELBQAwQDEgMB4GA1UEAwwXRGVtb0NsaWVudFN1YkNBXzIzMDdSU0ExHDAaBgNVBAoMEzNLZXkgQ29tcGFueSBzLnIuby4wHhcNMjQwNDI5MTMwMTM2WhcNMjYwNDI5MTMwMTM1WjAcMRowGAYDVQQDDBF0ZXN0Y21wY2xpZW50Y2VydDB2MBAGByqGSM49AgEGBSuBBAAiA2IABAuHVkX5et+TLQ5yoHrU2j22IpoDPUFo7c+t01iXFjPXPGf3q5MDwAOp7y79QyXvDgzSo56NTrVzDg9EDSWwjAdVl2fj06QoMLXq7APSc3B15Gvw+pn0ME5Vkfw5T4DcL6OCATQwggEwMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUlW9WiT+pb/3A1zDBt5df5ixKrx0wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzAChjxodHRwOi8vcGtpLjNrZXkuY29tcGFueS9jYXMvZGVtby9kZW1vY2xpZW50c3ViY2FfMjMwN3JzYS5jcnQwEQYDVR0gBAowCDAGBgRVHSAAMBMGA1UdJQQMMAoGCCsGAQUFBwMCME4GA1UdHwRHMEUwQ6BBoD+GPWh0dHA6Ly9wa2kuM2tleS5jb21wYW55L2NybHMvZGVtby9kZW1vY2xpZW50c3ViY2FfMjMwN3JzYS5jcmwwHQYDVR0OBBYEFGHmdF5qP/gtNmU/iIT4N22jQbiJMA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0BAQsFAAOCAgEA03P8vQpq8wUB6bKpBtS43U+/T/wYUG1tq+2N0G16lZpXgFRAiBOe9ZrUov4iW+gIb8rRNmVcqgaeQtYn57AkC5oQp6tT1FdrEtx71B9EaMaSrGJwLfXypzEYyco4PBmHTadNJimFcIDA25Gp5hAHWDj6GeBUffUOb4PTR+ACBnHi/ApUxRPYCuqeeZZguOIlfy796SWSruCQN+zBQGjKpuCy795eSmaSfjl2h63uOzb+ulLhulHilWi9pk7nGTIbWd1m0LlLrhJQZcesMSlEx7yIkrrz5xCI1/rGu9BnpH5LH1b7TVExtsN3sZmeI10XTlVSLVt0WJTWB71O03QHSi+Fgb28msts2sZ6HSH2zyCxbtvqCZ4aXIfAKh9Cmg5xy6vG9isMtAHCK9m7fKDSnZ57qp6O2Et+zjEbQvOHdu8RHIbQIwHEdAEEUsMDKG7C+DrcZ+2AhK9fm2ToZX3Nt9t3H9BSnFKLfbpsXZsICftrlIFXoVSP+K3/DfLIF8gQQKLxdAiKnUJnGrnMQmy7moBo8LfMkA0MHLlKWwVvUHvNyv5cnhU4J2GSyC8T5aYVD1x/udv+B5xrjSbfbwLsWE2qC6XqThWcypJaSQBM2nzNi78Qnu/HLGsHPfiRBA4wqpG9gZ3qw3BT9nvNI452REqA6WNy4mzEbgpOp0WQkhE=");
        certificateContentSig = certificateContentRepository.save(certificateContentSig);

        Certificate certificateSig = new Certificate();
        certificateSig.setCertificateContent(certificateContentSig);
        certificateSig.setSerialNumber(new BigInteger(10, new SecureRandom()).toString(16));
        certificateSig.setUuid(UUID.randomUUID());
        certificateSig.setKey(key);
        certificateSig.setKeyUuid(key.getUuid());
        certificateSig = certificateRepository.save(certificateSig);
        certificateContentSig.setCertificate(certificateSig);
        certificateContentRepository.save(certificateContentSig);
        return certificateSig;
    }

}
