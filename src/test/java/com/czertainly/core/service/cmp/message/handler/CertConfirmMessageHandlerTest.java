package com.czertainly.core.service.cmp.message.handler;

import com.czertainly.api.clients.cryptography.CryptographicOperationsApiClient;
import com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.cryptography.operations.SignDataResponseDto;
import com.czertainly.api.model.connector.cryptography.operations.data.SignatureResponseData;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.interfaces.core.cmp.error.ImplFailureInfo;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.entity.cmp.CmpTransaction;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.provider.CzertainlyProvider;
import com.czertainly.core.provider.key.CzertainlyPrivateKey;
import com.czertainly.core.service.cmp.CmpEntityUtil;
import com.czertainly.core.service.cmp.CmpTestUtil;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.configurations.variants.Mobile3gppProfileContext;
import com.czertainly.core.service.cmp.message.CertificateKeyService;
import com.czertainly.core.service.cmp.message.CmpTransactionService;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIConfirmContent;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

@Disabled
@ExtendWith(MockitoExtension.class)
public class CertConfirmMessageHandlerTest {

    @InjectMocks
    private CertConfirmMessageHandler tested;

    @Mock private CertificateKeyService certificateKeyService;
    @Mock private CertificateRepository certificateRepository;
    @Mock private CmpTransactionService cmpTransactionService;
    @Mock private CryptographicOperationsApiClient cryptographicOperationsApiClient;
    @Mock private RaProfileRepository raProfileRepository;

    private X509CertificateHolder x509certificate;
    private final BigInteger serialNumber = BigInteger.valueOf(123456789);
    private RaProfile raProfile;
    private CmpProfile cmpProfile;
    private CryptographicKeyItem ckPrivateKey;

    @BeforeAll
    public static void beforeAll() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() throws Exception {
        KeyPair kp = CmpTestUtil.generateKeyPairEC();
        x509certificate = CmpTestUtil.makeV3Certificate(serialNumber, kp, "CN=Test", kp, "CN=Test");

        CryptographicKey key = CmpEntityUtil.createCryptographicKey();
        ckPrivateKey = CmpEntityUtil.createCryptographicKeyItem(key,
                UUID.fromString("bb016fae-79b7-4284-9e77-950648dd9d26"),
                KeyType.PRIVATE_KEY,
                KeyAlgorithm.ECDSA,
                "7d903217b49fcf947f9b45ba239d4236b99fb75baf7ede08ce53a55c06678f1e");
        Set<CryptographicKeyItem> items = new HashSet<>();
        items.add((ckPrivateKey));
        key.setItems(items);

        Certificate certificateSig = CmpEntityUtil.createCertificate(
                new BigInteger(10, new SecureRandom()),
                CertificateState.ISSUED,
                CmpEntityUtil.createCertContent(
                    "20bfa83ea6a554a92313e62e7f897e71d8fd7406f0a80872defcce755245a63b",
                    "MIIEcjCCAlqgAwIBAgIUSRfTNEXeaZ+rtyTnaGLwRvzKv40wDQYJKoZIhvcNAQELBQAwQDEgMB4GA1UEAwwXRGVtb0NsaWVudFN1YkNBXzIzMDdSU0ExHDAaBgNVBAoMEzNLZXkgQ29tcGFueSBzLnIuby4wHhcNMjQwNDI5MTMwMTM2WhcNMjYwNDI5MTMwMTM1WjAcMRowGAYDVQQDDBF0ZXN0Y21wY2xpZW50Y2VydDB2MBAGByqGSM49AgEGBSuBBAAiA2IABAuHVkX5et+TLQ5yoHrU2j22IpoDPUFo7c+t01iXFjPXPGf3q5MDwAOp7y79QyXvDgzSo56NTrVzDg9EDSWwjAdVl2fj06QoMLXq7APSc3B15Gvw+pn0ME5Vkfw5T4DcL6OCATQwggEwMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUlW9WiT+pb/3A1zDBt5df5ixKrx0wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzAChjxodHRwOi8vcGtpLjNrZXkuY29tcGFueS9jYXMvZGVtby9kZW1vY2xpZW50c3ViY2FfMjMwN3JzYS5jcnQwEQYDVR0gBAowCDAGBgRVHSAAMBMGA1UdJQQMMAoGCCsGAQUFBwMCME4GA1UdHwRHMEUwQ6BBoD+GPWh0dHA6Ly9wa2kuM2tleS5jb21wYW55L2NybHMvZGVtby9kZW1vY2xpZW50c3ViY2FfMjMwN3JzYS5jcmwwHQYDVR0OBBYEFGHmdF5qP/gtNmU/iIT4N22jQbiJMA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0BAQsFAAOCAgEA03P8vQpq8wUB6bKpBtS43U+/T/wYUG1tq+2N0G16lZpXgFRAiBOe9ZrUov4iW+gIb8rRNmVcqgaeQtYn57AkC5oQp6tT1FdrEtx71B9EaMaSrGJwLfXypzEYyco4PBmHTadNJimFcIDA25Gp5hAHWDj6GeBUffUOb4PTR+ACBnHi/ApUxRPYCuqeeZZguOIlfy796SWSruCQN+zBQGjKpuCy795eSmaSfjl2h63uOzb+ulLhulHilWi9pk7nGTIbWd1m0LlLrhJQZcesMSlEx7yIkrrz5xCI1/rGu9BnpH5LH1b7TVExtsN3sZmeI10XTlVSLVt0WJTWB71O03QHSi+Fgb28msts2sZ6HSH2zyCxbtvqCZ4aXIfAKh9Cmg5xy6vG9isMtAHCK9m7fKDSnZ57qp6O2Et+zjEbQvOHdu8RHIbQIwHEdAEEUsMDKG7C+DrcZ+2AhK9fm2ToZX3Nt9t3H9BSnFKLfbpsXZsICftrlIFXoVSP+K3/DfLIF8gQQKLxdAiKnUJnGrnMQmy7moBo8LfMkA0MHLlKWwVvUHvNyv5cnhU4J2GSyC8T5aYVD1x/udv+B5xrjSbfbwLsWE2qC6XqThWcypJaSQBM2nzNi78Qnu/HLGsHPfiRBA4wqpG9gZ3qw3BT9nvNI452REqA6WNy4mzEbgpOp0WQkhE="
                ),
                key
        );

        raProfile = raProfileRepository.save(CmpEntityUtil.createRaProfile());
        cmpProfile = CmpEntityUtil.createCmpProfile(
                raProfile, certificateSig);
    }

    @Test
    public void test_handleOk() throws Exception {
        // -- WHEN --
        String trxId = "999";
        PKIBody body = CmpTestUtil.createCertConfBody(x509certificate, serialNumber);
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage(
                trxId,
                CmpTestUtil.generateKeyPairEC().getPrivate(),
                body)
                .toASN1Structure();
        ConfigurationContext configuration = new Mobile3gppProfileContext(
                cmpProfile, raProfile, request, certificateKeyService,
                null, null);

        // -- GIVEN
        given(certificateRepository.findByFingerprint(any()))
                .willReturn(Optional.of(new Certificate()));
        given(cmpTransactionService.findByTransactionIdAndFingerprint(any(), any()))
                .willReturn(Optional.of(new CmpTransaction()));
        given(certificateKeyService.getPrivateKey(any()))
                .willReturn(new CzertainlyPrivateKey(
                        null,
                        ckPrivateKey.getKeyReferenceUuid().toString(),
                        new ConnectorDto(),
                        KeyAlgorithm.ECDSA.getLabel()));
        given(certificateKeyService.getProvider(any(), any())).
                willReturn(CzertainlyProvider.getInstance(cmpProfile.getName(),
                        true, cryptographicOperationsApiClient));
        SignDataResponseDto singData = new SignDataResponseDto();
        SignatureResponseData singDataRsp = new SignatureResponseData();
        singDataRsp.setData("test".getBytes());
        singData.setSignatures(List.of(singDataRsp));
        given(cryptographicOperationsApiClient.signData(any(), any(), any(), any()))
                .willReturn(singData);

        // -- THEN
        PKIMessage response = tested.handle(request, configuration);
        assertEquals(PKIBody.TYPE_CONFIRM, response.getBody().getType());
        assertEquals(new DEROctetString(trxId.getBytes()).toString(),
                response.getHeader().getTransactionID().toString());
        Assertions.assertInstanceOf(PKIConfirmContent.class, response.getBody().getContent());
    }

    @Test
    public void test_handleRelatedCertificateBySerialNumberNotFound() throws Exception {
        // -- WHEN --
        String expectedTrxId = "999";
        PKIBody body = CmpTestUtil.createCertConfBody(x509certificate, serialNumber);
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage(
                        expectedTrxId,
                        CmpTestUtil.generateKeyPairEC().getPrivate(),
                        body)
                .toASN1Structure();
        ConfigurationContext configuration = new Mobile3gppProfileContext(
                new CmpProfile(), raProfile, request, certificateKeyService,
                null, null);

        // -- GIVEN
        given(certificateRepository.findByFingerprint(any())).willReturn(Optional.empty());

        // -- THEN
        CmpProcessingException response = assertThrows(
                CmpProcessingException.class, () -> tested.handle(request, configuration));
        assertEquals(PKIFailureInfo.badCertId, response.getFailureInfo());
        assertEquals(response.getImplFailureInfo(), ImplFailureInfo.CMPHANCERTCONF001);
    }

    @Test
    public void test_handleRelatedTransactionNotFound() throws Exception {
        // -- WHEN --
        String trxId = "999";
        PKIBody body = CmpTestUtil.createCertConfBody(x509certificate, serialNumber);
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage(
                        trxId,
                        CmpTestUtil.generateKeyPairEC().getPrivate(),
                        body)
                .toASN1Structure();
        ConfigurationContext configuration = new Mobile3gppProfileContext(
                new CmpProfile(), raProfile, request, certificateKeyService,
                null, null);

        // -- GIVEN
        given(certificateRepository.findByFingerprint(any())).willReturn(Optional.of(new Certificate()));

        // -- THEN
        CmpProcessingException response = assertThrows(
                CmpProcessingException.class, () -> tested.handle(request, configuration));
        assertEquals(PKIFailureInfo.badRequest, response.getFailureInfo());
        assertEquals(response.getImplFailureInfo(), ImplFailureInfo.CMPHANCERTCONF002);
    }

}
