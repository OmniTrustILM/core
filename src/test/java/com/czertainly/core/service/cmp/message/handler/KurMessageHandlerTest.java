package com.czertainly.core.service.cmp.message.handler;

import com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.v2.ClientCertificateDataResponseDto;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.service.cmp.CmpEntityUtil;
import com.czertainly.core.service.cmp.CmpTestUtil;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.configurations.variants.Mobile3gppProfileContext;
import com.czertainly.core.service.cmp.message.CertificateKeyService;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.CertificateUtil;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
public class KurMessageHandlerTest {

    @InjectMocks
    private CrmfKurMessageHandler tested;

    @Mock private CertificateRepository certificateRepository;
    @Mock private ClientOperationService clientOperationService;
    @Mock private CertificateKeyService certificateKeyService;
    @Mock private RaProfileRepository raProfileRepository;

    private RaProfile raProfile;
    private CmpProfile cmpProfile;
    private CryptographicKeyItem ckPrivateKey;
    private X509Certificate x509Certificate;
    private Certificate issuedCertificated;

    @BeforeAll
    public static void beforeAll() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() throws Exception {
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

        // The mocked raProfileRepository returns null on save() unless stubbed; build the
        // RA profile directly so the test fixture is fully populated.
        raProfile = CmpEntityUtil.createRaProfile();
        cmpProfile = CmpEntityUtil.createCmpProfile(
                raProfile, certificateSig);

        String contentOfIssuedCert = "MIIFITCCAwmgAwIBAgIUWOYu4x4SR3+uoFbQXDgFk4tIm7MwDQYJKoZIhvcNAQELBQAwQDEgMB4GA1UEAwwXRGVtb0NsaWVudFN1YkNBXzIzMDdSU0ExHDAaBgNVBAoMEzNLZXkgQ29tcGFueSBzLnIuby4wHhcNMjQwNTE1MTYzNTA1WhcNMjYwNTE1MTYzNTA0WjAdMRswGQYDVQQDDBJjbXAtdGVzdC1kZXYuaXIuY3owggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIrii/N6zI35rtw6sYmApohhNqOXRa8ktsqDPROdzdNc55aBVyTQFvf0z1XRi26l4GhsUv3KpLVTLV3vrCXtOTAeZccQgNqfKqDIVByjzWxGxFMuiTwpToB+a/CqXblaavTlyrv9varnxBEDjXK7H5iA4U+HxhM+WWidcSstnqGG8CnTmWS9cnj163zF01JzQANuIXKQ1CvJkHaMidbj5n5+w/nU/73BZEhnKivbOw3WWgVlV7fnR325FCF25J4AzJ2YyXo0Xu95cH0psjX0DM/ZroV+geiPZgGUp8cszkNYJMg5vHXSIQnYDDhDyiACy0QUqpxmK2iZdAqpTeI2W7AgMBAAGjggE0MIIBMDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFJVvVok/qW/9wNcwwbeXX+YsSq8dMFgGCCsGAQUFBwEBBEwwSjBIBggrBgEFBQcwAoY8aHR0cDovL3BraS4za2V5LmNvbXBhbnkvY2FzL2RlbW8vZGVtb2NsaWVudHN1YmNhXzIzMDdyc2EuY3J0MBEGA1UdIAQKMAgwBgYEVR0gADATBgNVHSUEDDAKBggrBgEFBQcDAjBOBgNVHR8ERzBFMEOgQaA/hj1odHRwOi8vcGtpLjNrZXkuY29tcGFueS9jcmxzL2RlbW8vZGVtb2NsaWVudHN1YmNhXzIzMDdyc2EuY3JsMB0GA1UdDgQWBBSzr9nhVund/xU3Zg5Pfc0taDDc/DAOBgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQELBQADggIBAMh4GZJmz3lGiLT89RaTBRVrkOY3+g6Wz/wCi/TcAqnEmz72g+rP2aMOMWL87KhlU7A18liDh5F0EK+yW8zyJx8ZYCLqzvw1fO3ijzFZ/HcNr9eymu/1csP8mCk+CFWgezGsg+jhBJICFM8tgAUm4HOZgsjy3oFLNXhIUBfATrSMMnAtYWoC7zXrseSNvVYPBvwCMzUyC0liMVLedxHgMYiIO1LuP1C9HjMk82QtI9rJjf67YoArpdJMue+QjwwYfgCQap5ZHa7fWdnrNxSneT1F4hxka5zI6BL2JNl0AWqvrgfKITzpNHg7t0QR36zBOleGUeGTflxQpkB1ibtHhaqlb6aN/Qw9K+m/bLVJO5rbCCImyXXTzTY06vzBwoygAYQP6CpRaD7Oq15VTJwAsrxFintOaX+ZXjeLSc0BtprJPU12+48yX27846R13u8y0kD5cvDsb/ukqTg2pNrdl7jAYBnG0BK0CLnRNluY/AV55PVsEOo9ymqOqHjznbhKu8bUtQWWu6lr2Vick7ACvyeRc50aBBTCMarty4t3mAc/g/odiP8Qb0Y8G2fCbMJiau5VQA53tJb61o+ph4zJAmCaW0Drnbws/OIVF1ZTnjb4m0zdWtvfM6hKpxJ/8jckOXU35m5woLgAbzEbOz2xLfYrmWQmLiWGuQ5ttUW8vYY5";
        x509Certificate = CertificateUtil.parseCertificate(contentOfIssuedCert);
        issuedCertificated = CmpEntityUtil.createCertificate(
                CertificateState.ISSUED,
                CmpEntityUtil.createCertContent(
                                CertificateUtil.getThumbprint(x509Certificate),
                                contentOfIssuedCert),
                x509Certificate.getSerialNumber());
    }

    @Test
    public void test_handleOk() throws Exception {
        // -- WHEN --
        String trxId= "779";
        PKIMessage request = CmpTestUtil.createKur(
                        trxId,
                        x509Certificate.getSerialNumber(),
                        CmpTestUtil.generateKeyPairEC())
                .toASN1Structure();
        ConfigurationContext configuration = new Mobile3gppProfileContext(
                cmpProfile, raProfile, request, certificateKeyService,
                null, null);

        // -- GIVEN
        given(certificateRepository.findBySerialNumberIgnoreCase(any()))
                .willReturn(Optional.of(issuedCertificated));
        given(clientOperationService.rekeyCertificate(any(), any(), any(), any()))
                .willReturn(new ClientCertificateDataResponseDto());

        // -- THEN
        ClientCertificateDataResponseDto response = tested.handle(request, configuration);
        assertNotNull(response);
    }

    @Test
    public void test_handle_certificate_for_re_key_not_found() throws Exception {
        // -- WHEN --
        String trxId= "779";
        PKIMessage request = CmpTestUtil.createKur(
                        trxId,
                        x509Certificate.getSerialNumber(),
                        CmpTestUtil.generateKeyPairEC())
                .toASN1Structure();
        ConfigurationContext configuration = new Mobile3gppProfileContext(
                cmpProfile, raProfile, request, certificateKeyService,
                null, null);

        // -- GIVEN
        given(certificateRepository.findBySerialNumberIgnoreCase(any()))
                .willReturn(Optional.empty());

        // -- THEN
        CmpProcessingException response = assertThrows(
                CmpProcessingException.class, () -> tested.handle(request, configuration));
        // RFC 4210 §3.2.7: badCertId is the specific failureInfo for "no certificate could be
        // found matching the provided criteria". The handler returns this instead of the
        // generic badRequest.
        assertEquals(PKIFailureInfo.badCertId, response.getFailureInfo());
        assertTrue(response.getMessage().contains(new DEROctetString(trxId.getBytes()).toString()));
        assertTrue(response.getMessage().contains("current certificate is not found in inventory"));
    }


    @Test
    public void test_handle_certificate_with_corrupted_content() throws Exception {
        // -- WHEN --
        String trxId= "779";
        PKIMessage request = CmpTestUtil.createKur(
                        trxId,
                        x509Certificate.getSerialNumber(),
                        CmpTestUtil.generateKeyPairEC())
                .toASN1Structure();
        ConfigurationContext configuration = new Mobile3gppProfileContext(
                cmpProfile, raProfile, request, certificateKeyService,
                null, null);

        // -- GIVEN
        issuedCertificated.getCertificateContent().setContent("");//corrupted content
        given(certificateRepository.findBySerialNumberIgnoreCase(any()))
                .willReturn(Optional.of(issuedCertificated));

        // -- THEN
        CmpProcessingException response = assertThrows(
                CmpProcessingException.class, () -> tested.handle(request, configuration));
        assertEquals(PKIFailureInfo.badDataFormat, response.getFailureInfo());
        assertTrue(response.getMessage().contains(new DEROctetString(trxId.getBytes()).toString()));
        assertTrue(response.getMessage().contains("current certificate (in database) cannot parsed"));
    }


}
