package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.certificate.UploadCertificateRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.core.authority.CertificateRevocationReason;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.raprofile.RaProfileCertificateValidationSettingsUpdateDto;
import com.czertainly.api.model.core.settings.CertificateSettingsUpdateDto;
import com.czertainly.api.model.core.settings.CertificateValidationSettingsUpdateDto;
import com.czertainly.api.model.core.settings.PlatformSettingsUpdateDto;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.CertificateTestUtil;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;

@SpringBootTest
@Transactional
@Rollback
public class CertificateValidationTest extends BaseSpringBootTest {

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private CrlService crlService;

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private CrlRepository crlRepository;

    @Autowired
    private CrlEntryRepository crlEntryRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private SettingService settingService;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    private Certificate certificate;

    private Certificate caCertificate;

    private Certificate chainIncompleteCertificate;

    private Certificate chainCompleteCertificate;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() throws GeneralSecurityException, IOException, com.czertainly.api.exception.CertificateException {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());
        InputStream keyStoreStream = CertificateServiceTest.class.getClassLoader().getResourceAsStream("client1.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStoreStream, "123456".toCharArray());

        X509Certificate x509Cert = (X509Certificate) keyStore.getCertificate("1");

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent(Base64.getEncoder().encodeToString(x509Cert.getEncoded()));
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCertificate");
        certificate.setSerialNumber("123456789");
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateType(CertificateType.X509);
        certificate.setNotBefore(new Date());
        certificate.setNotAfter(new Date());
        certificate.setCertificateContent(certificateContent);
        certificate = certificateRepository.save(certificate);

        String caCertificateContent = "MIIFyzCCA7OgAwIBAgIUOymQEJz0e6+2cDE/" + "1Z76gPbY0cAwDQYJKoZIhvcNAQELBQAwOzEbMBkGA1UEAwwSRGVtb1Jvb3RDQ" + "V8yMzA3UlNBMRwwGgYDVQQKDBMzS2V5IENvbXBhbnkgcy5yLm8uMCAXDTIzMDcx" + "OTExMTIwOFoYDzIwNTMwNzExMTExMjA3WjA7MRswGQYDVQQDDBJEZW1vUm9vdENBX" + "zIzMDdSU0ExHDAaBgNVBAoMEzNLZXkgQ29tcGFueSBzLnIuby4wggIiMA0GCSqGSIb3D" + "QEBAQUAA4ICDwAwggIKAoICAQCsbi+SUia7Hlp4DmR6MzJrBwIKh1Bq5vP64RcmsYch4" + "4Xa2bCRv5oDW57Hx9uy8cZpWI/7x4U5m7B/P1/FQG7SQ5u7ATvn6cbrZthaM9NYRZLY3z6" + "wRl2SQY0SUDWQyu2vkc2PxYy7qzz8r8s7T7vgDn9ozq/ODAZxYnfDGzdSLKay1ZVzNs7GNhk1Y" + "2RDA1JQXehi6avD+xaKH61YeO96sPpIGBOsbyvoQ3qZjCVPGRgXuXwJuqaxGV1QKIDPGCpKV" + "T7wy+edSh3XlEixW9GnLIQkTS/WiFYEO4B6DbZJ+WFU+djIAHzQwFHx1WYqfm9ok9QEzi2" + "jyUEafKtjDv++O8giHpRaMDvOiRRZPrHRBmCjbFmktB83VDTDyhiL+tuAUDBPDdEifWgXa" + "ikEsC2tA9sbrfUyByQCGhNXj8u8acNt0UPRGXC18uAmoCM4qkq4x0DaplnOwG8Cqi0IgAyLO" + "ZSNb/pXmfnvQxM3yyQ/kQAV3u69FX6ExkcoMnDi8ntfqMPAEK6tJGShgB27rEVhWJc9+" + "IhW0f/mFbSJicUpeUeao02lTkSUn0r15hAz9rUVnjz6a+aSUS4yTW9nigJuy7Fi5N5fq" + "wzDdIWkWIg3dvzjcObsC5zHSf1a8qyi9E/RHfh1LneLA116IpMmTQpr2CNnWtQuwCKqJ" + "M30bDP/DQIDAQABo4HEMIHBMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUJMpCDu+q" + "xpE+0ar6E1h4KhZQRokwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vcGtpL" + "jNrZXkuY29tcGFueS9jYXMvZGVtby9kZW1vcm9vdGNhLmNydDARBgNVHSAECjAIMAYGBFUdI" + "AAwHQYDVR0OBBYEFCTKQg7vqsaRPtGq+hNYeCoWUEaJMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG" + "9w0BAQsFAAOCAgEAI0yAtaw0o8952LGD4gxZWskfun1bl92JvpJ5ydd9kQngE2zsWlLk470O3qM4hwa" + "+umEqUo6YkVK5tH1xDyggwHYS/LW92uBoPbvW+cMVZvpwBWR12lXQzAvmN5w5EcDS6s1WOjNAfR5ILtOW" + "Sd79cCOEUsOVl+JNKeFDdBFT4I1xir3F4C3bN1DmwgVVWKzpRmetS2Ds1zJsIfWlFoywQynEHQzxth" + "5EPQCc/KF4tjcEeNnYeHjBLm7iY70HCiOATzvT8bj/rJkVeUJLPGEikAY0YMQOEGHtF8UstDm+EGH4" + "4ON50FRFd++9nrZtnziDwrC0m6fMsjfBkk0G7coJqNSHvEr41AmCeWUX3cfT9TIm1qLecZpnW383Y0" + "Z67+YqOf8p8vx5dYZy+uqe+CrJMvvXk6O1ZVDMNuib3y0UY3PRpZ7FW5SCNKfyiSv2edp+OSmmDAkI" + "w55i6G/QVQyxq18LNgzFmZIXDysIV7hLlt5W54h86iTEHGNhm7Qsy+LFN3dq31oO11sVQBaUKjONUIK" + "gKuGrbAVmeDteGpBdQCv3fu3SY4BG74ryNkvotnAeMUaL/XhrvC9XOKeQbJ/tRLeE8rf4It8Par1Ruuu" + "bC5IL0ajdJ2e7X99Tt1Mqh48cQ2pFA3sVEif7h81+Y/i4UWraB/7pGxa/CehwrF8eIOI=";

        caCertificate = certificateService.createCertificate(caCertificateContent, CertificateType.X509);

        certificateRepository.save(caCertificate);

        String chainCertificateContent = "MIICjTCCAjOgAwIBAgIQf/NXf/Y8fKN+BkL4yLhikDAKBggqhkjOPQQDAjBQMSQwIgYDVQQLExtHbG9iYWxTaWduIEVDQyBSb290IENBIC0gUjQxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMjMxMjEzMDkwMDAwWhcNMjkwMjIwMTQwMDAwWjA7MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMQwwCgYDVQQDEwNXRTIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ1fh/yFO2QfeGeKjRDhsHVlugncN+eBMupyoZ5CwhNRorCdKS72b/u/SPXOPNL71QX4b7nylUlqAwwrC1dTqFRo4IBAjCB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHW+xHeuifZEN33PsWgfHRrr3DRZMB8GA1UdIwQYMBaAFFSwe61FuOJAf/sKbvu+M8k8o4TVMDYGCCsGAQUFBwEBBCowKDAmBggrBgEFBQcwAoYaaHR0cDovL2kucGtpLmdvb2cvZ3NyNC5jcnQwLQYDVR0fBCYwJDAioCCgHoYcaHR0cDovL2MucGtpLmdvb2cvci9nc3I0LmNybDATBgNVHSAEDDAKMAgGBmeBDAECATAKBggqhkjOPQQDAgNIADBFAiBbsQQLhG0VbSTee24xTExpfZjtvxSr0QUeF5ynbsLfsAIhALzHr/nsu7YViuT13ZNVPKTQ4UWHvxnqxJZRGRgNHE4w";
        chainIncompleteCertificate = certificateService.createCertificate(chainCertificateContent, CertificateType.X509);

        String chainCompleteCertificateContent = "MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAwWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cPR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdxsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8ZutmNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxgZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaAFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6WPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wlikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQzCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BImlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1OyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90IdshCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6ZvMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqXnLRbwHOoq7hHwg==";
        chainCompleteCertificate = certificateService.createCertificate(chainCompleteCertificateContent, CertificateType.X509);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }


    @Test
    void testValidateCertificate() throws NotFoundException, CertificateException {
        certificateService.validate(certificate);

        String result = certificate.getCertificateValidationResult();
        Assertions.assertNotNull(result);
        Assertions.assertTrue(StringUtils.isNotBlank(result));

        Map<CertificateValidationCheck, CertificateValidationCheckDto> resultMap = MetaDefinitions.deserializeValidation(result);
        Assertions.assertNotNull(resultMap);
        Assertions.assertFalse(resultMap.isEmpty());

        CertificateValidationCheckDto signatureVerification = resultMap.get(CertificateValidationCheck.CERTIFICATE_CHAIN);
        Assertions.assertNotNull(signatureVerification);
        Assertions.assertEquals(CertificateValidationStatus.INVALID, signatureVerification.getStatus());

        // check disabled RA profile validation
        var validationSettingsUpdateDto = new RaProfileCertificateValidationSettingsUpdateDto();
        validationSettingsUpdateDto.setEnabled(false);
        RaProfile raProfile = getRaProfile(validationSettingsUpdateDto);
        certificate.setRaProfile(raProfile);
        certificate = certificateRepository.save(certificate);
        CertificateValidationResultDto validationResult = certificateService.getCertificateValidationResult(certificate.getSecuredUuid());
        Assertions.assertEquals(CertificateValidationStatus.NOT_CHECKED, validationResult.getResultStatus());

        raProfile.setValidationEnabled(null);
        raProfile.setExpiringThreshold(null);
        raProfile.setValidationFrequency(null);
        raProfileRepository.save(raProfile);
        validationResult = certificateService.getCertificateValidationResult(certificate.getSecuredUuid());
        Assertions.assertEquals(CertificateValidationStatus.INVALID, validationResult.getResultStatus());

        // turn off validation on platform level
        var settingsUpdateDto = new PlatformSettingsUpdateDto();
        var certificateSettingsUpdateDto = new CertificateSettingsUpdateDto();
        var certificateValidationSettingsUpdateDto = new CertificateValidationSettingsUpdateDto();
        certificateValidationSettingsUpdateDto.setEnabled(false);
        certificateSettingsUpdateDto.setValidation(certificateValidationSettingsUpdateDto);
        settingsUpdateDto.setCertificates(certificateSettingsUpdateDto);
        settingService.updatePlatformSettings(settingsUpdateDto);

        validationResult = certificateService.getCertificateValidationResult(certificate.getSecuredUuid());
        Assertions.assertEquals(CertificateValidationStatus.NOT_CHECKED, validationResult.getResultStatus());

        // turn validation back on
        certificateSettingsUpdateDto.setValidation(new CertificateValidationSettingsUpdateDto());
        settingService.updatePlatformSettings(settingsUpdateDto);
    }

    @Test
    void testValidateHybridCertificate() throws InvalidAlgorithmParameterException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, OperatorCreationException, IOException {
        X509Certificate x509Certificate = CertificateTestUtil.createHybridCertificate();
        certificate.getCertificateContent().setContent(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));
        certificate.setHybridCertificate(true);
        certificateService.validate(certificate);
        Map<CertificateValidationCheck, CertificateValidationCheckDto> resultMap = MetaDefinitions.deserializeValidation(certificate.getCertificateValidationResult());
        Assertions.assertEquals(CertificateValidationStatus.VALID, resultMap.get(CertificateValidationCheck.CERTIFICATE_VALIDITY).getStatus());

        // Set issuer with different classic key and alt key to test signature not verified
        X509Certificate x509CertificateIssuer = CertificateTestUtil.createHybridCertificate();
        Certificate issuerCertificate = new Certificate();
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent(Base64.getEncoder().encodeToString(x509CertificateIssuer.getEncoded()));
        certificateContentRepository.save(certificateContent);
        issuerCertificate.setCertificateContent(certificateContent);
        certificateRepository.save(issuerCertificate);
        certificate.setIssuerCertificateUuid(issuerCertificate.getUuid());
        certificateRepository.save(certificate);
        certificateService.validate(certificate);
        resultMap = MetaDefinitions.deserializeValidation(certificate.getCertificateValidationResult());
        Assertions.assertEquals(CertificateValidationStatus.FAILED, resultMap.get(CertificateValidationCheck.SIGNATURE_VERIFICATION).getStatus());
        Assertions.assertEquals("Signature verification failed. Alternative signature verification failed.", resultMap.get(CertificateValidationCheck.SIGNATURE_VERIFICATION).getMessage());


    }

    @Test
    void testExpiringCertificate() throws CertificateException, NoSuchAlgorithmException, OperatorCreationException {

        LocalDate today = LocalDate.now();
        // Expiring according to platform settings with null RA Profile
        LocalDate expiringDate = today.plusDays(29);
        X509Certificate x509Certificate = createCertificateWithCustomNotAfter(Date.from(expiringDate.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        certificate.getCertificateContent().setContent(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));

        certificateService.validate(certificate);
        Map<CertificateValidationCheck, CertificateValidationCheckDto> resultMap = MetaDefinitions.deserializeValidation(certificate.getCertificateValidationResult());
        Assertions.assertEquals(CertificateValidationStatus.EXPIRING, resultMap.get(CertificateValidationCheck.CERTIFICATE_VALIDITY).getStatus());

        // Expiring according to platform settings with not null RA Profile, but null validation enabled
        certificate.setRaProfile(getRaProfile(new RaProfileCertificateValidationSettingsUpdateDto()));
        certificateService.validate(certificate);
        resultMap = MetaDefinitions.deserializeValidation(certificate.getCertificateValidationResult());
        Assertions.assertEquals(CertificateValidationStatus.EXPIRING, resultMap.get(CertificateValidationCheck.CERTIFICATE_VALIDITY).getStatus());

        // Expiring according to RA Profile settings
        RaProfileCertificateValidationSettingsUpdateDto validationSettingsUpdateDto = new RaProfileCertificateValidationSettingsUpdateDto();
        validationSettingsUpdateDto.setEnabled(true);
        validationSettingsUpdateDto.setExpiringThreshold(10);
        certificate.setRaProfile(getRaProfile(validationSettingsUpdateDto));

        // Certificate is not yet expiring
        certificateService.validate(certificate);
        resultMap = MetaDefinitions.deserializeValidation(certificate.getCertificateValidationResult());
        Assertions.assertEquals(CertificateValidationStatus.VALID, resultMap.get(CertificateValidationCheck.CERTIFICATE_VALIDITY).getStatus());

        // Certificate is expiring
        expiringDate = today.plusDays(9);
        x509Certificate = createCertificateWithCustomNotAfter(Date.from(expiringDate.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        certificate.getCertificateContent().setContent(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));
        certificateService.validate(certificate);
        resultMap = MetaDefinitions.deserializeValidation(certificate.getCertificateValidationResult());
        Assertions.assertEquals(CertificateValidationStatus.EXPIRING, resultMap.get(CertificateValidationCheck.CERTIFICATE_VALIDITY).getStatus());
    }

    private RaProfile getRaProfile(RaProfileCertificateValidationSettingsUpdateDto validationUpdateDto) {
        RaProfile raProfile = new RaProfile();
        raProfile.setEnabled(true);
        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setStatus("connected");
        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReferenceRepository.save(authorityInstanceReference);
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile.setValidationEnabled(validationUpdateDto.getEnabled());
        raProfile.setExpiringThreshold(validationUpdateDto.getExpiringThreshold());
        raProfileRepository.save(raProfile);
        return raProfile;
    }

    private X509Certificate createCertificateWithCustomNotAfter(Date notAfter) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Principal issuer = new X500Principal("CN=" + certificate.getIssuerDn());
        Date notBefore = new Date();
        BigInteger serialNumber = BigInteger.ONE;

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber, notBefore, notAfter, issuer, keyPair.getPublic()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certificateHolder);
    }

    @Test
    void testConstructingCertificateChainForSelfSignedCertificate() throws NotFoundException {
        CertificateChainResponseDto certificateChainResponseDto = certificateService.getCertificateChain(caCertificate.getSecuredUuid(), false);
        Assertions.assertEquals(0, certificateChainResponseDto.getCertificates().size());
        CertificateChainResponseDto certificateChainResponseDto2 = certificateService.getCertificateChain(caCertificate.getSecuredUuid(), true);
        Assertions.assertEquals(1, certificateChainResponseDto2.getCertificates().size());
    }

    @Test
    void testGetCertificateChain() throws NotFoundException {
        CertificateChainResponseDto certificateChainResponseDto = certificateService.getCertificateChain(chainIncompleteCertificate.getSecuredUuid(), false);
        Assertions.assertTrue(certificateChainResponseDto.isCompleteChain());
        CertificateChainResponseDto certificateChainCompleteResponseDto = certificateService.getCertificateChain(chainCompleteCertificate.getSecuredUuid(), false);
        Assertions.assertTrue(certificateChainCompleteResponseDto.isCompleteChain());
        List<CertificateDetailDto> certificates = certificateChainCompleteResponseDto.getCertificates();
        Assertions.assertEquals(chainCompleteCertificate.getIssuerDn(), certificates.get(certificates.size() - 1).getSubjectDn());
        Assertions.assertEquals(1, certificates.size());
        CertificateChainResponseDto certificateChainCompleteResponseDto2 = certificateService.getCertificateChain(chainCompleteCertificate.getSecuredUuid(), true);
        Assertions.assertEquals(2, certificateChainCompleteResponseDto2.getCertificates().size());
        Assertions.assertTrue(certificateChainCompleteResponseDto.isCompleteChain());
    }

    @Test
    void testDownloadCertificateChain() throws NotFoundException, CertificateException, CMSException, IOException {
        CertificateChainDownloadResponseDto certificateChainIncompletePEMDownloadResponseDto = certificateService.downloadCertificateChain(chainIncompleteCertificate.getSecuredUuid(), CertificateFormat.RAW, true, CertificateFormatEncoding.PEM);
        Assertions.assertEquals(2, getNumberOfCertificatesInPem(certificateChainIncompletePEMDownloadResponseDto.getContent()));
        Assertions.assertTrue(certificateChainIncompletePEMDownloadResponseDto.isCompleteChain());
        CertificateChainDownloadResponseDto certificateChainCompletePEMResponseDto = certificateService.downloadCertificateChain(chainCompleteCertificate.getSecuredUuid(), CertificateFormat.RAW, true, CertificateFormatEncoding.PEM);
        Assertions.assertTrue(certificateChainCompletePEMResponseDto.isCompleteChain());
        Assertions.assertEquals(2, getNumberOfCertificatesInPem(certificateChainCompletePEMResponseDto.getContent()));
        CertificateChainDownloadResponseDto certificateChainCompletePKCS7ResponseDto = certificateService.downloadCertificateChain(chainCompleteCertificate.getSecuredUuid(), CertificateFormat.PKCS7, true, CertificateFormatEncoding.PEM);
        Assertions.assertTrue(certificateChainCompletePKCS7ResponseDto.isCompleteChain());
        Assertions.assertEquals(2, getNumberOfCertificatesInPkcs7(certificateChainCompletePKCS7ResponseDto.getContent()));
        CertificateChainDownloadResponseDto certificateChainResponseDto = certificateService.downloadCertificateChain(chainCompleteCertificate.getSecuredUuid(), CertificateFormat.PKCS7, false, CertificateFormatEncoding.PEM);
        Assertions.assertTrue(certificateChainResponseDto.isCompleteChain());
        Assertions.assertEquals(1, getNumberOfCertificatesInPkcs7(certificateChainResponseDto.getContent()));

    }

    @Test
    void testOcspValidationCheck() throws Exception {
        var certificateChainInfo = CertificateGeneratorHelper.generateCertificateWithIssuer(KeyAlgorithm.RSA, "CN=Test-Ca", "CN=Test-EndEntity", "http://localhost:%d/ocsp".formatted(mockServer.port()));

        UploadCertificateRequestDto uploadDto = new UploadCertificateRequestDto();
        uploadDto.setCertificate(certificateChainInfo.getCaCertificateBase64Encoded());
        certificateService.upload(uploadDto, true);

        KeyPair ecdsaKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.ECDSA, null);
        X509Certificate ecdsaX509Certificate = CertificateGeneratorHelper.generateEndEntityCertificate(certificateChainInfo.getCaCertificateKeyPair(), certificateChainInfo.getCaCertificate(), ecdsaKeyPair, "CN=Test-EndEntity-ECDSA", null);
        uploadDto.setCertificate(Base64.getEncoder().encodeToString(ecdsaX509Certificate.getEncoded()));
        CertificateDetailDto certificateEcdsa = certificateService.upload(uploadDto, true);

        var validationResult = certificateService.getCertificateValidationResult(SecuredUUID.fromString(certificateEcdsa.getUuid()));
        Assertions.assertEquals(CertificateValidationStatus.NOT_CHECKED, validationResult.getValidationChecks().get(CertificateValidationCheck.OCSP_VERIFICATION).getStatus());

        uploadDto.setCertificate(certificateChainInfo.getEndEntityCertificateBase64Encoded());
        CertificateDetailDto certificateEndEntity = certificateService.upload(uploadDto, true);

        validationResult = certificateService.getCertificateValidationResult(SecuredUUID.fromString(certificateEndEntity.getUuid()));
        Assertions.assertEquals(CertificateValidationStatus.FAILED, validationResult.getValidationChecks().get(CertificateValidationCheck.OCSP_VERIFICATION).getStatus());

        OCSPResp ocspResp = CertificateGeneratorHelper.generateOCSPResponse(certificateChainInfo.getCaCertificate(), certificateChainInfo.getCaCertificateKeyPair().getPrivate(), certificateChainInfo.getEndEntityCertificate(), CertificateStatus.GOOD);
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/ocsp"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/ocsp-response")
                        .withBody(ocspResp.getEncoded())));


        validationResult = certificateService.getCertificateValidationResult(SecuredUUID.fromString(certificateEndEntity.getUuid()));
        Assertions.assertEquals(CertificateValidationStatus.VALID, validationResult.getValidationChecks().get(CertificateValidationCheck.OCSP_VERIFICATION).getStatus());

        mockServer.resetAll();
    }

    @Test
    void testCrlProcessing() throws GeneralSecurityException, OperatorCreationException, IOException, NotFoundException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair pair = keyPairGen.generateKeyPair();

        // prepare certs
        X509Certificate x509CaCertificate = CertificateUtil.getX509Certificate(caCertificate.getCertificateContent().getContent());

        List<String> crlUrls = List.of(mockServer.baseUrl() + "/crl1.crl", mockServer.baseUrl() + "/crl2.crl");
        X509Certificate certificateWithCrl = createSelfSignedCertificateWithCrl("testCrl", crlUrls, null, BigInteger.ONE);
        Certificate certificateWithCrlEntity = certificateService.createCertificateEntity(certificateWithCrl);
        certificateWithCrlEntity.setTrustedCa(true);
        certificateRepository.save(certificateWithCrlEntity);

        X509Certificate certificateWithDelta = createSelfSignedCertificateWithCrl("testCrlWithDelta", crlUrls, List.of(mockServer.baseUrl() + "/deltaCrl"), BigInteger.TWO);
        Certificate certificateWithCrlDeltaEntity = certificateService.createCertificateEntity(certificateWithDelta);
        certificateWithCrlDeltaEntity.setTrustedCa(true);
        certificateRepository.save(certificateWithCrlDeltaEntity);

        // Test no CRL available for existing URLs
        var validationResult = certificateService.getCertificateValidationResult(certificateWithCrlEntity.getSecuredUuid());
        Assertions.assertEquals(CertificateValidationStatus.FAILED, validationResult.getValidationChecks().get(CertificateValidationCheck.CRL_VERIFICATION).getStatus());

        // Test CRL without the end certificate and without delta
        X509CRL emptyX509Crl = createEmptyCRL(x509CaCertificate, pair.getPrivate());
        byte[] emptyX509CrlBytes = emptyX509Crl.getEncoded();
        stubCrlPoint("/crl1.crl", emptyX509CrlBytes);
        validationResult = certificateService.getCertificateValidationResult(certificateWithCrlEntity.getSecuredUuid());
        Assertions.assertEquals(CertificateValidationStatus.VALID, validationResult.getValidationChecks().get(CertificateValidationCheck.CRL_VERIFICATION).getStatus());
        UUID crlUuid = crlService.getCurrentCrl(certificateWithCrl, certificateWithCrl);
        Assertions.assertNull(crlService.findCrlEntryForCertificate(certificateWithCrl.getSerialNumber().toString(16), crlUuid));

        crlRepository.deleteAll();
        crlRepository.findAll();
        // Test updating existing CRL
        Crl oldCrl = new Crl();
        oldCrl.setNextUpdate(new Date());
        oldCrl.setCrlNumber(String.valueOf(1));
        oldCrl.setSerialNumber("1");
        oldCrl.setCrlIssuerDn("2.5.4.3=testCrl");
        oldCrl.setIssuerDn("2.5.4.3=testCrl");

        crlRepository.save(oldCrl);
        CrlEntry crlEntry = new CrlEntry();
        CrlEntryId crlEntryId = new CrlEntryId();
        crlEntryId.setSerialNumber("2");
        crlEntryId.setCrlUuid(oldCrl.getUuid());
        crlEntry.setId(crlEntryId);
        crlEntry.setCrl(oldCrl);
        crlEntry.setRevocationDate(new Date());
        crlEntry.setRevocationReason(CertificateRevocationReason.CERTIFICATE_HOLD);
        oldCrl.setCrlEntries(List.of(crlEntry));
        certificateService.getCertificateValidationResult(certificateWithCrlEntity.getSecuredUuid());
        Assertions.assertTrue(crlEntryRepository.findById(crlEntryId).isEmpty());
        crlRepository.deleteAll();

        // Test CRL with revoked certificate and without delta and with one invalid CRL distribution point
        mockServer.removeStubMapping(mockServer.getStubMappings().getFirst());
        Map<BigInteger, Integer> crlEntries = new HashMap<>();
        crlEntries.put(certificateWithCrl.getSerialNumber(), CRLReason.keyCompromise);
        X509CRL x509CrlRevokedCert = addRevocationToCRL(pair.getPrivate(), "SHA256WithRSAEncryption", emptyX509Crl, crlEntries);
        stubCrlPoint("/crl2.crl", x509CrlRevokedCert.getEncoded());
        validationResult = certificateService.getCertificateValidationResult(certificateWithCrlEntity.getSecuredUuid());
        Assertions.assertEquals(CertificateValidationStatus.REVOKED, validationResult.getValidationChecks().get(CertificateValidationCheck.CRL_VERIFICATION).getStatus());
        UUID crlWithRevokedUuid = crlService.getCurrentCrl(certificateWithCrl, certificateWithCrl);
        Assertions.assertNotNull(crlService.findCrlEntryForCertificate(certificateWithCrl.getSerialNumber().toString(16), crlWithRevokedUuid));

        // Test properly set deltaCrl
        Crl crlWithRevoked = crlRepository.findByUuid(SecuredUUID.fromUUID(crlWithRevokedUuid)).get();
        X509CRL deltaCrl = createEmptyDeltaCRL(x509CaCertificate.getSubjectX500Principal(), pair.getPrivate(), BigInteger.valueOf(Integer.parseInt(crlWithRevoked.getCrlNumber())), BigInteger.ONE);
        stubCrlPoint("/deltaCrl", deltaCrl.getEncoded());
        UUID crlWithDeltaUuid = crlService.getCurrentCrl(certificateWithDelta, certificateWithDelta);
        Crl crlWithDelta = crlRepository.findByUuid(SecuredUUID.fromUUID(crlWithDeltaUuid)).get();
        Assertions.assertNotNull(crlWithDelta.getCrlNumberDelta());
        Assertions.assertNotNull(crlWithDelta.getNextUpdateDelta());

        // Test improperly set deltaCrl because of CRL numbers
        crlRepository.delete(crlWithDelta);
        X509CRL deltaCrl2 = createEmptyDeltaCRL(x509CaCertificate.getSubjectX500Principal(), pair.getPrivate(), BigInteger.valueOf(3), BigInteger.TWO);
        stubCrlPoint("/deltaCrl", deltaCrl2.getEncoded());
        validationResult = certificateService.getCertificateValidationResult(certificateWithCrlDeltaEntity.getSecuredUuid());
        Assertions.assertEquals(CertificateValidationStatus.FAILED, validationResult.getValidationChecks().get(CertificateValidationCheck.CRL_VERIFICATION).getStatus());
        Assertions.assertThrows(ValidationException.class, () -> crlService.getCurrentCrl(certificateWithDelta, certificateWithDelta));

        // Test improperly set deltaCrl
        crlRepository.deleteAll();
        X509CRL deltaCrlIssuerNotMatching = createEmptyDeltaCRL(certificateWithDelta.getIssuerX500Principal(), pair.getPrivate(), BigInteger.valueOf(Integer.parseInt(crlWithRevoked.getCrlNumber())), BigInteger.TWO);
        stubCrlPoint("/deltaCrl", deltaCrlIssuerNotMatching.getEncoded());
        validationResult = certificateService.getCertificateValidationResult(certificateWithCrlDeltaEntity.getSecuredUuid());
        Assertions.assertEquals(CertificateValidationStatus.FAILED, validationResult.getValidationChecks().get(CertificateValidationCheck.CRL_VERIFICATION).getStatus());
        Assertions.assertThrows(ValidationException.class, () -> crlService.getCurrentCrl(certificateWithDelta, certificateWithDelta));

        // Test deltaCrl with revoked cert and with one certificate to remove from CRL entries
        crlRepository.deleteAll();
        X509CRL deltaCrl3 = createEmptyDeltaCRL(x509CaCertificate.getSubjectX500Principal(), pair.getPrivate(), BigInteger.valueOf(Integer.parseInt(crlWithRevoked.getCrlNumber())), BigInteger.TWO);
        crlEntries.put(BigInteger.valueOf(123), CRLReason.removeFromCRL);
        crlEntries.put(BigInteger.valueOf(1234), CRLReason.keyCompromise);
        crlEntries.put(BigInteger.TWO, CRLReason.cACompromise);
        X509CRL deltaCrlWithRevoked = addRevocationToCRL(pair.getPrivate(), "SHA256WithRSAEncryption", deltaCrl3, crlEntries);

        crlEntries.remove(x509CaCertificate.getSerialNumber());
        crlEntries.remove(BigInteger.TWO);
        crlEntries.put(BigInteger.valueOf(123), CRLReason.keyCompromise);
        crlEntries.put(BigInteger.valueOf(1234), CRLReason.cACompromise);
        X509CRL crlWithCertificateToRemove = addRevocationToCRL(pair.getPrivate(), "SHA256WithRSAEncryption", emptyX509Crl, crlEntries);

        stubCrlPoint("/crl1.crl", crlWithCertificateToRemove.getEncoded());
        stubCrlPoint("/deltaCrl", deltaCrlWithRevoked.getEncoded());
        validationResult = certificateService.getCertificateValidationResult(certificateWithCrlDeltaEntity.getSecuredUuid());
        Assertions.assertEquals(CertificateValidationStatus.REVOKED, validationResult.getValidationChecks().get(CertificateValidationCheck.CRL_VERIFICATION).getStatus());
        UUID crlWithDelta2Uuid = crlService.getCurrentCrl(certificateWithDelta, certificateWithDelta);
        Assertions.assertNotNull(crlService.findCrlEntryForCertificate(certificateWithDelta.getSerialNumber().toString(16), crlWithDelta2Uuid));
        Assertions.assertNull(crlService.findCrlEntryForCertificate(BigInteger.valueOf(123).toString(16), crlWithRevokedUuid));
        CrlEntryId crlEntryId1 = new CrlEntryId();
        crlEntryId1.setCrlUuid(crlWithDelta2Uuid);
        crlEntryId1.setSerialNumber(BigInteger.valueOf(1234).toString(16));
        Assertions.assertEquals(CertificateRevocationReason.KEY_COMPROMISE, crlEntryRepository.findById(crlEntryId1).get().getRevocationReason());
    }


    private void stubCrlPoint(String urlPart, byte[] body) {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching(urlPart))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withHeader("Set-Cookie", "session_id=91837492837")
                        .withHeader("Set-Cookie", "split_test_group=B")
                        .withHeader("Cache-Control", "no-cache")
                        .withBody(body)));
    }

    private X509Certificate createSelfSignedCertificateWithCrl(String commonName, List<String> crlUrls, List<String> deltaCrlUrls, BigInteger serialNumber) throws CertIOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair pair = keyPairGen.generateKeyPair();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());

        X500Name x500Name = new X500Name("CN=" + commonName);
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(x500Name, serialNumber, new Date(0), new Date(Long.MAX_VALUE), x500Name, subjectPublicKeyInfo);
        CRLDistPoint crlDistPoint = new CRLDistPoint(createCrlDistributionPoints(crlUrls));
        certificateBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);
        if (deltaCrlUrls != null) {
            CRLDistPoint deltaCrlDistPoint = new CRLDistPoint(createCrlDistributionPoints(deltaCrlUrls));
            certificateBuilder.addExtension(Extension.freshestCRL, false, deltaCrlDistPoint);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .build(pair.getPrivate());
        X509CertificateHolder holder = certificateBuilder.build(signer);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(new BouncyCastleProvider());
        return converter.getCertificate(holder);
    }


    private int getNumberOfCertificatesInPkcs7(String content) throws CMSException {
        String pkcs7Data = new String(Base64.getDecoder().decode(content));
        pkcs7Data = pkcs7Data.replace("-----BEGIN PKCS7-----", "").replace("-----END PKCS7-----", "").replaceAll("\\s", "");
        CMSSignedData signedData = new CMSSignedData(Base64.getDecoder().decode(pkcs7Data));
        Store<X509CertificateHolder> certificates = signedData.getCertificates();
        Collection<X509CertificateHolder> certCollection = certificates.getMatches(null);
        return certCollection.size();
    }

    private int getNumberOfCertificatesInPem(String content) throws IOException {
        byte[] pemCertificateChainBytes = Base64.getDecoder().decode(content);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pemCertificateChainBytes);
        PemReader reader = new PemReader(new InputStreamReader(inputStream));
        List<PemObject> pemObjects = new ArrayList<>();
        PemObject pemObject;
        while ((pemObject = reader.readPemObject()) != null) {
            pemObjects.add(pemObject);
        }
        reader.close();
        return pemObjects.size();
    }

    public static Date calculateDate(int hoursInFuture) {
        long secs = System.currentTimeMillis() / 1000;
        return new Date((secs + ((long) hoursInFuture * 60 * 60)) * 1000);
    }

    private X509CRL createEmptyCRL(X509Certificate caCert, PrivateKey caKey) throws CRLException, OperatorCreationException, CertIOException {
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded()), calculateDate(0));
        crlGen.setNextUpdate(calculateDate(24 * 7));
        crlGen.addExtension(Extension.cRLNumber,
                false,
                new CRLNumber(BigInteger.TWO));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(caKey);

        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
        return converter.getCRL(crlGen.build(signer));
    }

    private X509CRL createEmptyDeltaCRL(X500Principal issuerDnPrincipal, PrivateKey caKey, BigInteger deltaCrlIndicator, BigInteger deltaCrlNumber) throws CRLException, OperatorCreationException, CertIOException {
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(X500Name.getInstance(issuerDnPrincipal.getEncoded()), calculateDate(0));
        crlGen.setNextUpdate(calculateDate(24 * 7));
        crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(deltaCrlNumber));
        crlGen.addExtension(Extension.deltaCRLIndicator, false, new CRLNumber(deltaCrlIndicator));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(caKey);

        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
        return converter.getCRL(crlGen.build(signer));
    }

    public X509CRL addRevocationToCRL(PrivateKey caKey, String sigAlg, X509CRL crl, Map<BigInteger, Integer> serialNumberAndRevocationReasonMap) throws IOException, GeneralSecurityException, OperatorCreationException {
        JcaX509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(crl);
        crlGen.setNextUpdate(calculateDate(24 * 7));

        // add revocations
        for (BigInteger serialNumber : serialNumberAndRevocationReasonMap.keySet()) {
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen.addExtension(Extension.reasonCode, false, org.bouncycastle.asn1.x509.CRLReason.lookup(serialNumberAndRevocationReasonMap.get(serialNumber)));
            crlGen.addCRLEntry(serialNumber,
                    new Date(), extGen.generate());
        }

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(caKey);
        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");

        return converter.getCRL(crlGen.build(signer));
    }

    private DistributionPoint[] createCrlDistributionPoints(List<String> urls) {
        List<DistributionPoint> list = new ArrayList<>();
        for (String url : urls) {
            DERIA5String deria5String = new DERIA5String(url);
            GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, deria5String);
            DistributionPointName distributionPointName = new DistributionPointName(new GeneralNames(generalName));
            list.add(new DistributionPoint(distributionPointName, null, null));
        }
        return list.toArray(new DistributionPoint[0]);
    }

    @Test
    void testGetCertificateChainNullContent() throws NotFoundException {
        Certificate certNoContent = new Certificate();
        certNoContent.setSubjectDn("CN=NullContentCert");
        certNoContent.setIssuerDn("CN=SomeIssuer");
        certNoContent.setSerialNumber("000000");
        certNoContent.setState(CertificateState.REQUESTED);
        certNoContent.setCertificateType(CertificateType.X509);
        certNoContent.setNotBefore(new Date());
        certNoContent.setNotAfter(new Date());
        // intentionally no certificateContent set → null
        certNoContent = certificateRepository.save(certNoContent);

        CertificateChainResponseDto withoutEnd = certificateService.getCertificateChain(certNoContent.getSecuredUuid(), false);
        Assertions.assertTrue(withoutEnd.getCertificates() == null || withoutEnd.getCertificates().isEmpty());
        Assertions.assertFalse(withoutEnd.isCompleteChain());

        CertificateChainResponseDto withEnd = certificateService.getCertificateChain(certNoContent.getSecuredUuid(), true);
        Assertions.assertTrue(withEnd.getCertificates() == null || withEnd.getCertificates().isEmpty());
        Assertions.assertFalse(withEnd.isCompleteChain());
    }

    @Test
    void testGetCertificateChainWithEndCertificateIncompleteChain() throws NotFoundException {
        // chainIncompleteCertificate has no issuer pre-loaded in the DB
        CertificateChainResponseDto withoutEnd = certificateService.getCertificateChain(chainIncompleteCertificate.getSecuredUuid(), false);
        CertificateChainResponseDto withEnd = certificateService.getCertificateChain(chainIncompleteCertificate.getSecuredUuid(), true);

        // withEnd must have exactly one more certificate (the end certificate itself)
        Assertions.assertEquals(withoutEnd.getCertificates().size() + 1, withEnd.getCertificates().size());
        // The first certificate returned must be the end certificate
        Assertions.assertEquals(chainIncompleteCertificate.getSubjectDn(), withEnd.getCertificates().get(0).getSubjectDn());
        // Chain-completeness judgement must be consistent regardless of withEndCertificate flag
        Assertions.assertEquals(withoutEnd.isCompleteChain(), withEnd.isCompleteChain());
    }

    @Test
    void testGetCertificateChainThreeLevelWithEndCertificate() throws Exception {
        // Build a three-level chain: root CA → intermediate CA → end entity
        KeyPair rootKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKeyPair, "CN=TestRoot3Level");

        KeyPair intermediateKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate intermediateX509 = generateIntermediateCACertificate(rootKeyPair, rootX509, intermediateKeyPair, "CN=TestIntermediate3Level");

        KeyPair eeKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate eeX509 = CertificateGeneratorHelper.generateEndEntityCertificate(intermediateKeyPair, intermediateX509, eeKeyPair, "CN=TestEndEntity3Level", null);

        UploadCertificateRequestDto uploadDto = new UploadCertificateRequestDto();
        uploadDto.setCertificate(Base64.getEncoder().encodeToString(rootX509.getEncoded()));
        certificateService.upload(uploadDto, true);

        uploadDto.setCertificate(Base64.getEncoder().encodeToString(intermediateX509.getEncoded()));
        certificateService.upload(uploadDto, true);

        uploadDto.setCertificate(Base64.getEncoder().encodeToString(eeX509.getEncoded()));
        CertificateDetailDto eeDto = certificateService.upload(uploadDto, true);
        Certificate eeCert = certificateRepository.findByUuid(UUID.fromString(eeDto.getUuid())).orElseThrow();

        // withEndCertificate=false → chain is [intermediate, root], complete
        CertificateChainResponseDto withoutEnd = certificateService.getCertificateChain(eeCert.getSecuredUuid(), false);
        Assertions.assertEquals(2, withoutEnd.getCertificates().size());
        Assertions.assertTrue(withoutEnd.isCompleteChain());

        // withEndCertificate=true → chain is [endEntity, intermediate, root], complete
        CertificateChainResponseDto withEnd = certificateService.getCertificateChain(eeCert.getSecuredUuid(), true);
        Assertions.assertEquals(3, withEnd.getCertificates().size());
        Assertions.assertTrue(withEnd.isCompleteChain());

        // Verify ordering: end entity is first, root is last
        Assertions.assertEquals(eeDto.getSubjectDn(), withEnd.getCertificates().get(0).getSubjectDn());
        Assertions.assertEquals(eeDto.getIssuerDn(), withEnd.getCertificates().get(1).getSubjectDn());
        Assertions.assertEquals(rootX509.getSubjectX500Principal().getName(), withEnd.getCertificates().get(2).getSubjectDn());
    }

    @Test
    void testGetCertificateChainCircularReferenceTerminates() throws Exception {
        // Create two self-signed certificates and then set up a circular issuer reference
        // in the DB (A → B → A) to verify that the recursive CTE cycle-detection terminates.
        KeyPair keyPairA = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate x509A = CertificateGeneratorHelper.generateCACertificate(keyPairA, "CN=CircularA");

        KeyPair keyPairB = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate x509B = CertificateGeneratorHelper.generateCACertificate(keyPairB, "CN=CircularB");

        UploadCertificateRequestDto uploadDto = new UploadCertificateRequestDto();
        uploadDto.setCertificate(Base64.getEncoder().encodeToString(x509A.getEncoded()));
        CertificateDetailDto dtoA = certificateService.upload(uploadDto, true);

        uploadDto.setCertificate(Base64.getEncoder().encodeToString(x509B.getEncoded()));
        CertificateDetailDto dtoB = certificateService.upload(uploadDto, true);

        // Introduce a circular FK relationship directly in the DB: A → B → A
        Certificate certA = certificateRepository.findByUuid(UUID.fromString(dtoA.getUuid())).orElseThrow();
        Certificate certB = certificateRepository.findByUuid(UUID.fromString(dtoB.getUuid())).orElseThrow();
        certA.setIssuerCertificateUuid(certB.getUuid());
        certB.setIssuerCertificateUuid(certA.getUuid());
        certificateRepository.save(certA);
        certificateRepository.save(certB);

        CertificateChainResponseDto chain = certificateService.getCertificateChain(
                certificateRepository.findByUuid(certA.getUuid()).orElseThrow().getSecuredUuid(), false);

        Assertions.assertNotNull(chain);
        Assertions.assertTrue(chain.getCertificates().size() <= 1,
                "Circular-reference chain should contain at most 1 ancestor (certB), but got: "
                        + chain.getCertificates().size());
        Assertions.assertTrue(chain.isCompleteChain());
    }

    private X509Certificate generateIntermediateCACertificate(KeyPair issuerKeyPair, X509Certificate issuerCert, KeyPair subjectKeyPair, String subjectDn) throws Exception {
        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date start = new Date();
        Date end = new Date(System.currentTimeMillis() + 3650 * 86400000L);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, start, end, subject, subjectKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    void testVerifyAlt() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, CertificateEncodingException {
        String certificateString = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSVc3VENDRmRXZ0F3SUJBZ0lVTjJMQllaSHNHeTg5LzBOdkdVemtGTjVKMkRZd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0lERWVNQndHQTFVRUF3d1ZTSGxpY21sa1pVTmxjblJwWm1sallYUmxJRU5CTUI0WERUSTFNRFV5TXpFeApNell4TVZvWERUSTNNRFV5TXpFeE16WXhNRm93RnpFVk1CTUdBMVVFQXd3TWFIbGljbWxrSUdWcVltTmhNSUlICnNqQUxCZ2xnaGtnQlpRTUVBeElEZ2dlaEFMZ0FpMnEycWFoWFFIUUJyVnZzOENhaFRBdDVZcmsrSU4rRHo5aWYKYzQ0SEQySEh3SGNpN3FQa1FGbFhJTXJVa3EzbnBDS0h4NEJONnFjRUxOalIxRkgrbFpPMHFVMDA5azdLTWNKRApoV2kxYmNKNGdraHZKZmIxaE92NDVjNklxcExQQmJRbmFVSFFQY2lHdWtwZnR1UjBqRTRLZi9FNW9sRGtuNUlPCnY4MmdUaEhYTVpNV2ZKaDkzTVVRSHU3K2ZkQjAxSmNJcmJRTUFRVnpEbmVlcldLcTdaT1JQcjBTdVhMUUlDUnYKY1B2UnFMMDdWaXYxaHd4MllXSU11M0VRcndDbGNDR2R6Wm1TYkdwaHUvMVFoSm5BUzlHTm1pVDl0VGUzdnJEYgpJaTJzZUthdkFsMjErM1FHTHl6N1BBb29YV0luZytoOENNeUVkK1B5dXJ2Y0dYNjdBbGdWNktBUU9pQTQwalBoClU4aDFnUU1xVVVFcE5HWTNxaEEzaE9HcHpPSGJFcUxESk5oZUM0azJORWpWY0ZQN0hacSs1QXpUcWJvNlRzN2MKSngraG0xak1hOXNrOEErbnFUdkRhVDEza1hZWlhFS2FuSnlrVW80SzY1TnJrcVlEcXMzYkgxTEJDMWlBUW5DUQptTzY3NW04aEhMZUhLaGdMenB2M21TZGx3dVprMHhtb1VadDFRUlNWM3BmT0ViTFYyR2VDSzFIdEtTellRZDU2CjFhZlpnaHZ3WFYyRVg4OFlnVTBaR1BwdUtMTW0rL3hYNHpHYlU3Qk50Z2FtalJWaldLd1Z5VFJ2WTJldzZkWU0KeFBGSmUrYlpvckhvbDdXaG1mVEdhalI0aWgxVE5JTEtuODNlY2hqcWJuaEh4dXRwOG5oU3o1VlBjSTJkS0RVaAo4Y2kra2VJUzNtKzFkTjRRUHlYWEdKNFFkSjltL0lQOXo4UU9QY3FESlB4NTlhQ1NRdjhvUGNCOG5wRUVveit4CkdEVk1lS09kWkVBaE1MN2ZNbGEzSDRpNFh2ZTRLWGkrTU1KbXo1V0hTY1gxb0hGcGh0ZGEvcG9FU3FUbmI1WC8KRE8zSUlkOEJPazAxcEpnYWNOM0VQWHB6ODBkbWR6NS91cDdpRFJPMW5uWXl2Vmd6czhCQ2N4a1hKMnFtalcxRwpUV2x5b2NqZnlJbXVua2JnaHJmTmxkVGlsNDZHcXhiMEUvYWtJTWFlUUhhVHFnUks1dE9EeEdudzRLWEhjNXFiCmFOS1JhVkNlWjlEb0ZreXMvZS82VVpGMHpIRjBld1FpWHpraUgrRUR2TGNXQlB2aUt5ei8zNk1ReUFlaXFKOHUKRHVUTjZMcEErU2ZOZk5FeE02VGZtS2FPcE1wczdDQzZUQ3dCOHdkT3JXRjRJRVFXQnFYbzRuMWF3SEdIckZxZgpjcDV2S2tCbHg5RmkvL0FzRWJWTWFtTkdpT2JVcDIvZmhBUVAvd2ZHd0I1eXRPYWx4aVpXZ0tJbVF5NjhJNkJZClhxRVBNcjJwalFOK1BzMyttWGRiYTlNc3VOcCs0S3dOdS9YQjJmZDVocW5aVUliTjcra2lLVytUeHl1THJ4SWoKanpoZU1DWTV3ekVadnpQU0JZenFZU0lxZUFLT2RWb3ltM3pQL2xEeUcwbnpEcHd5V2IwSmVuWUYzS1dvNUQwKwpkSmlVVTVhVk5ua3c4M29IM1FZczF3YlF1MENwbUQzMDhxYU9SRkdsWTZabENXeHRxdkZZR3pmaHNIWWZkTXZyCm9zbUYzdThHM29zMDFjRmE1SlNOT2JxSU43Uy9YVXVwcEtWcEIyUHRBNDJIMGpHSEZaOUcwbUVrYWZHUTRzUTQKQ0tEUmxYVmNwTkZUQVhRZkt0bUJkamVtbFJaSGc5TzJsZWg4V2I2bWVncWJSUWljRDU2SGx5TW9kTTJGdk5UawpETWFaSC8vb3dHUFJwc3NpbnhKcGVSM25GNUZHTStHSngxS3Q4YWcxTjRPcWExQ1ZJT1NMNXdhVTAxRjBFMnVCClFiYmEwcEVLYlp3bDNhSTJxc3hxZ1drT1NFT2tMOC84OUl4Nkxqa29pbVdKa0xHSmxaaUF4djUybHJ4bmpUcWMKcGpydDJyeDhaS3VuM1laZ2NURU0yY3NRUmFJVXBVSEdwaTNmOHpKNE5JcmZHRWlrWkNLZTM1RS91Zng5ZUFBVgpJMnBrZmM5eG82MUtpVnZMQjdrZXMrSXlFb1NodVZCcDJZUmE0cG1VNnI5Y1QzNDhQNE1LMjJUODkwVnJFM2NYCmR3dWJBSjg2M0Y2eFVhZ1E2ZkxweXVJZUo4NUgyQXBQamNjYWdETDY2SUlwaGZHZlVBbG9JZnhmK0R0Z0xrdTgKTVVwRXhmK01nakVFMXVEdHhhcml6RElwWU9xRzBSbWlHWDJWK01mTlZsNmwwZXVaYitlMFV0dHp0clk3VjJEQwoxbmxYTTlZQ1pMREx0SEt1QVlpaVk1QURueFd2dmYxUmQ5YUpQeC9UT1ZQQTA0TWJ3NStVTW9BMTdxN3dPRlNECndxMmN2azNZUHFTak43cW4xYm1JanJQdTU5R3k4NktoMHJQd051YWZWYnRTQThVditxVmJhWmlYQndNSDUyenUKYmpwbksxSVVTZTJMSDdIVkZyck1nNnBQZXArcHE4LzM2NjB2NG5KV0x0dC9MMzM0cWNEMHVoU3NwRFl3elB6Mwpza2pwNzdSV0VBaGNWTHRNVWNLa2w3ckovcUppR29aNVhwY3lmdUgrQkxKbWlXVE5zc1JmYTV1Yk0vVkI1dHlzCmF3ZU01L1JHbWc0NktpYXBicy8xZldpc2UybWFXUUpWU2N2TkZ5TDFjMnVNRjdadTFjMlpLb3NuZ1NaSzBkTWwKcHFYd1UvY2ZySysvSllvZE0wV1VNdk44eUJBQ0JTUyt5SmdseU9hSlpReXBCbUZCZHVXVnZTQnQwaFEzMGQwVwp6WU1XSFpHU0xIeUF2SGhlUm0zQStWdTRKUmJhOXBvSkpMcnlTdkh2NC9GbDNTeUVhUitrVDEzK3JoQ1J5V3YxCkdDOCtoZGZEbU91ZG5icG9KaGVIL0kya2o3aGZHWDY2SWlYbE9lcmNhdkJtaThwNkE1amhoaVppSUozWGQyZ0gKcEJBWFlCN3ZNRUh5cEFGbFBMc3Z6T3NjSzNwWGkyUU80SHlxVFliRWJFalZkS1p2UGZ6WDFIUTZLNzZHU2hWSQpuY1NBTnZiYXJEWGxpWWVFWUFTOWtBUUZJSFRnK1kvWDJDN3owSUlYZUZNTnBZVjZ4bUliM0JhZHdZa3k1R3NXCjY2MldKSHU4U3FjblpmaHJtQ1B2TzE2NmpOaVBPVnV1K0VvRnVEbVprZ01Cb0NGZXlUMTBQdWJxTjBpODZhWGkKd3VBUzdadHJqRkI1bjg1aHBKRExrUFBpbHdqMEV0cmdQSU81Q1FlSStIZCt3UDFTcy9ERWZzd3VJQXdiUUhFVApGeXFLbzRJTmxqQ0NEWkl3REFZRFZSMFRBUUgvQkFJd0FEQWZCZ05WSFNNRUdEQVdnQlNXbzFXaTRKeHpLRVdiCks4N1lYNEE4T0ZvY3RqQWRCZ05WSFNVRUZqQVVCZ2dyQmdFRkJRY0RBZ1lJS3dZQkJRVUhBd1F3SFFZRFZSME8KQkJZRUZDK2g3ZU9CWnNUdGlDZDF1NzNVeitWQmhWWnBNQTRHQTFVZER3RUIvd1FFQXdJRjREQVVCZ05WSFVrRQpEVEFMQmdsZ2hrZ0JaUU1FQXhJd2dnejdCZ05WSFVvRWdnenlBNElNN2dCZHpUUjZZQzNkYWdFZzNXSFV1UVBOClFFV3NPeTJkZ1F1ZFNHNEtpMjduT0NkOERKNWRRTUsxMzJvNUdCNWVUS2s4c1V6eVFVLzZoR3F4V25qZVhyd0gKblRRNXdoSDJLVGhWMy95WEJScGVNRXBUcnNKQ2ZZYllWTENqTGo1ZDE0MThLMk0rNGxiUCtTL1lORXFSaThNRApTWDRlbDUzNVkyQTluWFZuaDlFY2NsNThhVzRIcm9naHpmbTRweWhrWlpkWnVrMHI2VXNaR2pQV3lONkQxVHpUCmpZNG5Zcm1TandTallJbGFBcUU0bnBGK1ZvS3V2c0M2RWlDQ3VVUDhQdnJCTzFNcUtHcndheGd1SFpXM1BTcHYKVm83WmhPMUhvZjl5QkIrSEpBQitXUkE0Q0c5UUo3c2VBZ1RsNlplMndLSXYwaUdNRlNLelV2d3pQRHZpTHdvTwpDUUd4Wnd4dmRtY1BBenRPU2R2ak5VR2hOQU04YWFhSktyZnVzbi9lazF5dWVFcGJQa2YrZUdtZnU2OWdITTJYCnVvRG5leVB2MTJzSVJmSGFJOWQzYjlGbXVYUC9QWWNNSGs2YlhHT1gzN0l2eU5mckR4U3pqU21tdnE0TWpFa0oKeEZRcDRFelIyMWxWY3NUM3hhR2MvTkJzZUZXMjMzMnFPTjlPbCtaM3ZBNVdkbklwUlNrUnV4MEd5NXRTOGNyUgoya3dudUFkMm13c3RTNkZiaFNuNlB0WmZ4d1VDUmVza21iMkdEV3dGOVc0WDU3aXhNNXhmaFo0NGZYZy9tNkg0CndOQ3FzQVkvdzdZVC8rTkZ0elhDYkV5L2VJTEh1bWJmQ3RwcE5EaHEwSE41LzlEc0wzY2lOS0ZzOGV5OUJmcmgKSzdGRi81cDUrc1g5QkJaM3Bwb2JZdGw3MjY3aDYvdjRnN1NYMXgzSUpTRnRZczdZVXZMTnpNcjN5azFBSzF0MwprVVZnR3dJdHliSGMwWVlZTEdkK0hFMzNYKzhyb0NrYld0Q1dGK0Nsek5HbytZSzZZaFhGZjJLUzAvUXpVSlJWCmFJeUM4NzR5akxyamxQZ3JFbnBDNmdlR1VFNWNPRGRvNVhsTGUyb2M4VWY3QW16bkJzTzNBK1VrTFVkQUIvbWkKYmhWV1g1YVNqTVVaU25ITDA1d2xicXVDNnRtc2JZQXphM3ZJNzIwaFJqYTlvcGRiTWo2WXQ3Rm51MVpDMStWUgpiZUk4NU1KVUhqRDFWcjJjVUhiMzBGT2hjZGxhYmdVVzg1U1FuOEhWQUhRcU9oNG10WUpMbTdFdjNBeE4zK0dmCmVmMlFBUkZ0NVRadFM0dHU1dEViY0xvRXF6Mk1rL2Rsekp2ZUFzZ3dGdjBzZTNocy9mYUJ1ekwyUlI0WW1GRWUKd3o3ek85UVY1dDUzekNlWC9EbGRSZ3p0QnZOdnltRWsrUnhySmI3UHJHSFhtNWh1a3d3c0gyTHl5THVTKzJDOApsdFByKzFSREk4UlQ1WW5qS2EzWHAvUWxsbmkrNW9hL2FjR2J2K0l6SlZtVmcxb3dHR2o0ZDh3MmRpNk9oU0dFCjJZTFZES09rV0xVeWRZNUNkdnYrNUN4a21CKzhCdzhremdJbmtEUm1oYWg2QmhjMGtoWGlhM0Fxb1A5ZkdxeHIKMjlJMlJrQ25pS2tlSkJIYTlkM2hkdEtKQWE0NXlyd3JtYko2ZmhFV0pFMk9tUkhKRitINllINit6QmlsUTlZeQoxL3ZYVEMvdGxmU3NMbkRhN3VWLzNpK3hhV1V0S1RXRWlHWWp2TGE2RkR6aGZuSlJvZTZ3Vmg4OUdVMGZmS3pyCncySFZzM3owSjNhcER2bFNkQkpkbjNRWjBHQVpoVGIyWDBpZmI4TEFSVmlBY3BJL0ZlcEhFOXRXVkZPNDlXV3cKamdXelAxL3BUbkNvQmNGV215Z1YvZjlBeTFWMFdpVk9rdzBocUJ3WnJQNy9WMDNocjh3OXh0bk9Fbkc1Z1IybAo1eDh0dkRsNUZDQ2dUcjkrTGlPUU1RUmUxZ3J2NjF6YWZ1N1NZdlBpclJMUEdQVWF5UWx6NmdFOTcxdkJ4NVp5CitDRlg1NmVzWDkrODBYcG1BamRLeHNsWU5rcVhUbzE2V3Y5b1RPQk1nVmQ3R2hqbUhuY2JKOHhVZERCS2dVY1EKMWF4TWtqUythT0NzOEMveEZmSzY2YkE4eHlFS2owcmh3TU4xWjd3RTM2eGRzTUVaVTF4L3VsVjVsMUp1NDl5ZQpFU3VNb0U3eXFnczd3eU52cWdFVytvZmpHbjNURnNJbTZnOE85UE9nMnlUWExxZEM2UW9aTVlQN3JmaC8wWFRYCnREZjByV2V6QmtBMjFtM0pJSUVVSEl2SVEvcmRiOGpoMTQwSFkvLzhWRUNUZDlhOW9wN1NlMVM2aTErb0NFa3AKL3VoWDl2dkdVOWlScWFTdHpJUEdiMHZMWUwrbnNSU1l0Z3U0SEZ2SEpRQ1MwdENWSktHY0JRUDVmZWV0enBSNAptOWVCQ3pXSVZzbXFFQ3ZOQmxkcTJaMU1QR3MzSkkxMHAyTmM0Qk1VZ2xDOHZSUkNKK1VTb2RRcG5wTHB3VlJsClZ4VjlmenBINlBQQ0RGbFlLSVRTcDAvTDhva1kvVmk0c280TkFpa2FLN0dQeng5Z0R2OFc3NDVNNXhkRXBIaHYKR3JEVFdjOWgvdGYwcTFPeWxGemgwNyt2WVh0WjhIdjVwdjZHWndHVE1mQ1ZpbXpCblBkeEphbjFWSzU4cUltdwo3dGZQVG5sb1pVaHE2bjhXNDZ0R2J6NWJiSURNYWppR1RBNHBlenRET096VDBnRTVDRktHS2dIUGV5V0gxcEZHCkRJelVabGVjTmhSMHJRV3JDbGRrZS8xWlV4cU1wZ2xqa0RvWDJ5ZDMzOXUrd0phOTdRa0tsbFlFdHdxdXpkY2UKdHBzbURNOHZlazJwRDc0MkxlcmdtVlk3TUo2THU4Y0dHdmFOWlFuYkhWUjRwRk90Y2tDb2NtRzRITGl3QTN6OAp2OWpML0VYRFBWVmZFY0ViNHptaUFkQWtJNG1qekVHcEhkSXVya2lmd00zTnM4VFByYU9SaUJCZXlReENkSVBwCm5oVTcvaC81VXJzWS83NkhYckNFVlo4Zm9ncjMxelpHbTBQT1VKbFJ5bWI0QXV1eXlZWktDbE5EbTZwM1ZtU3gKUFpadUEzbTZlTWt5a09GSnp3WFVBOUFqa2YyZGdlQW9sRC81aTVrMytKZUFEVytDM0NPanpadFRFSUJId2JBUQpqeEdJR25FeHdoUVZtOXlob0Q0ZTY4dmYwYlV6aXpTQ1ZoV2pIZDhvaG9yeWhCdjUvb3FvYzFnVU5xYXlwZlVUCmhaZGFrZXQwb3JpblYzM2EwbVZ2dzhZR2xXWUViMjFiT1lJK01UQzRqR0RxL1F1UVJIQ09jbWRIUE1adTQyU3oKUktYMmVlZHVtUjNJOUhhTHVybFBXQTVEWEV0aHFONUF6ZHJBTklTS3h3MC9FdWc1YnZSa2d5UTQ4N1JpTHR2NApUNzJva2cySnQ3QmJYbXpEU1BUamxnWHY1ZGdIaTlnNjdzL2lJRzdaaUUzYVM5RkJGUUM1d2VabFBYWEp4Y1BYCmE2eE5aV0J3Vy9DZE9yZGdSOXozMlIxZFY3UGxCUElSdm5wOFgzdkZqUVN2amE0emRWTmdoN2pBbFAvd1VqNFQKams4akVWSjFWUW51TWxydlJhTU9tRklDRFQ2aE9xbElpNFdRRk1lRFNNTTB2dEV6RlVrc0o4ejBkWENWbzFhegpldWZsMGE4Q1FVTHN1akFQUXQrZEpNNjJKVkNndnY5ektjU05RSWxML2kxQ2xZN2o3SkQyeWgreTBQUjVQdjZYCnZUa0dGWHBEa3BZV2djSkMzc1lPUENGOE03bmJOWkNRNXdGbk9nbCs3SU9aNkZNMFlZd2E0eTZ5bW8yM0xQN08KWEJDcU92cWk0KzdlQzlSd3oyMnR2WjAyZy90NEdSTHdhVGtXR3RHemJmM0ZOMVJIREZKblIwV2NySzFhdlRKUwpuS1NkWHNJUWwwVFdCSXNNUUNZK0h3ZDd2Y2ZORVZJZXdyQk9zbm0xQ0cwRjhia3BWVjR0SlRxS002M09IQy9OCjlvSUhFZVRhbUMwMlNhWHlsTC9hb2JxZjVJYVQxRmlXb3R4UXAzOFdPV3hlQk8zZkI4WDhIcDlLc0QyZ21NOGIKUHI1RjMxRktJd3VtVTFPMzhndHR3RUtDeDg3VXdoZFUwSk43aExybVNuaWZyYnRGWkE3K05BVjM5YUlPcUtEaQprMjR3NCtCWS9FZmtnS1JTVjVvVXk4RG9veE9sNFhkUUZlVnBWRWNudnpSN2MxUlQrWjc0QTd5Y3dHNkxmZUhRCldLU05mZWZ6cDg4NFUvbXVFYkkxak55U2pUbEs3NDdtL294aWxsTUpTOStTZ0JKb2FiVGt3Sk45VWdmRmZ6dEsKakI4WDQ1NUlxL09ZYW5mSHF1MzBVNjU3UFR4cWs2VFdwd3FUTlRzOUlLVG1TMWpuanJ0ZllpUEw0U2FuTmlGaApYZG8rNnM5dkNZcXhQWXlJWWpnQ0E0cE54UGVSQkJESlJJWnBXN1ovNERJd1c3ZGdLSk5DenBaRmdWYjZ3WkRGCmNpTXlnSHBlUklzUWF3NStBOGN4cHlmZHpBSTBYSlp2SkNIZTdDK3Y5ekNkalA1K3J4Vk1raTNqWlB3RG16NkcKM1pkaHVQZHY2NGJsQUpKWXZTWDIrL2tsQzZ0Szg1OGFNR3p3TW1LeG80OHhmVlNmV3JOSGtzMi9Xa0FOSEpMUgpBcTlKMTFOeERpMU9McS9raS8yTm9ucWNXZ1J2cU9BcXlHTzFvV2xuS3hDMk5HU0dhRlluRlAvOGFCMHA3dGN0CkFVU3VONkhka1FCbS9mVCtuQVVPdWNRN01scVlSZzg4RUpraWoxdE9nNTNGdzBUTDdDanlHcmduUmNvb1dVSHUKZWdkNFZqQ1g5SW5VSnFvMDE5Wi92N2pjaXNKbkx6TVNUdnV2WkMyRlNhUGU1Q3FsY3dYOGZVcmN0YnV3MW00RgpkMWZPc1A4SXFmcFkyVU1zMDU2RUlCME9IbmVlSGlFZTFoV0FjOW5tRUozZ2NrREhJcVNzS2c5MEM1SVVEdGZrCnVONCtxSWJKclFUY282M3JkYWRxaktDTzk4OG9ucnlaZUM2NVRmSU1Bb1lrbThXSk1hMmtqK0dOV1Rnb1J4eTcKVVg1UzNzREw4dlQyM21tUHdqd0s0eWpBTUl3Z05PVmNuQ1lmUjNVdXY4a0Irc0ZnVmtSRHR1T1BLNlh2a1U0eAo5dUtYN1RXbVUwUnRRSnVVTUdnZ3BmUHBVSmxaWllISTdmWXI5YldtdkhEdkpkRHRJUHNtbmRDRE9lMjlwRnhQCit5T1ZNcFBLZHZueTVrd1BvYjh3UnNTcDlnS0JhLzFBQ2o5RVdZcjNGb3p6VHpaNjd3cStMa2twNlo0bWFaZDMKYjM3SnlDSjR0Mm9INGdVeGhCSTkzSW0wZUx0UGFhbVE4MnRtYk1MZXRweHNDclA5N1h6SkgyTUU4cDlxVXpCMgpSaHU5ejR2eU9aK21xMDNmVy9oajg2ajBBYm0wb3N4YXFEWTRMOFg3cjZBang2dExwSXBUeWVzZm0raUk1R1R6Cm5MQUFMSWFTWTRCTUZhUlNadHZOYmgwaUVkZmpXbjBCOVNoOHh1VzJwU3dnWGIzWE9MK1FhK2tCa0E4bE5VWkUKZUtKQjFnUUZ6dTR4Q3lDUi9SRTBGSmExeE9UMUZSb2JXbDFqYm0rUjE5N3ZBQUVPSENsWG5jUVdJREZCMFBzSwpFSUcxMkFBZVYzKzR5OWJtQUFBQUFBQUFBQUFBQUFBRkVSa2ZKQ3d3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCCkFEZjdzM09kTzZqdHBSZmltd2NHdzMxQk5MS1V1L2o4UUExMERhVXl5S0Z1U09rUU5Ocm5jSU9lUFYwNEdScXcKcWtqT1dtVjFSSjBMUGY4RUtDZ0dMYTJmWHo1VVVGcHhiRXY4RE1sN25YT3lIQmhUdVQrcEoyazhQaXhsUG5aSApSZEZDVDhkTVBWSWkxZzRmQW93cU1QQzZ4TVZ4cmZZWXVVU2xWOVRNc09ndnhBU09oWld6TThVZWpuWEp0Skh1CjVsMFB4ZjJKakV2YjhwVjRBMU9NL0JQeWJpN1NQVjRVK1NPZlZSajVYNDdLQXQvbmRYbDRxZmJFa1FwSTcvZUMKdStBckcwcGJzZDQ0UXRERXhidi9VaCtBUVE1K0NCa2hjUXBqcS9zcFcrZE5qZUdlSDdpbldTc25jYkpDemR4dwpGMHlEalFBWTRUWStNbDdCR0c1Rk9MTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=";
        X509Certificate x509Certificate = CertificateUtil.parseUploadedCertificateContent(certificateString);
        String issuerCertString = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSVlEVENDRnZXZ0F3SUJBZ0lVSWhGc3h0YjVESHFOZzNMNkpKZHlVV0lKTGdJd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0lERWVNQndHQTFVRUF3d1ZTSGxpY21sa1pVTmxjblJwWm1sallYUmxJRU5CTUI0WERUSTFNRFV4TmpFdwpNRFEwTkZvWERUTTFNRFV4TkRFd01EUTBNMW93SURFZU1Cd0dBMVVFQXd3VlNIbGljbWxrWlVObGNuUnBabWxqCllYUmxJRU5CTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEwWENhakNkWDZ6SUsKL3lHY0IxYkVhb2RBZjFPWVZmSFFVVy9iUlpGdy9VeTFjdUhicFlZTnFXNEcvU1QvUlJJdERVajkyUFM0YjBPSApaSFRqR0FCWGExL1oyaFpOSVpFcE5MMzFkNDNLKzJMemJNLzhCZkdQT1RFbmMzTWdoWnFtVnlqUWdKV2FFV3FMClVOMjZIRzFsL0QzN0R1MElFRm9nV1lsaVBrWU5HcTVOcU9Hd2trWGVUTkZiK3JPay9SUDJDS2NYclZOV2Vpcm4KV2lXMXZ2WEJlZ2pqK2pFRmZNUHJtN2Y3RXB2ZU5jNm1FVUZlNkxkcHRXaUFNVklxdlo2MUNSZWhEZ0lMWHRnWApQNEZpOFErMlR5djNzd1lMenRCcm1EMENJbE9lbFluUkhVVkMxakVTL05pSVRLR1N6c3lZZmhvbmk2TlJIbnlKCjdOeUsxRWFyQXdJREFRQUJvNElWUFRDQ0ZUa3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWZCZ05WSFNNRUdEQVcKZ0JTV28xV2k0Snh6S0VXYks4N1lYNEE4T0ZvY3RqQWRCZ05WSFE0RUZnUVVscU5Wb3VDY2N5aEZteXZPMkYrQQpQRGhhSExZd0RnWURWUjBQQVFIL0JBUURBZ0dHTUlJSHZ3WURWUjFJQklJSHRqQ0NCN0l3Q3dZSllJWklBV1VECkJBTVNBNElIb1FBc2ZNUExWTTFHRnB1ZElma2hPdnRseloxdUxrZ1JUSGJLd1dYU2dMKzFVOTM4bnI1MlVVNWMKaG1qK1RKMGZrdEZFZzJPbndMeDJ2ekY2ZnRQT0c3alYva21ydDJlTVhwS1FMa01PL2ZrbW5xQ1dxTkVpYU9YZwovY3pPNXlUNkRIWlg5RVNpZlJZTGdacXdUY0M0SVd5WC8zWWlseUlwUW03T2hTd2hONlU0aHJBR1hxb0VVTWN3CjlZL0lNdWRTK0lNcFo3T29YdjA1aWloTUdDZ0c4QWEzYWtIcnRUQ3BXVU1MUzM4TFZJenU1UVhOd0Rmdjg2bW8KMnBjRjltQzdTSnNTRE9Ja1VYTjlIbDc2amkrQUduU3BTa3BLSlB2aGllSUJ2czMwbERBd3BmMXlXd3MrUWZrcApCOFVEN2MzRjZDcXNvRTFPbjA3MUpkb1A3Q2tBWlpmUEVKZ1ZMVjNHRStod1lnMHFESVM4enRtNGVxTzc3RnUwCjdOeWJQOFJPWDIrQVpQNWJhSklydTdYR0oxTVJrWG9jOVJIWmxPdWNjdW9aWXFrU0VLM3JtNk1JcGdYbSt3M3YKanJ1c1hybnZWSnZTdGNZRTErNlcrNWt1VzBCMnVBTXJabkZ5cWtJUkRQMU5kaktPWStvZG4wQlA3R2hkRkxOOAowRndvditkV0t2QTRRUmhjbWdUUEIvUW9tNnZlVzdNcHdJZ25OWlZxVHovakRKRmluSnlOSU92bFZaWUtEQ0dDCjlOWmZocWNrUkhlTFN5ZnUxc3E5aXMyWmRSbTc2eEZmcFJnU2hHdmFHcGVYMzcvc09MbzdzeU1OdHAyMERiQUcKdk85LzhYRnRwc25TL0doVC9UOVBsb0FEOXZoK2FxSjBJdkltVTZGOXY1a0VhcnY4em5MeENLOUliMm95SGpNSQpRYzhPWGVVaWt3WEpLejZZTklXMUdFOFJwUFhRNUF2NlJDWUxabnpLNlpPZlBjZXZKdFZhZ3lSNmZpMUVWT010Ckp4RHpaMHVXVjJRZG9kUDdUZ3Z2OVdIYlBER1Q1eHFsTkZHWFA0QmFwNDl3OXpQLy9LZit4VG1ZRmJyUWVCaUUKTjcxMkd0MUE4OWFkM0FYTUhFSmNhaDBtWmI4ZFlTZHJKNUhLVDFQMDhKL2Ryd3FuREd6V2tOQlQxei8yK2NybAozb3Q1WGRjSWRoa2dsUzZJbzRROHZqckRkU24yY1M0VExRWjFmYzZQc2t0YlJLVU1PMG1QWXJxVzhUajFSREVSCmFSY1lEcFZxTDg1V0s3RzdJZUJ1Rll4REtRSktJOUM3VTFES3A1TmJrN2s1WTdLMENPeDB2YUlFOUN5OW5RWFoKdVBZQjZYM3BZUzlzdml1VmtSdGNvc0pheHdGM0E3d3owZTI1T2tyTmVocW5ad0FDTnZRZEd4aGxUYS8xdDFxQQpkK2ZXOGtMaEtSQnNpVW9aREpSdDB2N3ZPRk84aFlUT2VqU2lZWU1jNnNYcUhpdjVOUThQZldMOFhCcW5JNXh2CkhacCtvT2dEU2hIRlFvWi9kM3ZKOUlZN3MwaEtENTBjOWorZ0F6VWY2cFFyaGlqbkRITVNSaGtWRzB4cHNEbGcKUFg3Nm8vK0NOMnZtUFRFbHdwTFV5UmFtVHd0bDU0eW1YcVlsTXU1dDU3T2wyeUZVZzNXcE1XMmNSM2dvU0hFegpSTDRvZzFhY2U5NzBUdnprZHZ3ajJCRGhVL0tZaU0rMnNrT1pHaENvM29mSk9kNlRtVjJXbnJNMXpaaWhOVi9CClY3QlQ2Tm83emdIZVkxQnFabG1WNWw4NEowRk9PR0ZKY3RjMlVBK3YrNkxsakJDMjI2WVVKblg4ck1vb3UxbkIKSWxBQzcySG84R2JhSzNGUUNWMHVGanZjQ0Q1UDNqRkNxTThxMTFXWUdOWTNwR0gwZzhVQlNaamhoM1VHZWxtMQpFUEU3TlNPTmdSMGhnRGZPT25jUzBkVUdyQkZTWGJqcndlNGFreHoxRzAvb1ZBeXVnUnNESm1la3RtNkREUEpPCnltQUpyd2NNdzl0QWF5OXgrdDBXY05ZWVVuZGFNbkVkQjl1RGN1S0dyZk9vRVJDeDFDdm92Y1l1bit1OVpxaXAKYk9YUUZlaEIvSjJOajA1MVRVaktwZ1ZsR2k5MHhDSjNEY0JsNTZiNWh0THk5dUFKVnVoL2tFSzZWOGRvbm5BeAorK2NGYlYyL0M4MUwxcDFVQUc1UUJKeGJEOUdndjBrSVRIWFRLRVFQMEVjSmNEVzhhbXprMnc0RGZTZCtyY0gvCkVLaXpqN0R2WmVvRENiSEVaa2NGQk16ZVV2cG9oMXZLN1paMFVBZjgxVGRHMS91ejBHMGk1c1c5ZjRSRDU3SjcKRzd0RDZXMnZEQ2Nic1lmZ1pEOFZoOFhJMXFhRzZOSVdDVHhsMHZPWmdzUDY1b3B6WUZhNWx1MXNvZFBXVHBYcApKcy9EWkRJbG1QUHlqNUdjREZNRWZ0KzZ6LzRUSzBnQzhyZ3RZbzF4OVErU0ZvN1l1eGwxcUNlS2Q0RWd5UnlmCndnOERxZDhGWStlWDM1QmtLbEZURGdHOWVuZFJqd0t6SjFjMlUvZHMzS1Z1TDRLNHBtbTR4ajUyaUhEcGZhZzYKaWZUeFNTaW9ycFVyZEdVNGhjTFpTMVJNT1pab3NXYnVuSGo1NzdpNTViYzV2d0piMDRyMWh1eWtBZmpsVTg0Mwo1cTFaQzA4K0tBaGdnZkVyOFM4UmxBWXhHQWpXWm14TEFnSGhxazB5OFdNQlpXak9nd3BsVmIydkJFUFR5QmluClRrM202c1R4bGZaQm54U0xTWTFYcnJsZE9Hak9sRnFnNnQ4ZmFxWmFtWGRsUFcwZFpIL2tsRlB1VjRnUWE2UTMKN3hHWTJ3M3JSL3ZPS1psd05yU1FWMmZtMnVsSERHcnpQemo5TXQxSWRrZUZ3NXJCRFBuZndwZjhzYmd5b2tnSQpOdkRaVzdpM0ovTllpNVZqWit4RERMeVVtZ3UxcEVoUklMTEZnVGlIbkhzZEJTNkdhVEhLRlR6WkM5QnE1aFlHCjhCUlVuajYyTW9NQmV4ZEV6bWJKWlpPMUs3cUlwS1NORVhxZm44QlJBZmJXMDl2OGRHK3M2YlRoWHY2WVYrY04KZ0VQQ0hmWEdDNEdpSmlQakxBRjE1M3VhYlZrZEJmKzVLZG93R0RqRlJMRVFlSlRnZW5FOFVwLzI1NXdkK0xrVwo1VG9NMDY3eXFybXAxTlFMMkt0dFNUOFZNRHBlNUUyTEZ0Mi9JTEUyNmVKQ1NPNUFuZm8yY05BU3BDY1puZGllCmFJSXl6ZUVhUmpsNHRvV1doeVBGeUxYMTdkZk84cnZiUzFWQk5SZHI5azlnNXAvZ2h4RUw5TWlYKytkZlArc1MKTHAwbDBQQ2ZSSSs5Qm1CVEFVbUU1U1BHYXlpUGRTeU5oTUo1dzRid3h5a2NXRCt3S08zK1JEQVVCZ05WSFVrRQpEVEFMQmdsZ2hrZ0JaUU1FQXhJd2dnejdCZ05WSFVvRWdnenlBNElNN2dCMHBkVVlseDdXQUJETGgyQWlEZGRFCjdGTU94cDZoVkxDNk9BTUxvREpaQTl1SjJaa3ZjbVppejV3b2RpaXRnRmJsKzUyUmZHd2JWUm9FeU9QOU5iRUEKQ08xRTRiVlZJYjBiSjc2dm9hMEVvVjNjTVFZcWpmNks5bkhBTTExZ3VNOVpRS2JucEJDckIxbEVaaWlTa3lrRQpYQkZaZDArQUVCb0N3Qno3TlY2akpVTDJvcmJrV3F6WWRHQlg5MnpDS2dCWnZVbms1NnBFMWhBU1lhZXYvenNXCnBTNHdLQi81U3c4S2lGaGhjemlBWHU4MmEvM0xnZDNiNXd3dGRnUjJtb2FERU1VUmpqU2Y5b1JLdER4ZUZKcDYKS2VnaURydzdmTTZrMEdtZExyemdlUzdRdUNkdXlIODFQNWY4MXpRM0cvakJDeXE0d1QzRjNESXl4ajVPTDFxbgozaytPY3Z1VWxwNk5oZzZIV0pOY3VCNW1mM2JEcFFVYlRmR0kxeHJhTVVIRGRqVHRmYVFvbktBeWRMN1pVK3NXCktGc043U0tZS0dBNEVnVFU3SGs5WkhzTTFoTzRlVVRQUG1EYVhkekVORkhqWlpkeCtJK2gzODVHVWplN3VPUjAKckw4VjJWeE9aMnd6b2U2ZXZQRWtsUTcreUE0bWNXRmtXcExMU0ZIejRxSnljUUxkcTNDUFUrMUNxbjUyRFNiawpVTFNjcFBNd1VaNFkvUGhtelFUZ2JwMWNPVHp0RzV5STVTNVNGbDMrc1FLZDBCaE1Eb0QyelVSWWpVT0plR3BDCmRaanROQloreDZYSG1mYWdydjVLSThTY2lyZ3VOb1ZZYTIxbnN1d3YvdUI5VStXMkJQeEIvbGQvYlhXS3EraXkKZ25VL1B6cjlPbERvQjhZNkMvckFyVUJmdTVlS285b1pKZm1iSFRDOW50dFgyZWFRVWhHVU9WT253cXJnVXVKbgowMGNnWGZ5b3U4TENKaHRzcEdVRW5tQUlQVTlscEdLSElRVzRJWVc2eTNmVUtkWk5OUVZRVitsV1NBejNOM2pMCkdLczVCVVEreVQybzdrQmhLZ2l2UVczaEdqY1RIZzlsVUdUQXlXMkpIbnQxY0VZamlLbjVJK0MvN3pRRkkwaFoKMGdaKytBb2xXK2J6SVdGQU9kcnVraForME1qNXdsMnVnTUVIZ3BKcTk2eFA4dnc5Vkt2b3JPMDNqbnZiV3BQZwpwV3phMmFMSndWOUlhYjErYzdGbU05SjZOclBzMzQyaVVLVXhlL3pMcWMrcjY4UVRHKzd6Z3F2U1dib0swOERBCk5sZU1vMUl5NGZTWTB1Rmk3NEVlbVhxZHZhcmhuQ1BZRmJpRk1kcHFPOTFUMkJobEd0cG1PTDdiVHQ0NXJubUkKbU9sbytGbmlWY1NHZHdWMlY3bVdVN2dPTS94VmR1enZsZVc1VjQrbko5UXhUQmNWQXROMXhLdXVINWRNL0IyTQpVRUlmd2E4NG9JWFJYS2pFTkU4aWExWGJPOU1tQXZoSDlNN2lWMm9SdVF1ckM3N0xhb3RLNWtQTXhnZUM1dkdhCkdyTkRWeVRLaFN2TVdZMXRwLzdWZzM3OXZHbWJnOVNVUUFXK2Z0b05PSmNMQVg3bWg5TnpnZTBMQXpyeCsyNXgKaXBCT2dPUDd5NTBEekE3eEVjOFR4TENsYmhSMjZNY1BaVUpaZis3NlpSMlhQbU5CQVJYY3VwZmNLOUIvMENxQQp2OVVsdEZEV3lpazRmdnRNZXp6ZGtwQWhhK2QyUVVoRi9mVUs4WDFRRjFnbnliUDhEb3U5cmEwN0hLaU5BN2NGCkM1dlJrV0NNRVAxYW9FbFR4b1VPcm0zTmdqTjM4UmFFcHhiaHlCLzZMNlUrNDhMNlpRckN0c21MeTZublFVSVcKaWRTdEFRQXNuNTNqQU5oSll1TllHdndnbXdKbnBtRFFyVjhiUGNOcTBpZFFtQVdRMXVsU1RBVklFM2tuQnVzZQpZTXpOVFNtMG5QR2xrY2F5cDBJK1l3amZSR0dOQk9MMmE5cDFSeFdrc1l6Y2VpOGdjZFZXQkxKQVlHVFdCM2JVCkVLR3pBcjdRVGJxNy9YUFVJMUVBaUVaV2UzSFgzMFlBMWJrRUZKNDJGVnJNMHkvQmNZbi8rSzZRSmJaVFdZVWsKbHY3dTF0bDI2WnliRG5ibDdiZjlJbmVtUkZZQ1BBbTUwdDJiOEVpQVQwSCsvTkxmZXNDdmpBdEVRREhUL1pndgp6QUM2V3orZmE2WnIwOXFrMUtkSlVmNUpXa3hMKzdndERWd09DUVpmNjNjVnJjeG5NYVl1Q3o0d3ZzNGRsbk5JClhMZTgvODQyMHdsY3dtejdUVmdOblUrN2IxdGxnNHNTanlNMGhxelVNWldaZ29rZmwxUm1xQStVbFNDN1pDeXUKd0EwVVdNOFVHWlREdjNoK1ovY01VSklaVENuQ3dvekxTb3hLUmgrZ1dnWWZGcVBCTXMraDNoNDB2WEEreUhJegpMNlVyWTBqbnZhYU5lVjBmM0x3NWNJc2lWSzh2TmNIUTYwWkVBeTVCK0dZNTN0d2Iyb2tJMG0ycVAyOExUZEg2CjdRNlpLNlpSKzVQQ0d3THg3L2NYMXpEMUtxQnFrTGx0NitmVFZFa053OW9lcWZXQWZLVUdENVlHSXNnVUZXRXoKTmt3Y0R2YkUwS3lFY09vbjdPS3U1SXhkSm5YUmxyVmlraUFxN3Jac3pQN24ybGJLZmh4VEF5eVJYQXl4aG5zRgpUWE1QeFZzeWJsUjRQaFBXeDQwVHdYdlZ1VWxCa1dDV0cySVovTHdEbTQrQkRXMjdwTlB5eW12K1YzYmVsWEJ4CjFOVjhMQnY3Q0lzdmh1aFFOYWVpTm1mcWR0eGsxeWdKbEhON25XUCtiT3E5TUxSYW1mM3g3VFNmYzdBVWNkODUKNE9ORHpDeXVxTHF4bXpZaGd4TTF3dVh5V1RlUktQU3FwVFV6OWZ5ZUhZWlBLazRaQlBwL0ZJYUhkZGdSQUgrawpmem5lMGgzOXdVb2YxQyt3L3RVTGg1RFo1UlVyWkM1WloweS9sSXVVclZFeFdZWkx1M0RQQkV6TmhQR0huQU1jCnJZS1VTZ3BsU2J3TWJOMFU3M0hnQTNqNDc3RHJOWm5aNHpSRU96Qy8wT0NyTE5RTGpQdkVkRDFodUo5VURZV1YKWXNaSWt2c0l2MEtHUGZscDlKeSs5SUFhc2ZyODIvNUFUdEZmMHRGc1ROYWI3SU0xTmxZb1NRRCtvMEw5d0REUQpZcmo3cEFVZGRLVlgvOFFBSmQ2T1dTOEF2WmI3bkpGcVl5dUFnaEw1THExcGpoTkNqL244TVFSWjhDTDE3UlBOClQzOUp4NlZhN3VYSmRaN1hIYjBQTFBnQUxoeGZUOXZRY3VHTFMrcmJiblBWcGpxVGQ3ZERKZk1NVzgxUDJwaVYKcDRaRXAxMURER1dyM1licWRzU1c2UG5YU1I4ZDF0Nm5Qc2trdXlBZFFVN3J3RjhwRUxxalF6R2Rpb3E0aVJ0TgpsK2E4MmhuZVRWald1a3d3ZnZGa3FpWjRiaXRKdkNZMlFUN2pDZ0VlcUhCS2RFWi90OEYwc0NsRlVlSTdDbVRHCkFjcVVvMHdmTDViZ0lTbmhydjJZR1JrR3BWVGt6QUNBU2kzNHhkckVicDl6VW5RYWJRQXFLdXlTcGN4RzhhT0QKU2tZVHh2bHhZWldoWlJDRUFyNGxmd0U4cys5RC9NKzlBNGNCd29BTE5wM0g3Z1gzeDRKSmtEMTdZZVNQSkg0cAo4QTQrQzRIOXBwNy9qVFhpc3AwTGJtODgvSWl6Nk9BN1E2blBUSUdtTFk5WFQrcUlFRHJua1ZwWWV4ejNEZ0RoCis2eDYzelQzOGJZT0duSEpNa3gzY1lpTS9YQWRRaTZGR2VhK3R1MFZJVktoenplNVNUMDBZZStTOGFzbGt1UEUKakthZXN0Y0N2RjBvQWQrY01nRm1YZUl6TTRvK0pJL3lQTDdEM0RwcnUxUkVqK1BjK2NXQTEvQmFvQ2Q2cHFnaApQNWwzUFh2MjYyZXhvanZGa0pTRWQ4L3dEVnNLYmhGb1pYOENSZjJZTFVEUWc2bDZ5WnBiSFJ6ZGFObXl0ZmFSCjYwMCtuaXYyNDc3NWwwQ1ZoUmVIWlBBS2pFNlFQcTR4S3FTQm43SHNNNjdOUGRFMDhxSVNIbUdWOWNKNURiTEkKZHFoVjRMOEdrQXV3Ymo2U1hzaUFBeFh5cjloclA0eTFqbUtaQmVZRHBzenZoUUFqbWpnVUwrTC9tSXU3bS9ZVwpjUTQwYmN2TjFLb0pWMkhOQVR0NjluZ1FjYmIxZzBkanhpVVNNTHJOVUJXb1ljckgxMW5lQko4aFY3VHM4T3JhCk9MSUF5WnBYZ0lEUWEwdFNpSEtvK3FCaTVNZmUwcEQ2NVJuQWNPRFFrSHRXSHR3RUpaM3V2L2paUm5SV3lrVWcKOTBJYis3bUlSNkliajBPZHJZRXBjNmVIeXR4UVQ1MFM1VFZoSlNaVWwxQlRiU1IzTVlmRjdaSkN6T1hXWGxaVApOOEJBZk9EQzREdFk0NnFvTUFtYnNQTXljV0V6VUxVQ2thcGtoRGpKNDBUOXo4ZnQ4WDJLQXV6REkzek03cXVICkdNSWRud1JCdWRCRy9vUjZXVHlUcWVFZ1Nvb1hKa2ZiL1V6NHJnWlphYlhlbjNiMXpURWp5Y0t2dWNjR3FVbksKY1NhTnMvNkhMK3BjZXJ4cHh4em80QlIvWGpiSHFiNlU4bDgzaFljdWw4cFRCbFlyb2hwRjNncm9qb01pWW5DUAo0ZU15dGpnTXBFS0NtSWxrbis5ZjU1RVZpTUljMml5QzVCaFF2VGkxWW9SL3VFSlhncDFTV2NaeEU3eGJvYk0xCmVmU0FYSlk3aWhqK2cwaEdHWjdsVy9UMVlIdXJHZWZ0VWNORFNobjZ0Z2JVTzQreW1yc1JtdnpGUUtLYWZsd0YKcTRaVHQrWlJ4dFhSUG5YdzJkOGhib2ZYWFVBTDMvcWNPc0ZyWjRtT1BYZDlSdDV2RmVYNjRYMCsrb2hBR210dgo0bTB3QjhOL0tjclUrekszK1k5RW9yZHRlN0NrZTkzTG4xeXpZZTNLOU5leDZ2M1luVTdsbXNxMlg5cndWVGowCm5HK3dzREhWU1NFQmhBWmtVcDZzVnBUbGtsS0V6RVdwSVJTK0UrU2FsMkQzcUhzSEZyWkVMRmhnalBwWEUvdTgKQTM3a25OMURxYjRVNkoxeFA1cEx1dWlGbWdSRVNxN1JPYXE2cGFZYUwvNndCTnQ3UDNlcjRqaGJyOHdmclhZdwpmQjBqWTd2QkFhZTl1MnVFZVZsb2NUN3lkRjJmV0g2RzFsTlJaUGtUUTF1R0hERHFJeVFTNTBhdHJkb3JBb1hsCjdWL0Vna0Z1RCtvbTFHVjVkNDZqVEVRc3dxaGpJSWNYUDl6SmdQV1NOK2t0RnI4d2VLSXBMRUk3T1U5WXF4MXMKbU4xUDJhcHg1VmJxZFNyT1JUbTlFUGMzaEV2dEp2cFovVy9hT29sYVAyaUk0SlFkWFoyUklaYUtDU3prVzkrbgpOaDRraERoUXRDT1djcnZ6QWovQ0xzRDFDQk9GL1grYTZwMGNNek8yODJJY0duTDVMNXFzRnB6TkdxVnJ2Y3UrCmN2RE16cVV0ejliVUtkSzVuOWZwb3lsSFliWXNtL2ZnYUJOeFRLY3hwVUlNQzAvcHljYXhhdWg0ODAxZlRpZ20KMExLdlViSkUzSEp5MTZ3Rk40Zyt0bE4wZTRTRnFmNEhDeEVVUzRQRDQvb01WYVd6RHhOVWROYmhJVFpBUTRXTwpwNm5GSWorVG5xS2x3TWZPQUFBQUFBQUFBQUFBQUFBSEVCUWFJeXd3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCCkFCWEtTbWIxalB0bHpEVEg4dFRUemRxVHRIQVBHeTRieFdINEJ0UkNPNGVoOUhMTFNnQXFmZmU5RnpWZDl5aHMKdzhnc0dHQUxUTlh5WEswc3FuelgzN0ZhSzNTS2ZhZ0gxL1NyUFIxZGVzaEo0M3VZTjRRSEl4QXFQNGczNDFTRgo0bThsWGdXcTZ3S3dBbzMwK08vMnRxWHlGUWwrU3BVcExUbnNBZ3NIdVhma1dDdk93MUtiN0tOdjQwVXhRUVE0CmVsbVdyNHJrbHUxTGdZbWdsd1FxWXhoQ2dGdldLZkw2YWdkcHdZOG5OQUVNK1VsSmZpbmxQc0UzUzRtNUN2elMKNE01K1dIaGtHQkNuTGdocmRUa0Znc0lmdEVyK0ttUFdYdGVQRWhWLzBmcjNFYmJsT0FDc3B5VjM0NC9iSUE0UQpmaXhCRVhzN290WmRXZGtJVTAvRlo0cz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=";
        X509Certificate issuerCertificate = CertificateUtil.parseUploadedCertificateContent(issuerCertString);
        byte[] altCertificateSignature = CertificateUtil.getAltSignatureValue(x509Certificate.getExtensionValue(Extension.altSignatureValue.getId()));
        Signature signature = Signature.getInstance(CertificateUtil.getAlternativeSignatureAlgorithm(x509Certificate.getExtensionValue(Extension.altSignatureAlgorithm.getId())));
        signature.initVerify(CertificateUtil.getAltPublicKey(issuerCertificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId())));
        X509CertificateHolder holder = new JcaX509CertificateHolder(x509Certificate);

        TBSCertificate tbsCert = holder.toASN1Structure().getTBSCertificate();

        // Step 2: Modify extensions
        Extensions extensions = tbsCert.getExtensions();
        ExtensionsGenerator newExtensionsGen = new ExtensionsGenerator();

        if (extensions != null) {
            Enumeration<?> oids = extensions.oids();
            while (oids.hasMoreElements()) {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) oids.nextElement();
                if (!oid.equals(Extension.altSignatureValue)) { // AuthorityInfoAccess (example alt signature extension)
                    Extension ext = extensions.getExtension(oid);
                    newExtensionsGen.addExtension(oid, ext.isCritical(), ext.getParsedValue());
                }
            }
        }

        // Step 3: Reconstruct TBSCertificate
        TBSCertificate newTbsCert = new TBSCertificate(
                tbsCert.getVersion(),
                tbsCert.getSerialNumber(),
                tbsCert.getSignature(),
                tbsCert.getIssuer(),
                tbsCert.getValidity(),
                tbsCert.getSubject(),
                tbsCert.getSubjectPublicKeyInfo(),
                tbsCert.getIssuerUniqueId(),
                tbsCert.getSubjectUniqueId(),
                newExtensionsGen.generate()
        );

        signature.update(newTbsCert.getEncoded());
        signature.verify(altCertificateSignature);
    }
}
