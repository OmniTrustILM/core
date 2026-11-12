package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.extension.ResponseDefinitionTransformerV2;
import com.github.tomakehurst.wiremock.http.ResponseDefinition;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.api.model.core.certificate.CertificateChainDownloadResponseDto;
import com.otilm.api.model.core.certificate.CertificateChainResponseDto;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateFormat;
import com.otilm.api.model.core.certificate.CertificateFormatEncoding;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.CertificateValidationCheck;
import com.otilm.api.model.core.certificate.CertificateValidationCheckDto;
import com.otilm.api.model.core.certificate.CertificateValidationResultDto;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.raprofile.RaProfileCertificateValidationSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateSettingsUpdateDto;
import com.otilm.api.model.core.settings.CertificateValidationSettingsUpdateDto;
import com.otilm.api.model.core.settings.PlatformSettingsUpdateDto;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Crl;
import com.otilm.core.dao.entity.CrlEntry;
import com.otilm.core.dao.entity.CrlEntryId;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CrlEntryRepository;
import com.otilm.core.dao.repository.CrlRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.events.handlers.CertificateUploadedEventHandler;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.messaging.model.CertificateUploadEventMessageData;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CrlService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.impl.CertificateServiceImpl;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateTestUtil;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.MetaDefinitions;
import com.otilm.core.util.PlatformX500NameStyle;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.OcspResponseBuilder.anOcspResponse;
import static com.otilm.core.util.builders.X509CrlBuilder.anX509Crl;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
public class CertificateValidationITest extends BaseSpringBootTest {

    @Autowired
    private CertificateServiceImpl certificateService;

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
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private SettingExternalService settingService;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Autowired
    private CertificateUploadedEventHandler certificateUploadedEventHandler;

    private X509CertificateEntity certificate;

    private Certificate caCertificate;

    private X509CertificateEntity chainIncompleteCertificate;

    private X509CertificateEntity chainCompleteCertificate;

    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() throws GeneralSecurityException, IOException, com.otilm.api.exception.CertificateException {
        mockServer = new WireMockServer(LoopbackWireMock.options());
        mockServer.start();

        WireMock.configureFor(LoopbackWireMock.HOST, mockServer.port());
        InputStream keyStoreStream = CertificateServiceITest.class.getClassLoader().getResourceAsStream("client1.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStoreStream, "123456".toCharArray());

        X509Certificate x509Cert = (X509Certificate) keyStore.getCertificate("1");

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent(Base64.getEncoder().encodeToString(x509Cert.getEncoded()));
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = aCertificate().build();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCertificate");
        certificate.setSerialNumber("123456789");
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setNotBefore(new Date());
        certificate.setNotAfter(new Date());
        certificate.setCertificateContent(certificateContent);
        certificate = certificateRepository.save(certificate);

        String caCertificateContent = "MIIFyzCCA7OgAwIBAgIUOymQEJz0e6+2cDE/"
                + "1Z76gPbY0cAwDQYJKoZIhvcNAQELBQAwOzEbMBkGA1UEAwwSRGVtb1Jvb3RDQ"
                + "V8yMzA3UlNBMRwwGgYDVQQKDBMzS2V5IENvbXBhbnkgcy5yLm8uMCAXDTIzMDcx"
                + "OTExMTIwOFoYDzIwNTMwNzExMTExMjA3WjA7MRswGQYDVQQDDBJEZW1vUm9vdENBX"
                + "zIzMDdSU0ExHDAaBgNVBAoMEzNLZXkgQ29tcGFueSBzLnIuby4wggIiMA0GCSqGSIb3D"
                + "QEBAQUAA4ICDwAwggIKAoICAQCsbi+SUia7Hlp4DmR6MzJrBwIKh1Bq5vP64RcmsYch4"
                + "4Xa2bCRv5oDW57Hx9uy8cZpWI/7x4U5m7B/P1/FQG7SQ5u7ATvn6cbrZthaM9NYRZLY3z6"
                + "wRl2SQY0SUDWQyu2vkc2PxYy7qzz8r8s7T7vgDn9ozq/ODAZxYnfDGzdSLKay1ZVzNs7GNhk1Y"
                + "2RDA1JQXehi6avD+xaKH61YeO96sPpIGBOsbyvoQ3qZjCVPGRgXuXwJuqaxGV1QKIDPGCpKV"
                + "T7wy+edSh3XlEixW9GnLIQkTS/WiFYEO4B6DbZJ+WFU+djIAHzQwFHx1WYqfm9ok9QEzi2"
                + "jyUEafKtjDv++O8giHpRaMDvOiRRZPrHRBmCjbFmktB83VDTDyhiL+tuAUDBPDdEifWgXa"
                + "ikEsC2tA9sbrfUyByQCGhNXj8u8acNt0UPRGXC18uAmoCM4qkq4x0DaplnOwG8Cqi0IgAyLO"
                + "ZSNb/pXmfnvQxM3yyQ/kQAV3u69FX6ExkcoMnDi8ntfqMPAEK6tJGShgB27rEVhWJc9+"
                + "IhW0f/mFbSJicUpeUeao02lTkSUn0r15hAz9rUVnjz6a+aSUS4yTW9nigJuy7Fi5N5fq"
                + "wzDdIWkWIg3dvzjcObsC5zHSf1a8qyi9E/RHfh1LneLA116IpMmTQpr2CNnWtQuwCKqJ"
                + "M30bDP/DQIDAQABo4HEMIHBMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUJMpCDu+q"
                + "xpE+0ar6E1h4KhZQRokwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vcGtpL"
                + "jNrZXkuY29tcGFueS9jYXMvZGVtby9kZW1vcm9vdGNhLmNydDARBgNVHSAECjAIMAYGBFUdI"
                + "AAwHQYDVR0OBBYEFCTKQg7vqsaRPtGq+hNYeCoWUEaJMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG"
                + "9w0BAQsFAAOCAgEAI0yAtaw0o8952LGD4gxZWskfun1bl92JvpJ5ydd9kQngE2zsWlLk470O3qM4hwa"
                + "+umEqUo6YkVK5tH1xDyggwHYS/LW92uBoPbvW+cMVZvpwBWR12lXQzAvmN5w5EcDS6s1WOjNAfR5ILtOW"
                + "Sd79cCOEUsOVl+JNKeFDdBFT4I1xir3F4C3bN1DmwgVVWKzpRmetS2Ds1zJsIfWlFoywQynEHQzxth"
                + "5EPQCc/KF4tjcEeNnYeHjBLm7iY70HCiOATzvT8bj/rJkVeUJLPGEikAY0YMQOEGHtF8UstDm+EGH4"
                + "4ON50FRFd++9nrZtnziDwrC0m6fMsjfBkk0G7coJqNSHvEr41AmCeWUX3cfT9TIm1qLecZpnW383Y0"
                + "Z67+YqOf8p8vx5dYZy+uqe+CrJMvvXk6O1ZVDMNuib3y0UY3PRpZ7FW5SCNKfyiSv2edp+OSmmDAkI"
                + "w55i6G/QVQyxq18LNgzFmZIXDysIV7hLlt5W54h86iTEHGNhm7Qsy+LFN3dq31oO11sVQBaUKjONUIK"
                + "gKuGrbAVmeDteGpBdQCv3fu3SY4BG74ryNkvotnAeMUaL/XhrvC9XOKeQbJ/tRLeE8rf4It8Par1Ruuu"
                + "bC5IL0ajdJ2e7X99Tt1Mqh48cQ2pFA3sVEif7h81+Y/i4UWraB/7pGxa/CehwrF8eIOI=";

        caCertificate = certificateService.createCertificate(caCertificateContent, CertificateType.X509);

        certificateRepository.save(caCertificate);

        String chainCertificateContent = "MIICjTCCAjOgAwIBAgIQf/NXf/Y8fKN+BkL4yLhikDAKBggqhkjOPQQDAjBQMSQwIgYDVQQLExtHbG9iYWxTaWduIEVDQyBSb290IENBIC0gUjQxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMjMxMjEzMDkwMDAwWhcNMjkwMjIwMTQwMDAwWjA7MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMQwwCgYDVQQDEwNXRTIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ1fh/yFO2QfeGeKjRDhsHVlugncN+eBMupyoZ5CwhNRorCdKS72b/u/SPXOPNL71QX4b7nylUlqAwwrC1dTqFRo4IBAjCB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHW+xHeuifZEN33PsWgfHRrr3DRZMB8GA1UdIwQYMBaAFFSwe61FuOJAf/sKbvu+M8k8o4TVMDYGCCsGAQUFBwEBBCowKDAmBggrBgEFBQcwAoYaaHR0cDovL2kucGtpLmdvb2cvZ3NyNC5jcnQwLQYDVR0fBCYwJDAioCCgHoYcaHR0cDovL2MucGtpLmdvb2cvci9nc3I0LmNybDATBgNVHSAEDDAKMAgGBmeBDAECATAKBggqhkjOPQQDAgNIADBFAiBbsQQLhG0VbSTee24xTExpfZjtvxSr0QUeF5ynbsLfsAIhALzHr/nsu7YViuT13ZNVPKTQ4UWHvxnqxJZRGRgNHE4w";
        chainIncompleteCertificate = X509CertificateEntity
                .from(certificateService.createCertificate(chainCertificateContent, CertificateType.X509));

        String chainCompleteCertificateContent = "MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAwWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cPR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdxsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8ZutmNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxgZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaAFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6WPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wlikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQzCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BImlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1OyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90IdshCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6ZvMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqXnLRbwHOoq7hHwg==";
        chainCompleteCertificate = X509CertificateEntity
                .from(certificateService.createCertificate(chainCompleteCertificateContent, CertificateType.X509));
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

        Map<CertificateValidationCheck, CertificateValidationCheckDto> resultMap = MetaDefinitions
                .deserializeValidation(result);
        Assertions.assertNotNull(resultMap);
        Assertions.assertFalse(resultMap.isEmpty());

        CertificateValidationCheckDto signatureVerification = resultMap
                .get(CertificateValidationCheck.CERTIFICATE_CHAIN);
        Assertions.assertNotNull(signatureVerification);
        Assertions.assertEquals(CertificateValidationStatus.INVALID, signatureVerification.getStatus());

        // check disabled RA profile validation
        var validationSettingsUpdateDto = new RaProfileCertificateValidationSettingsUpdateDto();
        validationSettingsUpdateDto.setEnabled(false);
        RaProfile raProfile = getRaProfile(validationSettingsUpdateDto);
        certificate.setRaProfile(raProfile);
        certificate = certificateRepository.save(certificate);
        CertificateValidationResultDto validationResult = certificateService
                .getCertificateValidationResult(certificate.getSecuredUuid());
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
    void testValidateHybridCertificate() throws InvalidAlgorithmParameterException, CertificateException,
            NoSuchAlgorithmException, SignatureException, InvalidKeyException, OperatorCreationException, IOException {
        X509Certificate x509Certificate = CertificateTestUtil.createHybridCertificate();
        certificate
                .getCertificateContent()
                .setContent(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));
        certificate.setHybridCertificate(true);
        certificateService.validate(certificate);
        Map<CertificateValidationCheck, CertificateValidationCheckDto> resultMap = MetaDefinitions
                .deserializeValidation(certificate.getCertificateValidationResult());
        Assertions
                .assertEquals(CertificateValidationStatus.VALID,
                        resultMap.get(CertificateValidationCheck.CERTIFICATE_VALIDITY).getStatus());

        // Set issuer with different classic key and alt key to test signature not verified
        X509Certificate x509CertificateIssuer = CertificateTestUtil.createHybridCertificate();
        X509CertificateEntity issuerCertificate = aCertificate().build();
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent(Base64.getEncoder().encodeToString(x509CertificateIssuer.getEncoded()));
        certificateContentRepository.save(certificateContent);
        issuerCertificate.setCertificateContent(certificateContent);
        certificateRepository.save(issuerCertificate);
        certificate.setIssuerCertificateUuid(issuerCertificate.getUuid());
        certificateRepository.save(certificate);
        certificateService.validate(certificate);
        resultMap = MetaDefinitions.deserializeValidation(certificate.getCertificateValidationResult());
        Assertions
                .assertEquals(CertificateValidationStatus.FAILED,
                        resultMap.get(CertificateValidationCheck.SIGNATURE_VERIFICATION).getStatus());
        Assertions
                .assertEquals("Signature verification failed. Alternative signature verification failed.",
                        resultMap.get(CertificateValidationCheck.SIGNATURE_VERIFICATION).getMessage());

    }

    @Test
    void testExpiringCertificate() throws CertificateException, NoSuchAlgorithmException, OperatorCreationException {

        LocalDate today = LocalDate.now();
        // Expiring according to platform settings with null RA Profile
        LocalDate expiringDate = today.plusDays(29);
        X509Certificate x509Certificate = createCertificateWithCustomNotAfter(
                Date.from(expiringDate.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        certificate
                .getCertificateContent()
                .setContent(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));

        certificateService.validate(certificate);
        Map<CertificateValidationCheck, CertificateValidationCheckDto> resultMap = MetaDefinitions
                .deserializeValidation(certificate.getCertificateValidationResult());
        Assertions
                .assertEquals(CertificateValidationStatus.EXPIRING,
                        resultMap.get(CertificateValidationCheck.CERTIFICATE_VALIDITY).getStatus());

        // Expiring according to platform settings with not null RA Profile, but null validation enabled
        certificate.setRaProfile(getRaProfile(new RaProfileCertificateValidationSettingsUpdateDto()));
        certificateService.validate(certificate);
        resultMap = MetaDefinitions.deserializeValidation(certificate.getCertificateValidationResult());
        Assertions
                .assertEquals(CertificateValidationStatus.EXPIRING,
                        resultMap.get(CertificateValidationCheck.CERTIFICATE_VALIDITY).getStatus());

        // Expiring according to RA Profile settings
        RaProfileCertificateValidationSettingsUpdateDto validationSettingsUpdateDto = new RaProfileCertificateValidationSettingsUpdateDto();
        validationSettingsUpdateDto.setEnabled(true);
        validationSettingsUpdateDto.setExpiringThreshold(10);
        certificate.setRaProfile(getRaProfile(validationSettingsUpdateDto));

        // Certificate is not yet expiring
        certificateService.validate(certificate);
        resultMap = MetaDefinitions.deserializeValidation(certificate.getCertificateValidationResult());
        Assertions
                .assertEquals(CertificateValidationStatus.VALID,
                        resultMap.get(CertificateValidationCheck.CERTIFICATE_VALIDITY).getStatus());

        // Certificate is expiring
        expiringDate = today.plusDays(9);
        x509Certificate = createCertificateWithCustomNotAfter(
                Date.from(expiringDate.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        certificate
                .getCertificateContent()
                .setContent(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));
        certificateService.validate(certificate);
        resultMap = MetaDefinitions.deserializeValidation(certificate.getCertificateValidationResult());
        Assertions
                .assertEquals(CertificateValidationStatus.EXPIRING,
                        resultMap.get(CertificateValidationCheck.CERTIFICATE_VALIDITY).getStatus());
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

    private X509Certificate createCertificateWithCustomNotAfter(Date notAfter)
            throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Principal issuer = new X500Principal("CN=" + certificate.getIssuerDn());
        Date notBefore = new Date();
        BigInteger serialNumber = BigInteger.ONE;

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore,
                notAfter, issuer, keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certificateHolder);
    }

    @Test
    void testConstructingCertificateChainForSelfSignedCertificate() throws NotFoundException {
        CertificateChainResponseDto certificateChainResponseDto = certificateService
                .getCertificateChain(caCertificate.getSecuredUuid(), false);
        Assertions.assertEquals(0, certificateChainResponseDto.getCertificates().size());
        CertificateChainResponseDto certificateChainResponseDto2 = certificateService
                .getCertificateChain(caCertificate.getSecuredUuid(), true);
        Assertions.assertEquals(1, certificateChainResponseDto2.getCertificates().size());
    }

    @Test
    void testGetCertificateChain() throws NotFoundException {
        CertificateChainResponseDto certificateChainResponseDto = certificateService
                .getCertificateChain(chainIncompleteCertificate.getSecuredUuid(), false);
        Assertions.assertTrue(certificateChainResponseDto.isCompleteChain());
        CertificateChainResponseDto certificateChainCompleteResponseDto = certificateService
                .getCertificateChain(chainCompleteCertificate.getSecuredUuid(), false);
        Assertions.assertTrue(certificateChainCompleteResponseDto.isCompleteChain());
        List<CertificateDetail> certificates = certificateChainCompleteResponseDto.getCertificates();
        Assertions
                .assertEquals(chainCompleteCertificate.getIssuerDn(),
                        certificates.get(certificates.size() - 1).getSubjectDn());
        Assertions.assertEquals(1, certificates.size());
        CertificateChainResponseDto certificateChainCompleteResponseDto2 = certificateService
                .getCertificateChain(chainCompleteCertificate.getSecuredUuid(), true);
        Assertions.assertEquals(2, certificateChainCompleteResponseDto2.getCertificates().size());
        Assertions.assertTrue(certificateChainCompleteResponseDto.isCompleteChain());
    }

    @Test
    void testDownloadCertificateChain() throws NotFoundException, CertificateException, CMSException, IOException {
        CertificateChainDownloadResponseDto certificateChainIncompletePEMDownloadResponseDto = certificateService
                .downloadCertificateChain(chainIncompleteCertificate.getSecuredUuid(), CertificateFormat.RAW, true,
                        CertificateFormatEncoding.PEM);
        Assertions
                .assertEquals(2,
                        getNumberOfCertificatesInPem(certificateChainIncompletePEMDownloadResponseDto.getContent()));
        Assertions.assertTrue(certificateChainIncompletePEMDownloadResponseDto.isCompleteChain());
        CertificateChainDownloadResponseDto certificateChainCompletePEMResponseDto = certificateService
                .downloadCertificateChain(chainCompleteCertificate.getSecuredUuid(), CertificateFormat.RAW, true,
                        CertificateFormatEncoding.PEM);
        Assertions.assertTrue(certificateChainCompletePEMResponseDto.isCompleteChain());
        Assertions.assertEquals(2, getNumberOfCertificatesInPem(certificateChainCompletePEMResponseDto.getContent()));
        CertificateChainDownloadResponseDto certificateChainCompletePKCS7ResponseDto = certificateService
                .downloadCertificateChain(chainCompleteCertificate.getSecuredUuid(), CertificateFormat.PKCS7, true,
                        CertificateFormatEncoding.PEM);
        Assertions.assertTrue(certificateChainCompletePKCS7ResponseDto.isCompleteChain());
        Assertions
                .assertEquals(2, getNumberOfCertificatesInPkcs7(certificateChainCompletePKCS7ResponseDto.getContent()));
        CertificateChainDownloadResponseDto certificateChainResponseDto = certificateService
                .downloadCertificateChain(chainCompleteCertificate.getSecuredUuid(), CertificateFormat.PKCS7, false,
                        CertificateFormatEncoding.PEM);
        Assertions.assertTrue(certificateChainResponseDto.isCompleteChain());
        Assertions.assertEquals(1, getNumberOfCertificatesInPkcs7(certificateChainResponseDto.getContent()));

    }

    @Test
    void testOcspValidationCheck() throws Exception {
        var certificateChainInfo = CertificateGeneratorHelper
                .generateCertificateWithIssuer(KeyAlgorithm.RSA, "CN=Test-Ca", "CN=Test-EndEntity",
                        LoopbackWireMock.url(mockServer) + "/ocsp");

        uploadCertificate(certificateChainInfo.getCaCertificateBase64Encoded());

        KeyPair ecdsaKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.ECDSA, null);
        X509Certificate ecdsaX509Certificate = CertificateGeneratorHelper
                .generateEndEntityCertificate(certificateChainInfo.getCaCertificateKeyPair(),
                        certificateChainInfo.getCaCertificate(), ecdsaKeyPair, "CN=Test-EndEntity-ECDSA", null);
        Certificate certificateEcdsa = uploadCertificate(
                Base64.getEncoder().encodeToString(ecdsaX509Certificate.getEncoded()));

        var validationResult = certificateService.getCertificateValidationResult(certificateEcdsa.getSecuredUuid());
        Assertions
                .assertEquals(CertificateValidationStatus.NOT_CHECKED,
                        validationResult
                                .getValidationChecks()
                                .get(CertificateValidationCheck.OCSP_VERIFICATION)
                                .getStatus());

        Certificate certificateEndEntity = uploadCertificate(
                certificateChainInfo.getEndEntityCertificateBase64Encoded());

        validationResult = certificateService.getCertificateValidationResult(certificateEndEntity.getSecuredUuid());
        Assertions
                .assertEquals(CertificateValidationStatus.FAILED,
                        validationResult
                                .getValidationChecks()
                                .get(CertificateValidationCheck.OCSP_VERIFICATION)
                                .getStatus());

        OCSPResp ocspResp = CertificateGeneratorHelper
                .generateOCSPResponse(certificateChainInfo.getCaCertificate(),
                        certificateChainInfo.getCaCertificateKeyPair().getPrivate(),
                        certificateChainInfo.getEndEntityCertificate(), CertificateStatus.GOOD);
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/ocsp"))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/ocsp-response")
                                .withBody(ocspResp.getEncoded())));

        validationResult = certificateService.getCertificateValidationResult(certificateEndEntity.getSecuredUuid());
        Assertions
                .assertEquals(CertificateValidationStatus.VALID,
                        validationResult
                                .getValidationChecks()
                                .get(CertificateValidationCheck.OCSP_VERIFICATION)
                                .getStatus());

        mockServer.resetAll();
    }

    @Test
    void reportsOcspFailed_whenAuthorityInfoAccessExtensionIsMalformed() throws Exception {
        // given
        byte[] noAccessDescriptions = new DERSequence().getEncoded();
        Certificate endEntity = uploadEndEntityWithAuthorityInfoAccess(noAccessDescriptions);

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(endEntity.getSecuredUuid());

        // then
        assertThat(result.getValidationChecks())
                .containsOnlyKeys(CertificateValidationCheck.values())
                .hasEntrySatisfying(CertificateValidationCheck.OCSP_VERIFICATION, ocspCheck -> {
                    assertThat(ocspCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
                    assertThat(ocspCheck.getMessage()).contains("The authorityInfoAccess extension is malformed");
                })
                .hasEntrySatisfying(CertificateValidationCheck.BASIC_CONSTRAINTS,
                        basicConstraintsCheck -> assertThat(basicConstraintsCheck.getStatus())
                                .isEqualTo(CertificateValidationStatus.VALID));
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void logsDecoderFailure_whenAuthorityInfoAccessExtensionIsMalformed(CapturedOutput output) throws Exception {
        // given
        byte[] noAccessDescriptions = new DERSequence().getEncoded();
        Certificate endEntity = uploadEndEntityWithAuthorityInfoAccess(noAccessDescriptions);

        // when
        certificateService.getCertificateValidationResult(endEntity.getSecuredUuid());

        // then
        assertThat(output.getOut()).contains("Caused by: java.lang.IllegalArgumentException");
    }

    @Test
    void testCrlProcessing_noCrlAvailable_failsCheck()
            throws GeneralSecurityException, OperatorCreationException, IOException, NotFoundException {
        long stamp = System.nanoTime();
        List<String> crlUrls = List
                .of(LoopbackWireMock.url(mockServer) + "/p1a-" + stamp + ".crl",
                        LoopbackWireMock.url(mockServer) + "/p1b-" + stamp + ".crl");
        X509Certificate cert = createSelfSignedCertificateWithCrl("testCrlNone-" + stamp, crlUrls, null,
                BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));

        var result = certificateService.getCertificateValidationResult(entity.getSecuredUuid());
        Assertions
                .assertEquals(CertificateValidationStatus.FAILED,
                        result.getValidationChecks().get(CertificateValidationCheck.CRL_VERIFICATION).getStatus());
    }

    @Test
    void reportsCrlValid_whenIssuerSignedCrlListsNothing() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/p2-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlEmpty-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + urlPath), null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(urlPath, createEmptyCRL(cert, issuerKeyPair.getPrivate()).getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.VALID);
        assertThat(findStoredCrl(cert)).isPresent();
        assertThat(findStoredCrlEntry(cert, cert.getSerialNumber())).isEmpty();
    }

    @Test
    void reportsCrlFailed_whenCrlDistributionPointsExtensionIsMalformed() throws Exception {
        // given
        long stamp = System.nanoTime();
        List<String> noDistributionPoints = List.of();
        X509Certificate cert = createSelfSignedCertificateWithCrl("testCrlMalformed-" + stamp, noDistributionPoints,
                null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("The cRLDistributionPoints extension is malformed");
    }

    @Test
    void reportsCrlFailed_whenFreshestCrlExtensionIsMalformed() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/malformed-delta-base-" + stamp + ".crl";
        List<String> noDeltaCrlDistributionPoints = List.of();
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaMalformed-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath), noDeltaCrlDistributionPoints, BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate()).build().getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("The freshestCRL extension is malformed");
    }

    @Test
    void keepsBaseCrlRevocation_whenFreshestCrlExtensionIsMalformed() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/malformed-delta-revoking-base-" + stamp + ".crl";
        List<String> noDeltaCrlDistributionPoints = List.of();
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair,
                "testCrlDeltaMalformedRevoked-" + stamp, List.of(LoopbackWireMock.url(mockServer) + basePath),
                noDeltaCrlDistributionPoints, BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void logsDecoderFailure_whenCrlDistributionPointsExtensionIsMalformed(CapturedOutput output) throws Exception {
        // given
        long stamp = System.nanoTime();
        List<String> noDistributionPoints = List.of();
        X509Certificate cert = createSelfSignedCertificateWithCrl("testCrlMalformedLogged-" + stamp,
                noDistributionPoints, null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));

        // when
        certificateService.getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(output.getOut()).contains("Caused by: java.lang.IllegalArgumentException");
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void logsDecoderFailure_whenStoredCrlKeepsCertificateRevoked(CapturedOutput output) throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/malformed-delta-logged-base-" + stamp + ".crl";
        List<String> noDeltaCrlDistributionPoints = List.of();
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaMalformedLogged-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath), noDeltaCrlDistributionPoints, BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());

        // when
        certificateService.getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(output.getOut()).contains("Caused by: java.lang.IllegalArgumentException");
    }

    @Test
    void replacesCrlEntries_whenRefreshedCrlHasHigherNumber() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/p3-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlUpdate-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + urlPath), null, BigInteger.ONE);
        createTrustedCertEntity(cert);
        BigInteger replacedSerialNumber = BigInteger.valueOf(0x99);
        BigInteger replacementSerialNumber = BigInteger.valueOf(0xAA);
        stubCrlPoint(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(replacedSerialNumber, CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        UUID crlUuid = crlService.getCurrentCrl(cert, cert);
        CrlEntryId replacedEntryId = new CrlEntryId(crlUuid, replacedSerialNumber.toString(16));
        assertThat(crlEntryRepository.findById(replacedEntryId)).as("entry of the first CRL").isPresent();
        markStoredCrlDue(cert);
        replaceStub(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withRevocation(replacementSerialNumber, CRLReason.affiliationChanged)
                        .build()
                        .getEncoded());

        // when
        UUID refreshedCrlUuid = crlService.getCurrentCrl(cert, cert);

        // then
        assertThat(refreshedCrlUuid).as("the refresh keeps the CRL row").isEqualTo(crlUuid);
        assertThat(crlEntryRepository.findById(replacedEntryId)).as("entry of the first CRL").isEmpty();
        assertThat(crlEntryRepository.findById(new CrlEntryId(crlUuid, replacementSerialNumber.toString(16))))
                .as("entry of the refreshed CRL")
                .isPresent();
    }

    @Test
    void reportsCrlRevoked_whenSecondDistributionPointListsCertificate() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String unansweredPath = "/p4-bad-" + stamp + ".crl";
        String listingPath = "/p4-ok-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlRevoked-" + stamp, List
                .of(LoopbackWireMock.url(mockServer) + unansweredPath, LoopbackWireMock.url(mockServer) + listingPath),
                null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        X509CRL revokingCrl = addRevocationToCRL(issuerKeyPair.getPrivate(), "SHA256WithRSAEncryption",
                createEmptyCRL(cert, issuerKeyPair.getPrivate()),
                Map.of(cert.getSerialNumber(), CRLReason.keyCompromise));
        stubCrlPoint(listingPath, revokingCrl.getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
        assertThat(findStoredCrlEntry(cert, cert.getSerialNumber())).isPresent();
    }

    @Test
    void storesDeltaCrlState_whenDeltaCrlExtendsBaseCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/p5-base-" + stamp + ".crl";
        String deltaPath = "/p5-delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaOk-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        createTrustedCertEntity(cert);
        stubCrlPoint(basePath, createEmptyCRL(cert, issuerKeyPair.getPrivate()).getEncoded());
        BigInteger baseCrlNumber = BigInteger.TWO;
        stubCrlPoint(deltaPath, createEmptyDeltaCRL(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate(),
                baseCrlNumber, BigInteger.valueOf(3)).getEncoded());

        // when
        UUID crlUuid = crlService.getCurrentCrl(cert, cert);

        // then
        Crl storedCrl = crlRepository.findByUuid(SecuredUUID.fromUUID(crlUuid)).orElseThrow();
        assertThat(storedCrl.getCrlNumberDelta()).isNotNull();
        assertThat(storedCrl.getNextUpdateDelta()).isNotNull();
    }

    @Test
    void reportsCrlFailed_whenDeltaCrlNeedsNewerBaseCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/p6-base-" + stamp + ".crl";
        String deltaPath = "/p6-delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaBad-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath, createEmptyCRL(cert, issuerKeyPair.getPrivate()).getEncoded());
        BigInteger unpublishedBaseCrlNumber = BigInteger.valueOf(3);
        stubCrlPoint(deltaPath, createEmptyDeltaCRL(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate(),
                unpublishedBaseCrlNumber, BigInteger.TWO).getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = result
                .getValidationChecks()
                .get(CertificateValidationCheck.CRL_VERIFICATION);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("lower than the base CRL number " + unpublishedBaseCrlNumber);
    }

    @Test
    void keepsBaseCrlRevocation_whenDeltaCrlNamesAnotherIssuer() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/p7-base-" + stamp + ".crl";
        String deltaPath = "/p7-delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaIssuer-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        X500Principal anotherIssuerName = new X500Principal("CN=Another-Crl-Issuer");
        stubCrlPoint(deltaPath,
                anX509Crl(anotherIssuerName, issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.removeFromCRL)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    @Test
    void appliesDeltaCrlEntries_whenDeltaCrlExtendsBaseCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/p8-base-" + stamp + ".crl";
        String deltaPath = "/p8-delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaApply-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        BigInteger removedSerialNumber = BigInteger.valueOf(123);
        BigInteger changedSerialNumber = BigInteger.valueOf(1234);
        X509CRL baseCrl = addRevocationToCRL(issuerKeyPair.getPrivate(), "SHA256WithRSAEncryption",
                createEmptyCRL(cert, issuerKeyPair.getPrivate()),
                Map.of(removedSerialNumber, CRLReason.keyCompromise, changedSerialNumber, CRLReason.cACompromise));
        stubCrlPoint(basePath, baseCrl.getEncoded());
        X509CRL deltaCrl = addRevocationToCRL(issuerKeyPair.getPrivate(), "SHA256WithRSAEncryption",
                createEmptyDeltaCRL(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate(), BigInteger.TWO,
                        BigInteger.TWO),
                Map
                        .of(removedSerialNumber, CRLReason.removeFromCRL, changedSerialNumber, CRLReason.keyCompromise,
                                cert.getSerialNumber(), CRLReason.cACompromise));
        stubCrlPoint(deltaPath, deltaCrl.getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
        assertThat(findStoredCrlEntry(cert, cert.getSerialNumber())).as("entry the delta CRL adds").isPresent();
        assertThat(findStoredCrlEntry(cert, removedSerialNumber)).as("entry the delta CRL removes").isEmpty();
        assertThat(findStoredCrlEntry(cert, changedSerialNumber))
                .as("entry the delta CRL changes")
                .hasValueSatisfying(entry -> assertThat(entry.getRevocationReason())
                        .isEqualTo(CertificateRevocationReason.KEY_COMPROMISE));
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void reportsCrlFailed_whenCrlIsNotSignedByIssuer(CapturedOutput output) throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        KeyPair forgerKeyPair = freshRsaKeyPair();
        String urlPath = "/forged-" + stamp + ".crl";
        String crlUrl = LoopbackWireMock.url(mockServer) + urlPath;
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlForged-" + stamp,
                List.of(crlUrl), null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(urlPath, createEmptyCRL(cert, forgerKeyPair.getPrivate()).getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = result
                .getValidationChecks()
                .get(CertificateValidationCheck.CRL_VERIFICATION);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("its signature does not verify with the issuer's public key");
        assertThat(findStoredCrl(cert)).isEmpty();
        assertThat(output.getOut().lines().filter(line -> line.contains("Ignoring the CRL from " + crlUrl)))
                .isNotEmpty()
                .allSatisfy(line -> assertThat(line).contains("WARN"));
    }

    @Test
    void keepsStoredCrl_whenRefreshedCrlIsNotSignedByIssuer() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        KeyPair forgerKeyPair = freshRsaKeyPair();
        String urlPath = "/refresh-forged-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlRefreshForged-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + urlPath), null, BigInteger.ONE);
        createTrustedCertEntity(cert);
        stubCrlPoint(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        UUID crlUuid = crlService.getCurrentCrl(cert, cert);
        markStoredCrlDue(cert);
        replaceStub(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), forgerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .build()
                        .getEncoded());

        // when
        ThrowingCallable refreshCrl = () -> crlService.getCurrentCrl(cert, cert);

        // then
        assertThatThrownBy(refreshCrl).isInstanceOf(IOException.class);
        assertThat(crlEntryRepository.findById(new CrlEntryId(crlUuid, cert.getSerialNumber().toString(16))))
                .as("revocation listed by the stored CRL")
                .isPresent();
    }

    @Test
    void keepsBaseCrlRevocation_whenDeltaCrlIsNotSignedByIssuer() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        KeyPair forgerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-forged-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaForged-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                addRevocationToCRL(issuerKeyPair.getPrivate(), "SHA256WithRSAEncryption",
                        createEmptyCRL(cert, issuerKeyPair.getPrivate()),
                        Map.of(cert.getSerialNumber(), CRLReason.keyCompromise)).getEncoded());
        X509CRL forgedDeltaCrl = addRevocationToCRL(forgerKeyPair.getPrivate(), "SHA256WithRSAEncryption",
                createEmptyDeltaCRL(cert.getSubjectX500Principal(), forgerKeyPair.getPrivate(), BigInteger.TWO,
                        BigInteger.TWO),
                Map.of(cert.getSerialNumber(), CRLReason.removeFromCRL));
        stubCrlPoint(deltaPath, forgedDeltaCrl.getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    @Test
    void keepsBaseCrlRevocation_whenDeltaCrlIsUnreachable() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String unansweredDeltaPath = "/delta-missing-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaMissing-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + unansweredDeltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                addRevocationToCRL(issuerKeyPair.getPrivate(), "SHA256WithRSAEncryption",
                        createEmptyCRL(cert, issuerKeyPair.getPrivate()),
                        Map.of(cert.getSerialNumber(), CRLReason.keyCompromise)).getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void reportsCrlFailed_whenCrlIsPastNextUpdate(CapturedOutput output) throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/stale-" + stamp + ".crl";
        String crlUrl = LoopbackWireMock.url(mockServer) + urlPath;
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlStale-" + stamp,
                List.of(crlUrl), null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        Instant beyondClockSkew = Instant.now().minus(Duration.ofMinutes(10));
        stubCrlPoint(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withNextUpdate(beyondClockSkew)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("it is not current");
        assertThat(findStoredCrl(cert)).isEmpty();
        assertCrlIgnoredWithWarning(output, crlUrl);
    }

    @Test
    void reportsCrlValid_whenCrlIsPastNextUpdateWithinClockSkew() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/skew-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlSkew-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + urlPath), null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        Instant withinClockSkew = Instant.now().minus(Duration.ofMinutes(1));
        stubCrlPoint(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withNextUpdate(withinClockSkew)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.VALID);
    }

    @Test
    void reportsCrlFailed_whenCrlHasNoNextUpdate() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/no-next-update-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlNoNextUpdate-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + urlPath), null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withNextUpdate(null)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("it is not current");
        assertThat(findStoredCrl(cert)).isEmpty();
    }

    @Test
    void reportsCrlFailed_whenCrlHasNoCrlNumber() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/no-number-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlNoNumber-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + urlPath), null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(null)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("it has no CRL number");
        assertThat(findStoredCrl(cert)).isEmpty();
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void reportsCrlFailed_whenCrlNamesAnotherIssuer(CapturedOutput output) throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/other-issuer-" + stamp + ".crl";
        String crlUrl = LoopbackWireMock.url(mockServer) + urlPath;
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlOtherIssuer-" + stamp,
                List.of(crlUrl), null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        X500Principal anotherIssuerName = new X500Principal("CN=Another-Crl-Issuer-" + stamp);
        stubCrlPoint(urlPath, anX509Crl(anotherIssuerName, issuerKeyPair.getPrivate()).build().getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("it names another issuer");
        assertThat(findStoredCrl(cert)).isEmpty();
        assertCrlIgnoredWithWarning(output, crlUrl);
    }

    @Test
    void reportsCrlValid_whenCrlSpellsIssuerNameDifferently() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/issuer-spelling-" + stamp + ".crl";
        String commonName = "testCrlIssuerSpelling-" + stamp;
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, commonName,
                List.of(LoopbackWireMock.url(mockServer) + urlPath), null, BigInteger.ONE);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        X500Name capitalizedPrintableName = new X500Name(
                new RDN[]{new RDN(BCStyle.CN, new DERPrintableString(commonName.toUpperCase(Locale.ROOT)))});
        X500Principal sameIssuerSpelledDifferently = new X500Principal(capitalizedPrintableName.getEncoded());
        stubCrlPoint(urlPath, anX509Crl(sameIssuerSpelledDifferently, issuerKeyPair.getPrivate()).build().getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.VALID);
    }

    @Test
    void keepsStoredCrl_whenRefreshedCrlIsPastNextUpdate() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/refresh-stale-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlRefreshStale-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + urlPath), null, BigInteger.ONE);
        createTrustedCertEntity(cert);
        stubCrlPoint(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        UUID crlUuid = crlService.getCurrentCrl(cert, cert);
        markStoredCrlDue(cert);
        Instant beyondClockSkew = Instant.now().minus(Duration.ofMinutes(10));
        replaceStub(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withNextUpdate(beyondClockSkew)
                        .build()
                        .getEncoded());

        // when
        ThrowingCallable refreshCrl = () -> crlService.getCurrentCrl(cert, cert);

        // then
        assertThatThrownBy(refreshCrl).isInstanceOf(IOException.class).hasMessageContaining("it is not current");
        assertThat(crlEntryRepository.findById(new CrlEntryId(crlUuid, cert.getSerialNumber().toString(16))))
                .as("revocation listed by the stored CRL")
                .isPresent();
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void keepsStoredCrl_whenRefreshedCrlHasLowerNumber(CapturedOutput output) throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/rollback-" + stamp + ".crl";
        String crlUrl = LoopbackWireMock.url(mockServer) + urlPath;
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlRollback-" + stamp,
                List.of(crlUrl), null, BigInteger.ONE);
        createTrustedCertEntity(cert);
        stubCrlPoint(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        UUID crlUuid = crlService.getCurrentCrl(cert, cert);
        markStoredCrlDue(cert);
        BigInteger lowerCrlNumber = BigInteger.TWO;
        replaceStub(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(lowerCrlNumber)
                        .build()
                        .getEncoded());

        // when
        ThrowingCallable refreshCrl = () -> crlService.getCurrentCrl(cert, cert);

        // then
        assertThatThrownBy(refreshCrl)
                .isInstanceOf(IOException.class)
                .hasMessageContaining("is lower than the stored CRL number");
        assertThat(crlEntryRepository.findById(new CrlEntryId(crlUuid, cert.getSerialNumber().toString(16))))
                .as("revocation listed by the stored CRL")
                .isPresent();
        assertCrlIgnoredWithWarning(output, crlUrl);
    }

    @Test
    void keepsDeltaCrlRevocation_whenRefreshedCrlPredatesAppliedDeltaCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        String commonName = "testCrlDeltaRollback-" + stamp;
        String baseCrlUrl = LoopbackWireMock.url(mockServer) + basePath;
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, commonName, List.of(baseCrlUrl),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509Certificate sameIssuerWithoutDeltaCrl = createSelfSignedCertificateWithCrl(issuerKeyPair, commonName,
                List.of(baseCrlUrl), null, BigInteger.valueOf(3));
        createTrustedCertEntity(cert);
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(4))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        UUID crlUuid = crlService.getCurrentCrl(cert, cert);
        markStoredCrlDue(cert);
        BigInteger predatesDeltaCrl = BigInteger.valueOf(3);
        replaceStub(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(predatesDeltaCrl)
                        .build()
                        .getEncoded());

        // when
        ThrowingCallable refreshCrl = () -> crlService.getCurrentCrl(sameIssuerWithoutDeltaCrl, cert);

        // then
        assertThatThrownBy(refreshCrl)
                .isInstanceOf(IOException.class)
                .hasMessageContaining("is lower than the stored CRL number");
        assertThat(crlEntryRepository.findById(new CrlEntryId(crlUuid, cert.getSerialNumber().toString(16))))
                .as("revocation listed by the applied delta CRL")
                .isPresent();
    }

    @Test
    void keepsDeltaCrlRevocation_whenSameRequestRefreshesCrlAfterApplyingDeltaCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        String commonName = "testCrlRequestDeltaRollback-" + stamp;
        String baseCrlUrl = LoopbackWireMock.url(mockServer) + basePath;
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, commonName, List.of(baseCrlUrl),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509Certificate sameIssuerWithoutDeltaCrl = createSelfSignedCertificateWithCrl(issuerKeyPair, commonName,
                List.of(baseCrlUrl), null, BigInteger.valueOf(3));
        createTrustedCertEntity(cert);
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(sameIssuerWithoutDeltaCrl, cert);
        markStoredCrlDue(cert);
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(4))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        X509CRL predatesDeltaCrl = anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                .withCrlNumber(BigInteger.valueOf(3))
                .build();

        // when
        ThrowingCallable applyDeltaThenRefreshInOneRequest = () -> runInOneRequest(() -> {
            crlService.getCurrentCrl(cert, cert);
            replaceStub(basePath, predatesDeltaCrl.getEncoded());
            crlService.getCurrentCrl(sameIssuerWithoutDeltaCrl, cert);
        });

        // then
        assertThatThrownBy(applyDeltaThenRefreshInOneRequest)
                .isInstanceOf(IOException.class)
                .hasMessageContaining("is lower than the stored CRL number");
        assertThat(findStoredCrlEntry(cert, cert.getSerialNumber()))
                .as("revocation listed by the applied delta CRL")
                .isPresent();
    }

    @Test
    void keepsDeltaCrlRevocation_whenSameRequestRefreshesCrlItStored() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        String commonName = "testCrlRequestStoredRollback-" + stamp;
        String baseCrlUrl = LoopbackWireMock.url(mockServer) + basePath;
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, commonName, List.of(baseCrlUrl),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509Certificate sameIssuerWithoutDeltaCrl = createSelfSignedCertificateWithCrl(issuerKeyPair, commonName,
                List.of(baseCrlUrl), null, BigInteger.valueOf(3));
        createTrustedCertEntity(cert);
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(BigInteger.valueOf(0x99), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(4))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        X509CRL predatesDeltaCrl = anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                .withCrlNumber(BigInteger.valueOf(3))
                .build();

        // when
        ThrowingCallable storeThenRefreshInOneRequest = () -> runInOneRequest(() -> {
            crlService.getCurrentCrl(cert, cert);
            replaceStub(basePath, predatesDeltaCrl.getEncoded());
            markStoredCrlDue(cert);
            crlService.getCurrentCrl(sameIssuerWithoutDeltaCrl, cert);
        });

        // then
        assertThatThrownBy(storeThenRefreshInOneRequest)
                .isInstanceOf(IOException.class)
                .hasMessageContaining("is lower than the stored CRL number");
        assertThat(findStoredCrlEntry(cert, cert.getSerialNumber()))
                .as("revocation listed by the applied delta CRL")
                .isPresent();
    }

    @Test
    void keepsStoredCrl_whenRefreshedCrlIsDeltaCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String urlPath = "/refresh-delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlRefreshDelta-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + urlPath), null, BigInteger.ONE);
        createTrustedCertEntity(cert);
        stubCrlPoint(urlPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        UUID crlUuid = crlService.getCurrentCrl(cert, cert);
        markStoredCrlDue(cert);
        X509CRL deltaCrlListingNothing = anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                .withCrlNumber(BigInteger.valueOf(3))
                .withDeltaCrlIndicator(BigInteger.TWO)
                .build();
        replaceStub(urlPath, deltaCrlListingNothing.getEncoded());

        // when
        ThrowingCallable refreshCrl = () -> crlService.getCurrentCrl(cert, cert);

        // then
        assertThatThrownBy(refreshCrl).isInstanceOf(IOException.class).hasMessageContaining("it is a delta CRL");
        assertThat(crlEntryRepository.findById(new CrlEntryId(crlUuid, cert.getSerialNumber().toString(16))))
                .as("revocation listed by the stored CRL")
                .isPresent();
    }

    @Test
    void keepsBaseCrlRevocation_whenDeltaCrlIsCompleteCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-complete-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaComplete-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        X509CRL completeCrlListingNothing = anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                .withCrlNumber(BigInteger.valueOf(3))
                .build();
        stubCrlPoint(deltaPath, completeCrlListingNothing.getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    @Test
    void keepsBaseCrlRevocation_whenDeltaCrlIsPastNextUpdate() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-stale-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaStale-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        Instant beyondClockSkew = Instant.now().minus(Duration.ofMinutes(10));
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .withNextUpdate(beyondClockSkew)
                        .withRevocation(cert.getSerialNumber(), CRLReason.removeFromCRL)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    @Test
    void appliesNewerDeltaCrl_whenStoredDeltaCrlIsDue() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaDue-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);
        markStoredDeltaCrlDue(cert);
        X509CRL newerDeltaCrl = anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                .withCrlNumber(BigInteger.valueOf(4))
                .withDeltaCrlIndicator(BigInteger.TWO)
                .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                .build();
        replaceStub(deltaPath, newerDeltaCrl.getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    @Test
    void skipsDeltaCrlDownload_whenStoredDeltaCrlIsCurrent() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaCurrent-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        createTrustedCertEntity(cert);
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);

        // when
        crlService.getCurrentCrl(cert, cert);

        // then
        mockServer.verify(1, WireMock.getRequestedFor(WireMock.urlPathEqualTo(deltaPath)));
    }

    @Test
    void clearsDeltaCrlState_whenBaseCrlIsRefreshed() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        String commonName = "testCrlDeltaReset-" + stamp;
        String baseCrlUrl = LoopbackWireMock.url(mockServer) + basePath;
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, commonName, List.of(baseCrlUrl),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509Certificate sameIssuerWithoutDeltaCrl = createSelfSignedCertificateWithCrl(issuerKeyPair, commonName,
                List.of(baseCrlUrl), null, BigInteger.valueOf(3));
        createTrustedCertEntity(cert);
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);
        markStoredCrlDue(cert);
        BigInteger refreshedCrlNumber = BigInteger.valueOf(4);
        replaceStub(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(refreshedCrlNumber)
                        .build()
                        .getEncoded());

        // when
        UUID crlUuid = crlService.getCurrentCrl(sameIssuerWithoutDeltaCrl, cert);

        // then
        Crl storedCrl = crlRepository.findByUuid(SecuredUUID.fromUUID(crlUuid)).orElseThrow();
        assertThat(storedCrl.getCrlNumber()).isEqualTo(refreshedCrlNumber.toString());
        assertThat(storedCrl.getCrlNumberDelta()).isNull();
        assertThat(storedCrl.getNextUpdateDelta()).isNull();
    }

    @Test
    void appliesDeltaCrlOfRefreshedBaseCrl_whenOldDeltaCrlIsStillCurrent() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaOfRefresh-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);
        markStoredCrlDue(cert);
        BigInteger refreshedCrlNumber = BigInteger.valueOf(4);
        replaceStub(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(refreshedCrlNumber)
                        .build()
                        .getEncoded());
        replaceStub(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(5))
                        .withDeltaCrlIndicator(refreshedCrlNumber)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    @Test
    void appliesNewerDeltaCrl_whenStoredDeltaCrlIsOlderThanBaseCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaLeftBehind-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);
        BigInteger newerBaseCrlNumber = BigInteger.valueOf(4);
        keepStoredDeltaCrlUnderNewerBaseCrl(cert, newerBaseCrlNumber);
        replaceStub(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(newerBaseCrlNumber)
                        .build()
                        .getEncoded());
        replaceStub(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(5))
                        .withDeltaCrlIndicator(newerBaseCrlNumber)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    @Test
    void refreshesBaseCrl_whenDueDeltaCrlExtendsNewerBaseCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaNewerBase-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);
        markStoredDeltaCrlDue(cert);
        BigInteger newerBaseCrlNumber = BigInteger.valueOf(4);
        replaceStub(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(newerBaseCrlNumber)
                        .build()
                        .getEncoded());
        replaceStub(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(5))
                        .withDeltaCrlIndicator(newerBaseCrlNumber)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
        assertThat(findStoredCrl(cert))
                .hasValueSatisfying(crl -> assertThat(crl.getCrlNumber()).isEqualTo(newerBaseCrlNumber.toString()));
    }

    @Test
    void keepsStoredCrl_whenRefreshedCrlPredatesBaseCrlOfNewDeltaCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaOlderRefresh-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        BigInteger storedBaseCrlNumber = BigInteger.TWO;
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(storedBaseCrlNumber)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(storedBaseCrlNumber)
                        .withRevocation(cert.getSerialNumber(), CRLReason.certificateHold)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);
        markStoredDeltaCrlDue(cert);
        replaceStub(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(4))
                        .build()
                        .getEncoded());
        replaceStub(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(7))
                        .withDeltaCrlIndicator(BigInteger.valueOf(6))
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
        assertThat(findStoredCrl(cert))
                .hasValueSatisfying(crl -> assertThat(crl.getCrlNumber()).isEqualTo(storedBaseCrlNumber.toString()));
    }

    @Test
    void reportsCrlFailed_whenDeltaCrlIsUnreachable() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String unansweredDeltaPath = "/delta-missing-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaUnreachable-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + unansweredDeltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("usable delta CRL").contains("it could not be read");
    }

    @Test
    void reportsCrlFailed_whenDeltaCrlIsNotSignedByIssuer() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        KeyPair forgerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-forged-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaForgedOnly-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), forgerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("its signature does not verify with the issuer's public key");
    }

    @Test
    void reportsCrlFailed_whenDueDeltaCrlCannotBeDownloaded() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaDueMissing-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);
        markStoredDeltaCrlDue(cert);
        stopServing(deltaPath);

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("usable delta CRL").contains("it could not be read");
    }

    @Test
    void reportsCrlFailed_whenDeltaCrlThatReleasedHoldIsNoLongerCurrent() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaReleaseExpired-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.certificateHold)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.removeFromCRL)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);
        markStoredDeltaCrlDue(cert);
        Instant beyondClockSkew = Instant.now().minus(Duration.ofMinutes(10));
        replaceStub(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .withNextUpdate(beyondClockSkew)
                        .withRevocation(cert.getSerialNumber(), CRLReason.removeFromCRL)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("it is not current");
    }

    @Test
    void reportsCrlFailed_whenDeltaCrlIsOlderThanStoredDeltaCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaRollback-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(5))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);
        markStoredDeltaCrlDue(cert);
        BigInteger olderDeltaCrlNumber = BigInteger.valueOf(4);
        replaceStub(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(olderDeltaCrlNumber)
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage())
                .contains("its CRL number " + olderDeltaCrlNumber + " is lower than the stored CRL number");
    }

    @Test
    void throwsWithoutRefreshingBaseCrl_whenDeltaCrlExtendsOlderBaseCrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaOlderBase-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        createTrustedCertEntity(cert);
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(4))
                        .build()
                        .getEncoded());
        BigInteger olderBaseCrlNumber = BigInteger.TWO;
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(5))
                        .withDeltaCrlIndicator(olderBaseCrlNumber)
                        .build()
                        .getEncoded());

        // when
        ThrowingCallable getCurrentCrl = () -> crlService.getCurrentCrl(cert, cert);

        // then
        assertThatThrownBy(getCurrentCrl)
                .isInstanceOf(IOException.class)
                .hasMessageContaining("it extends base CRL number " + olderBaseCrlNumber);
        mockServer.verify(1, WireMock.getRequestedFor(WireMock.urlPathEqualTo(basePath)));
    }

    @Test
    void reportsCrlFailed_whenDeltaCrlHasNoUrl() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        GeneralNames directoryNameOnly = new GeneralNames(new GeneralName(new X500Name("CN=Delta-Crl-" + stamp)));
        DistributionPoint deltaCrlPointWithoutUrl = new DistributionPoint(new DistributionPointName(directoryNameOnly),
                null, null);
        X509Certificate cert = createSelfSignedCertificate(issuerKeyPair, "testCrlDeltaNoUrl-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath), new DistributionPoint[]{deltaCrlPointWithoutUrl},
                BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
        assertThat(crlCheck.getMessage()).contains("names a delta CRL without a URL");
    }

    @Test
    void keepsHoldListedByBaseCrl_whenDeltaCrlIsUnreachable() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String unansweredDeltaPath = "/delta-missing-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaMissingHold-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + unansweredDeltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.certificateHold)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        CertificateValidationCheckDto crlCheck = readCrlCheck(result);
        assertThat(crlCheck.getStatus()).isEqualTo(CertificateValidationStatus.REVOKED);
        assertThat(crlCheck.getMessage()).contains(CertificateRevocationReason.CERTIFICATE_HOLD.getLabel());
    }

    @Test
    void appliesDeltaCrl_whenItsNumberExceedsIntegerRange() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaLongNumber-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        BigInteger baseCrlNumber = BigInteger.valueOf(Integer.MAX_VALUE - 1L);
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(baseCrlNumber)
                        .build()
                        .getEncoded());
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(Integer.MAX_VALUE))
                        .withDeltaCrlIndicator(baseCrlNumber)
                        .build()
                        .getEncoded());
        crlService.getCurrentCrl(cert, cert);
        markStoredDeltaCrlDue(cert);
        BigInteger deltaCrlNumberBeyondIntRange = BigInteger.valueOf(Integer.MAX_VALUE).add(BigInteger.ONE);
        replaceStub(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(deltaCrlNumberBeyondIntRange)
                        .withDeltaCrlIndicator(baseCrlNumber)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
        assertThat(findStoredCrl(cert))
                .hasValueSatisfying(
                        crl -> assertThat(crl.getCrlNumberDelta()).isEqualTo(deltaCrlNumberBeyondIntRange.toString()));
    }

    @Test
    void appliesDeltaCrl_whenItIsPastNextUpdateWithinClockSkew() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaSkew-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        Instant withinClockSkew = Instant.now().minus(Duration.ofMinutes(1));
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .withNextUpdate(withinClockSkew)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    @Test
    void appliesDeltaCrl_whenItRemovesCertificateNotListed() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaRemovesUnlisted-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .build()
                        .getEncoded());
        BigInteger unlistedSerialNumber = BigInteger.valueOf(0x77);
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .withRevocation(unlistedSerialNumber, CRLReason.removeFromCRL)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
        assertThat(findStoredCrlEntry(cert, unlistedSerialNumber)).isEmpty();
    }

    @Test
    void appliesDeltaCrlRevocation_whenItPredatesBaseCrlRevocations() throws Exception {
        // given
        long stamp = System.nanoTime();
        KeyPair issuerKeyPair = freshRsaKeyPair();
        String basePath = "/base-" + stamp + ".crl";
        String deltaPath = "/delta-" + stamp + ".crl";
        X509Certificate cert = createSelfSignedCertificateWithCrl(issuerKeyPair, "testCrlDeltaBackdated-" + stamp,
                List.of(LoopbackWireMock.url(mockServer) + basePath),
                List.of(LoopbackWireMock.url(mockServer) + deltaPath), BigInteger.TWO);
        X509CertificateEntity entity = X509CertificateEntity.from(createTrustedCertEntity(cert));
        stubCrlPoint(basePath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.TWO)
                        .withRevocation(BigInteger.valueOf(0x66), CRLReason.keyCompromise)
                        .build()
                        .getEncoded());
        Instant beforeBaseCrlRevocations = Instant.now().minus(Duration.ofDays(1));
        stubCrlPoint(deltaPath,
                anX509Crl(cert.getSubjectX500Principal(), issuerKeyPair.getPrivate())
                        .withCrlNumber(BigInteger.valueOf(3))
                        .withDeltaCrlIndicator(BigInteger.TWO)
                        .withRevocation(cert.getSerialNumber(), CRLReason.keyCompromise, beforeBaseCrlRevocations)
                        .build()
                        .getEncoded());

        // when
        CertificateValidationResultDto result = certificateService
                .getCertificateValidationResult(entity.getSecuredUuid());

        // then
        assertThat(readCrlStatus(result)).isEqualTo(CertificateValidationStatus.REVOKED);
    }

    private Certificate createTrustedCertEntity(X509Certificate cert) {
        X509CertificateEntity entity = X509CertificateEntity.from(certificateService.createCertificateEntity(cert));
        entity.setTrustedCa(true);
        return certificateRepository.save(entity);
    }

    private static KeyPair freshRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    private void stubCrlPoint(String urlPart, byte[] body) {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching(urlPart))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/json")
                                .withHeader("Set-Cookie", "session_id=91837492837")
                                .withHeader("Set-Cookie", "split_test_group=B")
                                .withHeader("Cache-Control", "no-cache")
                                .withBody(body)));
    }

    private int getNumberOfCertificatesInPkcs7(String content) throws CMSException {
        String pkcs7Data = new String(Base64.getDecoder().decode(content));
        pkcs7Data = pkcs7Data
                .replace("-----BEGIN PKCS7-----", "")
                .replace("-----END PKCS7-----", "")
                .replaceAll("\\s", "");
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

    private X509CRL createEmptyCRL(X509Certificate caCert, PrivateKey caKey)
            throws CRLException, OperatorCreationException, CertIOException {
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(
                X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded()), calculateDate(0));
        crlGen.setNextUpdate(calculateDate(24 * 7));
        crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.TWO));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(caKey);

        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
        return converter.getCRL(crlGen.build(signer));
    }

    private X509CRL createEmptyDeltaCRL(X500Principal issuerDnPrincipal, PrivateKey caKey, BigInteger deltaCrlIndicator,
            BigInteger deltaCrlNumber) throws CRLException, OperatorCreationException, CertIOException {
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(X500Name.getInstance(issuerDnPrincipal.getEncoded()),
                calculateDate(0));
        crlGen.setNextUpdate(calculateDate(24 * 7));
        crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(deltaCrlNumber));
        crlGen.addExtension(Extension.deltaCRLIndicator, false, new CRLNumber(deltaCrlIndicator));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(caKey);

        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
        return converter.getCRL(crlGen.build(signer));
    }

    public X509CRL addRevocationToCRL(PrivateKey caKey, String sigAlg, X509CRL crl,
            Map<BigInteger, Integer> serialNumberAndRevocationReasonMap)
            throws IOException, GeneralSecurityException, OperatorCreationException {
        JcaX509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(crl);
        crlGen.setNextUpdate(calculateDate(24 * 7));

        // add revocations
        for (BigInteger serialNumber : serialNumberAndRevocationReasonMap.keySet()) {
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen
                    .addExtension(Extension.reasonCode, false, org.bouncycastle.asn1.x509.CRLReason
                            .lookup(serialNumberAndRevocationReasonMap.get(serialNumber)));
            crlGen.addCRLEntry(serialNumber, new Date(), extGen.generate());
        }

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caKey);
        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");

        return converter.getCRL(crlGen.build(signer));
    }

    @Test
    void testGetCertificateChainNullContent() throws NotFoundException {
        X509CertificateEntity certNoContent = aCertificate()
                .withSubjectDn("CN=NullContentCert")
                .withIssuerDn("CN=SomeIssuer")
                .withSerialNumber("000000")
                .withState(CertificateState.REQUESTED)
                .build();
        certNoContent.setNotBefore(new Date());
        certNoContent.setNotAfter(new Date());
        // intentionally no certificateContent set → null
        certNoContent = certificateRepository.save(certNoContent);

        CertificateChainResponseDto withoutEnd = certificateService
                .getCertificateChain(certNoContent.getSecuredUuid(), false);
        Assertions.assertTrue(withoutEnd.getCertificates() == null || withoutEnd.getCertificates().isEmpty());
        Assertions.assertFalse(withoutEnd.isCompleteChain());

        CertificateChainResponseDto withEnd = certificateService
                .getCertificateChain(certNoContent.getSecuredUuid(), true);
        Assertions.assertTrue(withEnd.getCertificates() == null || withEnd.getCertificates().isEmpty());
        Assertions.assertFalse(withEnd.isCompleteChain());
    }

    @Test
    void testGetCertificateChainWithEndCertificateIncompleteChain() throws NotFoundException {
        // chainIncompleteCertificate has no issuer pre-loaded in the DB
        CertificateChainResponseDto withoutEnd = certificateService
                .getCertificateChain(chainIncompleteCertificate.getSecuredUuid(), false);
        CertificateChainResponseDto withEnd = certificateService
                .getCertificateChain(chainIncompleteCertificate.getSecuredUuid(), true);

        // withEnd must have exactly one more certificate (the end certificate itself)
        Assertions.assertEquals(withoutEnd.getCertificates().size() + 1, withEnd.getCertificates().size());
        // The first certificate returned must be the end certificate
        Assertions
                .assertEquals(chainIncompleteCertificate.getSubjectDn(),
                        withEnd.getCertificates().get(0).getSubjectDn());
        // Chain-completeness judgement must be consistent regardless of withEndCertificate flag
        Assertions.assertEquals(withoutEnd.isCompleteChain(), withEnd.isCompleteChain());
    }

    @Test
    void testGetCertificateChainThreeLevelWithEndCertificate() throws Exception {
        // Build a three-level chain: root CA → intermediate CA → end entity
        KeyPair rootKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate rootX509 = CertificateGeneratorHelper.generateCACertificate(rootKeyPair, "CN=TestRoot3Level");

        KeyPair intermediateKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate intermediateX509 = generateIntermediateCACertificate(rootKeyPair, rootX509, intermediateKeyPair,
                "CN=TestIntermediate3Level");

        KeyPair eeKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate eeX509 = CertificateGeneratorHelper
                .generateEndEntityCertificate(intermediateKeyPair, intermediateX509, eeKeyPair,
                        "CN=TestEndEntity3Level", null);

        uploadCertificate(Base64.getEncoder().encodeToString(rootX509.getEncoded()));
        uploadCertificate(Base64.getEncoder().encodeToString(intermediateX509.getEncoded()));
        X509CertificateEntity eeCert = X509CertificateEntity
                .from(uploadCertificate(Base64.getEncoder().encodeToString(eeX509.getEncoded())));

        // withEndCertificate=false → chain is [intermediate, root], complete
        CertificateChainResponseDto withoutEnd = certificateService.getCertificateChain(eeCert.getSecuredUuid(), false);
        Assertions.assertEquals(2, withoutEnd.getCertificates().size());
        Assertions.assertTrue(withoutEnd.isCompleteChain());

        // withEndCertificate=true → chain is [endEntity, intermediate, root], complete
        CertificateChainResponseDto withEnd = certificateService.getCertificateChain(eeCert.getSecuredUuid(), true);
        Assertions.assertEquals(3, withEnd.getCertificates().size());
        Assertions.assertTrue(withEnd.isCompleteChain());

        // Verify ordering: end entity is first, root is last
        Assertions.assertEquals(eeCert.getSubjectDn(), withEnd.getCertificates().get(0).getSubjectDn());
        Assertions.assertEquals(eeCert.getIssuerDn(), withEnd.getCertificates().get(1).getSubjectDn());
        Assertions
                .assertEquals(rootX509.getSubjectX500Principal().getName(),
                        withEnd.getCertificates().get(2).getSubjectDn());
    }

    @Test
    void testGetCertificateChainCircularReferenceTerminates() throws Exception {
        // Create two self-signed certificates and then set up a circular issuer reference
        // in the DB (A → B → A) to verify that the recursive CTE cycle-detection terminates.
        KeyPair keyPairA = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate x509A = CertificateGeneratorHelper.generateCACertificate(keyPairA, "CN=CircularA");

        KeyPair keyPairB = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate x509B = CertificateGeneratorHelper.generateCACertificate(keyPairB, "CN=CircularB");

        // Introduce a circular FK relationship directly in the DB: A → B → A
        Certificate certA = uploadCertificate(Base64.getEncoder().encodeToString(x509A.getEncoded()));
        Certificate certB = uploadCertificate(Base64.getEncoder().encodeToString(x509B.getEncoded()));
        certA.setIssuerCertificateUuid(certB.getUuid());
        certB.setIssuerCertificateUuid(certA.getUuid());
        certificateRepository.save(certA);
        certificateRepository.save(certB);

        CertificateChainResponseDto chain = certificateService
                .getCertificateChain(certificateRepository.findByUuid(certA.getUuid()).orElseThrow().getSecuredUuid(),
                        false);

        Assertions.assertNotNull(chain);
        Assertions
                .assertTrue(chain.getCertificates().size() <= 1,
                        "Circular-reference chain should contain at most 1 ancestor (certB), but got: "
                                + chain.getCertificates().size());
        Assertions.assertTrue(chain.isCompleteChain());
    }

    private Certificate uploadCertificate(String base64cert) throws Exception {
        X509Certificate x509 = CertificateUtil.parseCertificate(base64cert);
        String fingerprint = CertificateUtil.getThumbprint(x509);
        CertificateUploadEventMessageData eventData = CertificateUploadEventMessageData
                .builder()
                .certificateContent(base64cert)
                .build();
        certificateUploadedEventHandler.handleEvent(CertificateUploadedEventHandler.constructEventMessage(eventData));
        return certificateRepository.findByFingerprint(fingerprint).orElseThrow();
    }

    private X509Certificate generateIntermediateCACertificate(KeyPair issuerKeyPair, X509Certificate issuerCert,
            KeyPair subjectKeyPair, String subjectDn) throws Exception {
        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date start = new Date();
        Date end = new Date(System.currentTimeMillis() + 3650 * 86400000L);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, start, end, subject,
                subjectKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    void testVerifyAlt() throws Exception {
        String certificateString = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSVc3VENDRmRXZ0F3SUJBZ0lVTjJMQllaSHNHeTg5LzBOdkdVemtGTjVKMkRZd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0lERWVNQndHQTFVRUF3d1ZTSGxpY21sa1pVTmxjblJwWm1sallYUmxJRU5CTUI0WERUSTFNRFV5TXpFeApNell4TVZvWERUSTNNRFV5TXpFeE16WXhNRm93RnpFVk1CTUdBMVVFQXd3TWFIbGljbWxrSUdWcVltTmhNSUlICnNqQUxCZ2xnaGtnQlpRTUVBeElEZ2dlaEFMZ0FpMnEycWFoWFFIUUJyVnZzOENhaFRBdDVZcmsrSU4rRHo5aWYKYzQ0SEQySEh3SGNpN3FQa1FGbFhJTXJVa3EzbnBDS0h4NEJONnFjRUxOalIxRkgrbFpPMHFVMDA5azdLTWNKRApoV2kxYmNKNGdraHZKZmIxaE92NDVjNklxcExQQmJRbmFVSFFQY2lHdWtwZnR1UjBqRTRLZi9FNW9sRGtuNUlPCnY4MmdUaEhYTVpNV2ZKaDkzTVVRSHU3K2ZkQjAxSmNJcmJRTUFRVnpEbmVlcldLcTdaT1JQcjBTdVhMUUlDUnYKY1B2UnFMMDdWaXYxaHd4MllXSU11M0VRcndDbGNDR2R6Wm1TYkdwaHUvMVFoSm5BUzlHTm1pVDl0VGUzdnJEYgpJaTJzZUthdkFsMjErM1FHTHl6N1BBb29YV0luZytoOENNeUVkK1B5dXJ2Y0dYNjdBbGdWNktBUU9pQTQwalBoClU4aDFnUU1xVVVFcE5HWTNxaEEzaE9HcHpPSGJFcUxESk5oZUM0azJORWpWY0ZQN0hacSs1QXpUcWJvNlRzN2MKSngraG0xak1hOXNrOEErbnFUdkRhVDEza1hZWlhFS2FuSnlrVW80SzY1TnJrcVlEcXMzYkgxTEJDMWlBUW5DUQptTzY3NW04aEhMZUhLaGdMenB2M21TZGx3dVprMHhtb1VadDFRUlNWM3BmT0ViTFYyR2VDSzFIdEtTellRZDU2CjFhZlpnaHZ3WFYyRVg4OFlnVTBaR1BwdUtMTW0rL3hYNHpHYlU3Qk50Z2FtalJWaldLd1Z5VFJ2WTJldzZkWU0KeFBGSmUrYlpvckhvbDdXaG1mVEdhalI0aWgxVE5JTEtuODNlY2hqcWJuaEh4dXRwOG5oU3o1VlBjSTJkS0RVaAo4Y2kra2VJUzNtKzFkTjRRUHlYWEdKNFFkSjltL0lQOXo4UU9QY3FESlB4NTlhQ1NRdjhvUGNCOG5wRUVveit4CkdEVk1lS09kWkVBaE1MN2ZNbGEzSDRpNFh2ZTRLWGkrTU1KbXo1V0hTY1gxb0hGcGh0ZGEvcG9FU3FUbmI1WC8KRE8zSUlkOEJPazAxcEpnYWNOM0VQWHB6ODBkbWR6NS91cDdpRFJPMW5uWXl2Vmd6czhCQ2N4a1hKMnFtalcxRwpUV2x5b2NqZnlJbXVua2JnaHJmTmxkVGlsNDZHcXhiMEUvYWtJTWFlUUhhVHFnUks1dE9EeEdudzRLWEhjNXFiCmFOS1JhVkNlWjlEb0ZreXMvZS82VVpGMHpIRjBld1FpWHpraUgrRUR2TGNXQlB2aUt5ei8zNk1ReUFlaXFKOHUKRHVUTjZMcEErU2ZOZk5FeE02VGZtS2FPcE1wczdDQzZUQ3dCOHdkT3JXRjRJRVFXQnFYbzRuMWF3SEdIckZxZgpjcDV2S2tCbHg5RmkvL0FzRWJWTWFtTkdpT2JVcDIvZmhBUVAvd2ZHd0I1eXRPYWx4aVpXZ0tJbVF5NjhJNkJZClhxRVBNcjJwalFOK1BzMyttWGRiYTlNc3VOcCs0S3dOdS9YQjJmZDVocW5aVUliTjcra2lLVytUeHl1THJ4SWoKanpoZU1DWTV3ekVadnpQU0JZenFZU0lxZUFLT2RWb3ltM3pQL2xEeUcwbnpEcHd5V2IwSmVuWUYzS1dvNUQwKwpkSmlVVTVhVk5ua3c4M29IM1FZczF3YlF1MENwbUQzMDhxYU9SRkdsWTZabENXeHRxdkZZR3pmaHNIWWZkTXZyCm9zbUYzdThHM29zMDFjRmE1SlNOT2JxSU43Uy9YVXVwcEtWcEIyUHRBNDJIMGpHSEZaOUcwbUVrYWZHUTRzUTQKQ0tEUmxYVmNwTkZUQVhRZkt0bUJkamVtbFJaSGc5TzJsZWg4V2I2bWVncWJSUWljRDU2SGx5TW9kTTJGdk5UawpETWFaSC8vb3dHUFJwc3NpbnhKcGVSM25GNUZHTStHSngxS3Q4YWcxTjRPcWExQ1ZJT1NMNXdhVTAxRjBFMnVCClFiYmEwcEVLYlp3bDNhSTJxc3hxZ1drT1NFT2tMOC84OUl4Nkxqa29pbVdKa0xHSmxaaUF4djUybHJ4bmpUcWMKcGpydDJyeDhaS3VuM1laZ2NURU0yY3NRUmFJVXBVSEdwaTNmOHpKNE5JcmZHRWlrWkNLZTM1RS91Zng5ZUFBVgpJMnBrZmM5eG82MUtpVnZMQjdrZXMrSXlFb1NodVZCcDJZUmE0cG1VNnI5Y1QzNDhQNE1LMjJUODkwVnJFM2NYCmR3dWJBSjg2M0Y2eFVhZ1E2ZkxweXVJZUo4NUgyQXBQamNjYWdETDY2SUlwaGZHZlVBbG9JZnhmK0R0Z0xrdTgKTVVwRXhmK01nakVFMXVEdHhhcml6RElwWU9xRzBSbWlHWDJWK01mTlZsNmwwZXVaYitlMFV0dHp0clk3VjJEQwoxbmxYTTlZQ1pMREx0SEt1QVlpaVk1QURueFd2dmYxUmQ5YUpQeC9UT1ZQQTA0TWJ3NStVTW9BMTdxN3dPRlNECndxMmN2azNZUHFTak43cW4xYm1JanJQdTU5R3k4NktoMHJQd051YWZWYnRTQThVditxVmJhWmlYQndNSDUyenUKYmpwbksxSVVTZTJMSDdIVkZyck1nNnBQZXArcHE4LzM2NjB2NG5KV0x0dC9MMzM0cWNEMHVoU3NwRFl3elB6Mwpza2pwNzdSV0VBaGNWTHRNVWNLa2w3ckovcUppR29aNVhwY3lmdUgrQkxKbWlXVE5zc1JmYTV1Yk0vVkI1dHlzCmF3ZU01L1JHbWc0NktpYXBicy8xZldpc2UybWFXUUpWU2N2TkZ5TDFjMnVNRjdadTFjMlpLb3NuZ1NaSzBkTWwKcHFYd1UvY2ZySysvSllvZE0wV1VNdk44eUJBQ0JTUyt5SmdseU9hSlpReXBCbUZCZHVXVnZTQnQwaFEzMGQwVwp6WU1XSFpHU0xIeUF2SGhlUm0zQStWdTRKUmJhOXBvSkpMcnlTdkh2NC9GbDNTeUVhUitrVDEzK3JoQ1J5V3YxCkdDOCtoZGZEbU91ZG5icG9KaGVIL0kya2o3aGZHWDY2SWlYbE9lcmNhdkJtaThwNkE1amhoaVppSUozWGQyZ0gKcEJBWFlCN3ZNRUh5cEFGbFBMc3Z6T3NjSzNwWGkyUU80SHlxVFliRWJFalZkS1p2UGZ6WDFIUTZLNzZHU2hWSQpuY1NBTnZiYXJEWGxpWWVFWUFTOWtBUUZJSFRnK1kvWDJDN3owSUlYZUZNTnBZVjZ4bUliM0JhZHdZa3k1R3NXCjY2MldKSHU4U3FjblpmaHJtQ1B2TzE2NmpOaVBPVnV1K0VvRnVEbVprZ01Cb0NGZXlUMTBQdWJxTjBpODZhWGkKd3VBUzdadHJqRkI1bjg1aHBKRExrUFBpbHdqMEV0cmdQSU81Q1FlSStIZCt3UDFTcy9ERWZzd3VJQXdiUUhFVApGeXFLbzRJTmxqQ0NEWkl3REFZRFZSMFRBUUgvQkFJd0FEQWZCZ05WSFNNRUdEQVdnQlNXbzFXaTRKeHpLRVdiCks4N1lYNEE4T0ZvY3RqQWRCZ05WSFNVRUZqQVVCZ2dyQmdFRkJRY0RBZ1lJS3dZQkJRVUhBd1F3SFFZRFZSME8KQkJZRUZDK2g3ZU9CWnNUdGlDZDF1NzNVeitWQmhWWnBNQTRHQTFVZER3RUIvd1FFQXdJRjREQVVCZ05WSFVrRQpEVEFMQmdsZ2hrZ0JaUU1FQXhJd2dnejdCZ05WSFVvRWdnenlBNElNN2dCZHpUUjZZQzNkYWdFZzNXSFV1UVBOClFFV3NPeTJkZ1F1ZFNHNEtpMjduT0NkOERKNWRRTUsxMzJvNUdCNWVUS2s4c1V6eVFVLzZoR3F4V25qZVhyd0gKblRRNXdoSDJLVGhWMy95WEJScGVNRXBUcnNKQ2ZZYllWTENqTGo1ZDE0MThLMk0rNGxiUCtTL1lORXFSaThNRApTWDRlbDUzNVkyQTluWFZuaDlFY2NsNThhVzRIcm9naHpmbTRweWhrWlpkWnVrMHI2VXNaR2pQV3lONkQxVHpUCmpZNG5Zcm1TandTallJbGFBcUU0bnBGK1ZvS3V2c0M2RWlDQ3VVUDhQdnJCTzFNcUtHcndheGd1SFpXM1BTcHYKVm83WmhPMUhvZjl5QkIrSEpBQitXUkE0Q0c5UUo3c2VBZ1RsNlplMndLSXYwaUdNRlNLelV2d3pQRHZpTHdvTwpDUUd4Wnd4dmRtY1BBenRPU2R2ak5VR2hOQU04YWFhSktyZnVzbi9lazF5dWVFcGJQa2YrZUdtZnU2OWdITTJYCnVvRG5leVB2MTJzSVJmSGFJOWQzYjlGbXVYUC9QWWNNSGs2YlhHT1gzN0l2eU5mckR4U3pqU21tdnE0TWpFa0oKeEZRcDRFelIyMWxWY3NUM3hhR2MvTkJzZUZXMjMzMnFPTjlPbCtaM3ZBNVdkbklwUlNrUnV4MEd5NXRTOGNyUgoya3dudUFkMm13c3RTNkZiaFNuNlB0WmZ4d1VDUmVza21iMkdEV3dGOVc0WDU3aXhNNXhmaFo0NGZYZy9tNkg0CndOQ3FzQVkvdzdZVC8rTkZ0elhDYkV5L2VJTEh1bWJmQ3RwcE5EaHEwSE41LzlEc0wzY2lOS0ZzOGV5OUJmcmgKSzdGRi81cDUrc1g5QkJaM3Bwb2JZdGw3MjY3aDYvdjRnN1NYMXgzSUpTRnRZczdZVXZMTnpNcjN5azFBSzF0MwprVVZnR3dJdHliSGMwWVlZTEdkK0hFMzNYKzhyb0NrYld0Q1dGK0Nsek5HbytZSzZZaFhGZjJLUzAvUXpVSlJWCmFJeUM4NzR5akxyamxQZ3JFbnBDNmdlR1VFNWNPRGRvNVhsTGUyb2M4VWY3QW16bkJzTzNBK1VrTFVkQUIvbWkKYmhWV1g1YVNqTVVaU25ITDA1d2xicXVDNnRtc2JZQXphM3ZJNzIwaFJqYTlvcGRiTWo2WXQ3Rm51MVpDMStWUgpiZUk4NU1KVUhqRDFWcjJjVUhiMzBGT2hjZGxhYmdVVzg1U1FuOEhWQUhRcU9oNG10WUpMbTdFdjNBeE4zK0dmCmVmMlFBUkZ0NVRadFM0dHU1dEViY0xvRXF6Mk1rL2Rsekp2ZUFzZ3dGdjBzZTNocy9mYUJ1ekwyUlI0WW1GRWUKd3o3ek85UVY1dDUzekNlWC9EbGRSZ3p0QnZOdnltRWsrUnhySmI3UHJHSFhtNWh1a3d3c0gyTHl5THVTKzJDOApsdFByKzFSREk4UlQ1WW5qS2EzWHAvUWxsbmkrNW9hL2FjR2J2K0l6SlZtVmcxb3dHR2o0ZDh3MmRpNk9oU0dFCjJZTFZES09rV0xVeWRZNUNkdnYrNUN4a21CKzhCdzhremdJbmtEUm1oYWg2QmhjMGtoWGlhM0Fxb1A5ZkdxeHIKMjlJMlJrQ25pS2tlSkJIYTlkM2hkdEtKQWE0NXlyd3JtYko2ZmhFV0pFMk9tUkhKRitINllINit6QmlsUTlZeQoxL3ZYVEMvdGxmU3NMbkRhN3VWLzNpK3hhV1V0S1RXRWlHWWp2TGE2RkR6aGZuSlJvZTZ3Vmg4OUdVMGZmS3pyCncySFZzM3owSjNhcER2bFNkQkpkbjNRWjBHQVpoVGIyWDBpZmI4TEFSVmlBY3BJL0ZlcEhFOXRXVkZPNDlXV3cKamdXelAxL3BUbkNvQmNGV215Z1YvZjlBeTFWMFdpVk9rdzBocUJ3WnJQNy9WMDNocjh3OXh0bk9Fbkc1Z1IybAo1eDh0dkRsNUZDQ2dUcjkrTGlPUU1RUmUxZ3J2NjF6YWZ1N1NZdlBpclJMUEdQVWF5UWx6NmdFOTcxdkJ4NVp5CitDRlg1NmVzWDkrODBYcG1BamRLeHNsWU5rcVhUbzE2V3Y5b1RPQk1nVmQ3R2hqbUhuY2JKOHhVZERCS2dVY1EKMWF4TWtqUythT0NzOEMveEZmSzY2YkE4eHlFS2owcmh3TU4xWjd3RTM2eGRzTUVaVTF4L3VsVjVsMUp1NDl5ZQpFU3VNb0U3eXFnczd3eU52cWdFVytvZmpHbjNURnNJbTZnOE85UE9nMnlUWExxZEM2UW9aTVlQN3JmaC8wWFRYCnREZjByV2V6QmtBMjFtM0pJSUVVSEl2SVEvcmRiOGpoMTQwSFkvLzhWRUNUZDlhOW9wN1NlMVM2aTErb0NFa3AKL3VoWDl2dkdVOWlScWFTdHpJUEdiMHZMWUwrbnNSU1l0Z3U0SEZ2SEpRQ1MwdENWSktHY0JRUDVmZWV0enBSNAptOWVCQ3pXSVZzbXFFQ3ZOQmxkcTJaMU1QR3MzSkkxMHAyTmM0Qk1VZ2xDOHZSUkNKK1VTb2RRcG5wTHB3VlJsClZ4VjlmenBINlBQQ0RGbFlLSVRTcDAvTDhva1kvVmk0c280TkFpa2FLN0dQeng5Z0R2OFc3NDVNNXhkRXBIaHYKR3JEVFdjOWgvdGYwcTFPeWxGemgwNyt2WVh0WjhIdjVwdjZHWndHVE1mQ1ZpbXpCblBkeEphbjFWSzU4cUltdwo3dGZQVG5sb1pVaHE2bjhXNDZ0R2J6NWJiSURNYWppR1RBNHBlenRET096VDBnRTVDRktHS2dIUGV5V0gxcEZHCkRJelVabGVjTmhSMHJRV3JDbGRrZS8xWlV4cU1wZ2xqa0RvWDJ5ZDMzOXUrd0phOTdRa0tsbFlFdHdxdXpkY2UKdHBzbURNOHZlazJwRDc0MkxlcmdtVlk3TUo2THU4Y0dHdmFOWlFuYkhWUjRwRk90Y2tDb2NtRzRITGl3QTN6OAp2OWpML0VYRFBWVmZFY0ViNHptaUFkQWtJNG1qekVHcEhkSXVya2lmd00zTnM4VFByYU9SaUJCZXlReENkSVBwCm5oVTcvaC81VXJzWS83NkhYckNFVlo4Zm9ncjMxelpHbTBQT1VKbFJ5bWI0QXV1eXlZWktDbE5EbTZwM1ZtU3gKUFpadUEzbTZlTWt5a09GSnp3WFVBOUFqa2YyZGdlQW9sRC81aTVrMytKZUFEVytDM0NPanpadFRFSUJId2JBUQpqeEdJR25FeHdoUVZtOXlob0Q0ZTY4dmYwYlV6aXpTQ1ZoV2pIZDhvaG9yeWhCdjUvb3FvYzFnVU5xYXlwZlVUCmhaZGFrZXQwb3JpblYzM2EwbVZ2dzhZR2xXWUViMjFiT1lJK01UQzRqR0RxL1F1UVJIQ09jbWRIUE1adTQyU3oKUktYMmVlZHVtUjNJOUhhTHVybFBXQTVEWEV0aHFONUF6ZHJBTklTS3h3MC9FdWc1YnZSa2d5UTQ4N1JpTHR2NApUNzJva2cySnQ3QmJYbXpEU1BUamxnWHY1ZGdIaTlnNjdzL2lJRzdaaUUzYVM5RkJGUUM1d2VabFBYWEp4Y1BYCmE2eE5aV0J3Vy9DZE9yZGdSOXozMlIxZFY3UGxCUElSdm5wOFgzdkZqUVN2amE0emRWTmdoN2pBbFAvd1VqNFQKams4akVWSjFWUW51TWxydlJhTU9tRklDRFQ2aE9xbElpNFdRRk1lRFNNTTB2dEV6RlVrc0o4ejBkWENWbzFhegpldWZsMGE4Q1FVTHN1akFQUXQrZEpNNjJKVkNndnY5ektjU05RSWxML2kxQ2xZN2o3SkQyeWgreTBQUjVQdjZYCnZUa0dGWHBEa3BZV2djSkMzc1lPUENGOE03bmJOWkNRNXdGbk9nbCs3SU9aNkZNMFlZd2E0eTZ5bW8yM0xQN08KWEJDcU92cWk0KzdlQzlSd3oyMnR2WjAyZy90NEdSTHdhVGtXR3RHemJmM0ZOMVJIREZKblIwV2NySzFhdlRKUwpuS1NkWHNJUWwwVFdCSXNNUUNZK0h3ZDd2Y2ZORVZJZXdyQk9zbm0xQ0cwRjhia3BWVjR0SlRxS002M09IQy9OCjlvSUhFZVRhbUMwMlNhWHlsTC9hb2JxZjVJYVQxRmlXb3R4UXAzOFdPV3hlQk8zZkI4WDhIcDlLc0QyZ21NOGIKUHI1RjMxRktJd3VtVTFPMzhndHR3RUtDeDg3VXdoZFUwSk43aExybVNuaWZyYnRGWkE3K05BVjM5YUlPcUtEaQprMjR3NCtCWS9FZmtnS1JTVjVvVXk4RG9veE9sNFhkUUZlVnBWRWNudnpSN2MxUlQrWjc0QTd5Y3dHNkxmZUhRCldLU05mZWZ6cDg4NFUvbXVFYkkxak55U2pUbEs3NDdtL294aWxsTUpTOStTZ0JKb2FiVGt3Sk45VWdmRmZ6dEsKakI4WDQ1NUlxL09ZYW5mSHF1MzBVNjU3UFR4cWs2VFdwd3FUTlRzOUlLVG1TMWpuanJ0ZllpUEw0U2FuTmlGaApYZG8rNnM5dkNZcXhQWXlJWWpnQ0E0cE54UGVSQkJESlJJWnBXN1ovNERJd1c3ZGdLSk5DenBaRmdWYjZ3WkRGCmNpTXlnSHBlUklzUWF3NStBOGN4cHlmZHpBSTBYSlp2SkNIZTdDK3Y5ekNkalA1K3J4Vk1raTNqWlB3RG16NkcKM1pkaHVQZHY2NGJsQUpKWXZTWDIrL2tsQzZ0Szg1OGFNR3p3TW1LeG80OHhmVlNmV3JOSGtzMi9Xa0FOSEpMUgpBcTlKMTFOeERpMU9McS9raS8yTm9ucWNXZ1J2cU9BcXlHTzFvV2xuS3hDMk5HU0dhRlluRlAvOGFCMHA3dGN0CkFVU3VONkhka1FCbS9mVCtuQVVPdWNRN01scVlSZzg4RUpraWoxdE9nNTNGdzBUTDdDanlHcmduUmNvb1dVSHUKZWdkNFZqQ1g5SW5VSnFvMDE5Wi92N2pjaXNKbkx6TVNUdnV2WkMyRlNhUGU1Q3FsY3dYOGZVcmN0YnV3MW00RgpkMWZPc1A4SXFmcFkyVU1zMDU2RUlCME9IbmVlSGlFZTFoV0FjOW5tRUozZ2NrREhJcVNzS2c5MEM1SVVEdGZrCnVONCtxSWJKclFUY282M3JkYWRxaktDTzk4OG9ucnlaZUM2NVRmSU1Bb1lrbThXSk1hMmtqK0dOV1Rnb1J4eTcKVVg1UzNzREw4dlQyM21tUHdqd0s0eWpBTUl3Z05PVmNuQ1lmUjNVdXY4a0Irc0ZnVmtSRHR1T1BLNlh2a1U0eAo5dUtYN1RXbVUwUnRRSnVVTUdnZ3BmUHBVSmxaWllISTdmWXI5YldtdkhEdkpkRHRJUHNtbmRDRE9lMjlwRnhQCit5T1ZNcFBLZHZueTVrd1BvYjh3UnNTcDlnS0JhLzFBQ2o5RVdZcjNGb3p6VHpaNjd3cStMa2twNlo0bWFaZDMKYjM3SnlDSjR0Mm9INGdVeGhCSTkzSW0wZUx0UGFhbVE4MnRtYk1MZXRweHNDclA5N1h6SkgyTUU4cDlxVXpCMgpSaHU5ejR2eU9aK21xMDNmVy9oajg2ajBBYm0wb3N4YXFEWTRMOFg3cjZBang2dExwSXBUeWVzZm0raUk1R1R6Cm5MQUFMSWFTWTRCTUZhUlNadHZOYmgwaUVkZmpXbjBCOVNoOHh1VzJwU3dnWGIzWE9MK1FhK2tCa0E4bE5VWkUKZUtKQjFnUUZ6dTR4Q3lDUi9SRTBGSmExeE9UMUZSb2JXbDFqYm0rUjE5N3ZBQUVPSENsWG5jUVdJREZCMFBzSwpFSUcxMkFBZVYzKzR5OWJtQUFBQUFBQUFBQUFBQUFBRkVSa2ZKQ3d3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCCkFEZjdzM09kTzZqdHBSZmltd2NHdzMxQk5MS1V1L2o4UUExMERhVXl5S0Z1U09rUU5Ocm5jSU9lUFYwNEdScXcKcWtqT1dtVjFSSjBMUGY4RUtDZ0dMYTJmWHo1VVVGcHhiRXY4RE1sN25YT3lIQmhUdVQrcEoyazhQaXhsUG5aSApSZEZDVDhkTVBWSWkxZzRmQW93cU1QQzZ4TVZ4cmZZWXVVU2xWOVRNc09ndnhBU09oWld6TThVZWpuWEp0Skh1CjVsMFB4ZjJKakV2YjhwVjRBMU9NL0JQeWJpN1NQVjRVK1NPZlZSajVYNDdLQXQvbmRYbDRxZmJFa1FwSTcvZUMKdStBckcwcGJzZDQ0UXRERXhidi9VaCtBUVE1K0NCa2hjUXBqcS9zcFcrZE5qZUdlSDdpbldTc25jYkpDemR4dwpGMHlEalFBWTRUWStNbDdCR0c1Rk9MTT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=";
        String issuerCertString = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSVlEVENDRnZXZ0F3SUJBZ0lVSWhGc3h0YjVESHFOZzNMNkpKZHlVV0lKTGdJd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0lERWVNQndHQTFVRUF3d1ZTSGxpY21sa1pVTmxjblJwWm1sallYUmxJRU5CTUI0WERUSTFNRFV4TmpFdwpNRFEwTkZvWERUTTFNRFV4TkRFd01EUTBNMW93SURFZU1Cd0dBMVVFQXd3VlNIbGljbWxrWlVObGNuUnBabWxqCllYUmxJRU5CTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEwWENhakNkWDZ6SUsKL3lHY0IxYkVhb2RBZjFPWVZmSFFVVy9iUlpGdy9VeTFjdUhicFlZTnFXNEcvU1QvUlJJdERVajkyUFM0YjBPSApaSFRqR0FCWGExL1oyaFpOSVpFcE5MMzFkNDNLKzJMemJNLzhCZkdQT1RFbmMzTWdoWnFtVnlqUWdKV2FFV3FMClVOMjZIRzFsL0QzN0R1MElFRm9nV1lsaVBrWU5HcTVOcU9Hd2trWGVUTkZiK3JPay9SUDJDS2NYclZOV2Vpcm4KV2lXMXZ2WEJlZ2pqK2pFRmZNUHJtN2Y3RXB2ZU5jNm1FVUZlNkxkcHRXaUFNVklxdlo2MUNSZWhEZ0lMWHRnWApQNEZpOFErMlR5djNzd1lMenRCcm1EMENJbE9lbFluUkhVVkMxakVTL05pSVRLR1N6c3lZZmhvbmk2TlJIbnlKCjdOeUsxRWFyQXdJREFRQUJvNElWUFRDQ0ZUa3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWZCZ05WSFNNRUdEQVcKZ0JTV28xV2k0Snh6S0VXYks4N1lYNEE4T0ZvY3RqQWRCZ05WSFE0RUZnUVVscU5Wb3VDY2N5aEZteXZPMkYrQQpQRGhhSExZd0RnWURWUjBQQVFIL0JBUURBZ0dHTUlJSHZ3WURWUjFJQklJSHRqQ0NCN0l3Q3dZSllJWklBV1VECkJBTVNBNElIb1FBc2ZNUExWTTFHRnB1ZElma2hPdnRseloxdUxrZ1JUSGJLd1dYU2dMKzFVOTM4bnI1MlVVNWMKaG1qK1RKMGZrdEZFZzJPbndMeDJ2ekY2ZnRQT0c3alYva21ydDJlTVhwS1FMa01PL2ZrbW5xQ1dxTkVpYU9YZwovY3pPNXlUNkRIWlg5RVNpZlJZTGdacXdUY0M0SVd5WC8zWWlseUlwUW03T2hTd2hONlU0aHJBR1hxb0VVTWN3CjlZL0lNdWRTK0lNcFo3T29YdjA1aWloTUdDZ0c4QWEzYWtIcnRUQ3BXVU1MUzM4TFZJenU1UVhOd0Rmdjg2bW8KMnBjRjltQzdTSnNTRE9Ja1VYTjlIbDc2amkrQUduU3BTa3BLSlB2aGllSUJ2czMwbERBd3BmMXlXd3MrUWZrcApCOFVEN2MzRjZDcXNvRTFPbjA3MUpkb1A3Q2tBWlpmUEVKZ1ZMVjNHRStod1lnMHFESVM4enRtNGVxTzc3RnUwCjdOeWJQOFJPWDIrQVpQNWJhSklydTdYR0oxTVJrWG9jOVJIWmxPdWNjdW9aWXFrU0VLM3JtNk1JcGdYbSt3M3YKanJ1c1hybnZWSnZTdGNZRTErNlcrNWt1VzBCMnVBTXJabkZ5cWtJUkRQMU5kaktPWStvZG4wQlA3R2hkRkxOOAowRndvditkV0t2QTRRUmhjbWdUUEIvUW9tNnZlVzdNcHdJZ25OWlZxVHovakRKRmluSnlOSU92bFZaWUtEQ0dDCjlOWmZocWNrUkhlTFN5ZnUxc3E5aXMyWmRSbTc2eEZmcFJnU2hHdmFHcGVYMzcvc09MbzdzeU1OdHAyMERiQUcKdk85LzhYRnRwc25TL0doVC9UOVBsb0FEOXZoK2FxSjBJdkltVTZGOXY1a0VhcnY4em5MeENLOUliMm95SGpNSQpRYzhPWGVVaWt3WEpLejZZTklXMUdFOFJwUFhRNUF2NlJDWUxabnpLNlpPZlBjZXZKdFZhZ3lSNmZpMUVWT010Ckp4RHpaMHVXVjJRZG9kUDdUZ3Z2OVdIYlBER1Q1eHFsTkZHWFA0QmFwNDl3OXpQLy9LZit4VG1ZRmJyUWVCaUUKTjcxMkd0MUE4OWFkM0FYTUhFSmNhaDBtWmI4ZFlTZHJKNUhLVDFQMDhKL2Ryd3FuREd6V2tOQlQxei8yK2NybAozb3Q1WGRjSWRoa2dsUzZJbzRROHZqckRkU24yY1M0VExRWjFmYzZQc2t0YlJLVU1PMG1QWXJxVzhUajFSREVSCmFSY1lEcFZxTDg1V0s3RzdJZUJ1Rll4REtRSktJOUM3VTFES3A1TmJrN2s1WTdLMENPeDB2YUlFOUN5OW5RWFoKdVBZQjZYM3BZUzlzdml1VmtSdGNvc0pheHdGM0E3d3owZTI1T2tyTmVocW5ad0FDTnZRZEd4aGxUYS8xdDFxQQpkK2ZXOGtMaEtSQnNpVW9aREpSdDB2N3ZPRk84aFlUT2VqU2lZWU1jNnNYcUhpdjVOUThQZldMOFhCcW5JNXh2CkhacCtvT2dEU2hIRlFvWi9kM3ZKOUlZN3MwaEtENTBjOWorZ0F6VWY2cFFyaGlqbkRITVNSaGtWRzB4cHNEbGcKUFg3Nm8vK0NOMnZtUFRFbHdwTFV5UmFtVHd0bDU0eW1YcVlsTXU1dDU3T2wyeUZVZzNXcE1XMmNSM2dvU0hFegpSTDRvZzFhY2U5NzBUdnprZHZ3ajJCRGhVL0tZaU0rMnNrT1pHaENvM29mSk9kNlRtVjJXbnJNMXpaaWhOVi9CClY3QlQ2Tm83emdIZVkxQnFabG1WNWw4NEowRk9PR0ZKY3RjMlVBK3YrNkxsakJDMjI2WVVKblg4ck1vb3UxbkIKSWxBQzcySG84R2JhSzNGUUNWMHVGanZjQ0Q1UDNqRkNxTThxMTFXWUdOWTNwR0gwZzhVQlNaamhoM1VHZWxtMQpFUEU3TlNPTmdSMGhnRGZPT25jUzBkVUdyQkZTWGJqcndlNGFreHoxRzAvb1ZBeXVnUnNESm1la3RtNkREUEpPCnltQUpyd2NNdzl0QWF5OXgrdDBXY05ZWVVuZGFNbkVkQjl1RGN1S0dyZk9vRVJDeDFDdm92Y1l1bit1OVpxaXAKYk9YUUZlaEIvSjJOajA1MVRVaktwZ1ZsR2k5MHhDSjNEY0JsNTZiNWh0THk5dUFKVnVoL2tFSzZWOGRvbm5BeAorK2NGYlYyL0M4MUwxcDFVQUc1UUJKeGJEOUdndjBrSVRIWFRLRVFQMEVjSmNEVzhhbXprMnc0RGZTZCtyY0gvCkVLaXpqN0R2WmVvRENiSEVaa2NGQk16ZVV2cG9oMXZLN1paMFVBZjgxVGRHMS91ejBHMGk1c1c5ZjRSRDU3SjcKRzd0RDZXMnZEQ2Nic1lmZ1pEOFZoOFhJMXFhRzZOSVdDVHhsMHZPWmdzUDY1b3B6WUZhNWx1MXNvZFBXVHBYcApKcy9EWkRJbG1QUHlqNUdjREZNRWZ0KzZ6LzRUSzBnQzhyZ3RZbzF4OVErU0ZvN1l1eGwxcUNlS2Q0RWd5UnlmCndnOERxZDhGWStlWDM1QmtLbEZURGdHOWVuZFJqd0t6SjFjMlUvZHMzS1Z1TDRLNHBtbTR4ajUyaUhEcGZhZzYKaWZUeFNTaW9ycFVyZEdVNGhjTFpTMVJNT1pab3NXYnVuSGo1NzdpNTViYzV2d0piMDRyMWh1eWtBZmpsVTg0Mwo1cTFaQzA4K0tBaGdnZkVyOFM4UmxBWXhHQWpXWm14TEFnSGhxazB5OFdNQlpXak9nd3BsVmIydkJFUFR5QmluClRrM202c1R4bGZaQm54U0xTWTFYcnJsZE9Hak9sRnFnNnQ4ZmFxWmFtWGRsUFcwZFpIL2tsRlB1VjRnUWE2UTMKN3hHWTJ3M3JSL3ZPS1psd05yU1FWMmZtMnVsSERHcnpQemo5TXQxSWRrZUZ3NXJCRFBuZndwZjhzYmd5b2tnSQpOdkRaVzdpM0ovTllpNVZqWit4RERMeVVtZ3UxcEVoUklMTEZnVGlIbkhzZEJTNkdhVEhLRlR6WkM5QnE1aFlHCjhCUlVuajYyTW9NQmV4ZEV6bWJKWlpPMUs3cUlwS1NORVhxZm44QlJBZmJXMDl2OGRHK3M2YlRoWHY2WVYrY04KZ0VQQ0hmWEdDNEdpSmlQakxBRjE1M3VhYlZrZEJmKzVLZG93R0RqRlJMRVFlSlRnZW5FOFVwLzI1NXdkK0xrVwo1VG9NMDY3eXFybXAxTlFMMkt0dFNUOFZNRHBlNUUyTEZ0Mi9JTEUyNmVKQ1NPNUFuZm8yY05BU3BDY1puZGllCmFJSXl6ZUVhUmpsNHRvV1doeVBGeUxYMTdkZk84cnZiUzFWQk5SZHI5azlnNXAvZ2h4RUw5TWlYKytkZlArc1MKTHAwbDBQQ2ZSSSs5Qm1CVEFVbUU1U1BHYXlpUGRTeU5oTUo1dzRid3h5a2NXRCt3S08zK1JEQVVCZ05WSFVrRQpEVEFMQmdsZ2hrZ0JaUU1FQXhJd2dnejdCZ05WSFVvRWdnenlBNElNN2dCMHBkVVlseDdXQUJETGgyQWlEZGRFCjdGTU94cDZoVkxDNk9BTUxvREpaQTl1SjJaa3ZjbVppejV3b2RpaXRnRmJsKzUyUmZHd2JWUm9FeU9QOU5iRUEKQ08xRTRiVlZJYjBiSjc2dm9hMEVvVjNjTVFZcWpmNks5bkhBTTExZ3VNOVpRS2JucEJDckIxbEVaaWlTa3lrRQpYQkZaZDArQUVCb0N3Qno3TlY2akpVTDJvcmJrV3F6WWRHQlg5MnpDS2dCWnZVbms1NnBFMWhBU1lhZXYvenNXCnBTNHdLQi81U3c4S2lGaGhjemlBWHU4MmEvM0xnZDNiNXd3dGRnUjJtb2FERU1VUmpqU2Y5b1JLdER4ZUZKcDYKS2VnaURydzdmTTZrMEdtZExyemdlUzdRdUNkdXlIODFQNWY4MXpRM0cvakJDeXE0d1QzRjNESXl4ajVPTDFxbgozaytPY3Z1VWxwNk5oZzZIV0pOY3VCNW1mM2JEcFFVYlRmR0kxeHJhTVVIRGRqVHRmYVFvbktBeWRMN1pVK3NXCktGc043U0tZS0dBNEVnVFU3SGs5WkhzTTFoTzRlVVRQUG1EYVhkekVORkhqWlpkeCtJK2gzODVHVWplN3VPUjAKckw4VjJWeE9aMnd6b2U2ZXZQRWtsUTcreUE0bWNXRmtXcExMU0ZIejRxSnljUUxkcTNDUFUrMUNxbjUyRFNiawpVTFNjcFBNd1VaNFkvUGhtelFUZ2JwMWNPVHp0RzV5STVTNVNGbDMrc1FLZDBCaE1Eb0QyelVSWWpVT0plR3BDCmRaanROQloreDZYSG1mYWdydjVLSThTY2lyZ3VOb1ZZYTIxbnN1d3YvdUI5VStXMkJQeEIvbGQvYlhXS3EraXkKZ25VL1B6cjlPbERvQjhZNkMvckFyVUJmdTVlS285b1pKZm1iSFRDOW50dFgyZWFRVWhHVU9WT253cXJnVXVKbgowMGNnWGZ5b3U4TENKaHRzcEdVRW5tQUlQVTlscEdLSElRVzRJWVc2eTNmVUtkWk5OUVZRVitsV1NBejNOM2pMCkdLczVCVVEreVQybzdrQmhLZ2l2UVczaEdqY1RIZzlsVUdUQXlXMkpIbnQxY0VZamlLbjVJK0MvN3pRRkkwaFoKMGdaKytBb2xXK2J6SVdGQU9kcnVraForME1qNXdsMnVnTUVIZ3BKcTk2eFA4dnc5Vkt2b3JPMDNqbnZiV3BQZwpwV3phMmFMSndWOUlhYjErYzdGbU05SjZOclBzMzQyaVVLVXhlL3pMcWMrcjY4UVRHKzd6Z3F2U1dib0swOERBCk5sZU1vMUl5NGZTWTB1Rmk3NEVlbVhxZHZhcmhuQ1BZRmJpRk1kcHFPOTFUMkJobEd0cG1PTDdiVHQ0NXJubUkKbU9sbytGbmlWY1NHZHdWMlY3bVdVN2dPTS94VmR1enZsZVc1VjQrbko5UXhUQmNWQXROMXhLdXVINWRNL0IyTQpVRUlmd2E4NG9JWFJYS2pFTkU4aWExWGJPOU1tQXZoSDlNN2lWMm9SdVF1ckM3N0xhb3RLNWtQTXhnZUM1dkdhCkdyTkRWeVRLaFN2TVdZMXRwLzdWZzM3OXZHbWJnOVNVUUFXK2Z0b05PSmNMQVg3bWg5TnpnZTBMQXpyeCsyNXgKaXBCT2dPUDd5NTBEekE3eEVjOFR4TENsYmhSMjZNY1BaVUpaZis3NlpSMlhQbU5CQVJYY3VwZmNLOUIvMENxQQp2OVVsdEZEV3lpazRmdnRNZXp6ZGtwQWhhK2QyUVVoRi9mVUs4WDFRRjFnbnliUDhEb3U5cmEwN0hLaU5BN2NGCkM1dlJrV0NNRVAxYW9FbFR4b1VPcm0zTmdqTjM4UmFFcHhiaHlCLzZMNlUrNDhMNlpRckN0c21MeTZublFVSVcKaWRTdEFRQXNuNTNqQU5oSll1TllHdndnbXdKbnBtRFFyVjhiUGNOcTBpZFFtQVdRMXVsU1RBVklFM2tuQnVzZQpZTXpOVFNtMG5QR2xrY2F5cDBJK1l3amZSR0dOQk9MMmE5cDFSeFdrc1l6Y2VpOGdjZFZXQkxKQVlHVFdCM2JVCkVLR3pBcjdRVGJxNy9YUFVJMUVBaUVaV2UzSFgzMFlBMWJrRUZKNDJGVnJNMHkvQmNZbi8rSzZRSmJaVFdZVWsKbHY3dTF0bDI2WnliRG5ibDdiZjlJbmVtUkZZQ1BBbTUwdDJiOEVpQVQwSCsvTkxmZXNDdmpBdEVRREhUL1pndgp6QUM2V3orZmE2WnIwOXFrMUtkSlVmNUpXa3hMKzdndERWd09DUVpmNjNjVnJjeG5NYVl1Q3o0d3ZzNGRsbk5JClhMZTgvODQyMHdsY3dtejdUVmdOblUrN2IxdGxnNHNTanlNMGhxelVNWldaZ29rZmwxUm1xQStVbFNDN1pDeXUKd0EwVVdNOFVHWlREdjNoK1ovY01VSklaVENuQ3dvekxTb3hLUmgrZ1dnWWZGcVBCTXMraDNoNDB2WEEreUhJegpMNlVyWTBqbnZhYU5lVjBmM0x3NWNJc2lWSzh2TmNIUTYwWkVBeTVCK0dZNTN0d2Iyb2tJMG0ycVAyOExUZEg2CjdRNlpLNlpSKzVQQ0d3THg3L2NYMXpEMUtxQnFrTGx0NitmVFZFa053OW9lcWZXQWZLVUdENVlHSXNnVUZXRXoKTmt3Y0R2YkUwS3lFY09vbjdPS3U1SXhkSm5YUmxyVmlraUFxN3Jac3pQN24ybGJLZmh4VEF5eVJYQXl4aG5zRgpUWE1QeFZzeWJsUjRQaFBXeDQwVHdYdlZ1VWxCa1dDV0cySVovTHdEbTQrQkRXMjdwTlB5eW12K1YzYmVsWEJ4CjFOVjhMQnY3Q0lzdmh1aFFOYWVpTm1mcWR0eGsxeWdKbEhON25XUCtiT3E5TUxSYW1mM3g3VFNmYzdBVWNkODUKNE9ORHpDeXVxTHF4bXpZaGd4TTF3dVh5V1RlUktQU3FwVFV6OWZ5ZUhZWlBLazRaQlBwL0ZJYUhkZGdSQUgrawpmem5lMGgzOXdVb2YxQyt3L3RVTGg1RFo1UlVyWkM1WloweS9sSXVVclZFeFdZWkx1M0RQQkV6TmhQR0huQU1jCnJZS1VTZ3BsU2J3TWJOMFU3M0hnQTNqNDc3RHJOWm5aNHpSRU96Qy8wT0NyTE5RTGpQdkVkRDFodUo5VURZV1YKWXNaSWt2c0l2MEtHUGZscDlKeSs5SUFhc2ZyODIvNUFUdEZmMHRGc1ROYWI3SU0xTmxZb1NRRCtvMEw5d0REUQpZcmo3cEFVZGRLVlgvOFFBSmQ2T1dTOEF2WmI3bkpGcVl5dUFnaEw1THExcGpoTkNqL244TVFSWjhDTDE3UlBOClQzOUp4NlZhN3VYSmRaN1hIYjBQTFBnQUxoeGZUOXZRY3VHTFMrcmJiblBWcGpxVGQ3ZERKZk1NVzgxUDJwaVYKcDRaRXAxMURER1dyM1licWRzU1c2UG5YU1I4ZDF0Nm5Qc2trdXlBZFFVN3J3RjhwRUxxalF6R2Rpb3E0aVJ0TgpsK2E4MmhuZVRWald1a3d3ZnZGa3FpWjRiaXRKdkNZMlFUN2pDZ0VlcUhCS2RFWi90OEYwc0NsRlVlSTdDbVRHCkFjcVVvMHdmTDViZ0lTbmhydjJZR1JrR3BWVGt6QUNBU2kzNHhkckVicDl6VW5RYWJRQXFLdXlTcGN4RzhhT0QKU2tZVHh2bHhZWldoWlJDRUFyNGxmd0U4cys5RC9NKzlBNGNCd29BTE5wM0g3Z1gzeDRKSmtEMTdZZVNQSkg0cAo4QTQrQzRIOXBwNy9qVFhpc3AwTGJtODgvSWl6Nk9BN1E2blBUSUdtTFk5WFQrcUlFRHJua1ZwWWV4ejNEZ0RoCis2eDYzelQzOGJZT0duSEpNa3gzY1lpTS9YQWRRaTZGR2VhK3R1MFZJVktoenplNVNUMDBZZStTOGFzbGt1UEUKakthZXN0Y0N2RjBvQWQrY01nRm1YZUl6TTRvK0pJL3lQTDdEM0RwcnUxUkVqK1BjK2NXQTEvQmFvQ2Q2cHFnaApQNWwzUFh2MjYyZXhvanZGa0pTRWQ4L3dEVnNLYmhGb1pYOENSZjJZTFVEUWc2bDZ5WnBiSFJ6ZGFObXl0ZmFSCjYwMCtuaXYyNDc3NWwwQ1ZoUmVIWlBBS2pFNlFQcTR4S3FTQm43SHNNNjdOUGRFMDhxSVNIbUdWOWNKNURiTEkKZHFoVjRMOEdrQXV3Ymo2U1hzaUFBeFh5cjloclA0eTFqbUtaQmVZRHBzenZoUUFqbWpnVUwrTC9tSXU3bS9ZVwpjUTQwYmN2TjFLb0pWMkhOQVR0NjluZ1FjYmIxZzBkanhpVVNNTHJOVUJXb1ljckgxMW5lQko4aFY3VHM4T3JhCk9MSUF5WnBYZ0lEUWEwdFNpSEtvK3FCaTVNZmUwcEQ2NVJuQWNPRFFrSHRXSHR3RUpaM3V2L2paUm5SV3lrVWcKOTBJYis3bUlSNkliajBPZHJZRXBjNmVIeXR4UVQ1MFM1VFZoSlNaVWwxQlRiU1IzTVlmRjdaSkN6T1hXWGxaVApOOEJBZk9EQzREdFk0NnFvTUFtYnNQTXljV0V6VUxVQ2thcGtoRGpKNDBUOXo4ZnQ4WDJLQXV6REkzek03cXVICkdNSWRud1JCdWRCRy9vUjZXVHlUcWVFZ1Nvb1hKa2ZiL1V6NHJnWlphYlhlbjNiMXpURWp5Y0t2dWNjR3FVbksKY1NhTnMvNkhMK3BjZXJ4cHh4em80QlIvWGpiSHFiNlU4bDgzaFljdWw4cFRCbFlyb2hwRjNncm9qb01pWW5DUAo0ZU15dGpnTXBFS0NtSWxrbis5ZjU1RVZpTUljMml5QzVCaFF2VGkxWW9SL3VFSlhncDFTV2NaeEU3eGJvYk0xCmVmU0FYSlk3aWhqK2cwaEdHWjdsVy9UMVlIdXJHZWZ0VWNORFNobjZ0Z2JVTzQreW1yc1JtdnpGUUtLYWZsd0YKcTRaVHQrWlJ4dFhSUG5YdzJkOGhib2ZYWFVBTDMvcWNPc0ZyWjRtT1BYZDlSdDV2RmVYNjRYMCsrb2hBR210dgo0bTB3QjhOL0tjclUrekszK1k5RW9yZHRlN0NrZTkzTG4xeXpZZTNLOU5leDZ2M1luVTdsbXNxMlg5cndWVGowCm5HK3dzREhWU1NFQmhBWmtVcDZzVnBUbGtsS0V6RVdwSVJTK0UrU2FsMkQzcUhzSEZyWkVMRmhnalBwWEUvdTgKQTM3a25OMURxYjRVNkoxeFA1cEx1dWlGbWdSRVNxN1JPYXE2cGFZYUwvNndCTnQ3UDNlcjRqaGJyOHdmclhZdwpmQjBqWTd2QkFhZTl1MnVFZVZsb2NUN3lkRjJmV0g2RzFsTlJaUGtUUTF1R0hERHFJeVFTNTBhdHJkb3JBb1hsCjdWL0Vna0Z1RCtvbTFHVjVkNDZqVEVRc3dxaGpJSWNYUDl6SmdQV1NOK2t0RnI4d2VLSXBMRUk3T1U5WXF4MXMKbU4xUDJhcHg1VmJxZFNyT1JUbTlFUGMzaEV2dEp2cFovVy9hT29sYVAyaUk0SlFkWFoyUklaYUtDU3prVzkrbgpOaDRraERoUXRDT1djcnZ6QWovQ0xzRDFDQk9GL1grYTZwMGNNek8yODJJY0duTDVMNXFzRnB6TkdxVnJ2Y3UrCmN2RE16cVV0ejliVUtkSzVuOWZwb3lsSFliWXNtL2ZnYUJOeFRLY3hwVUlNQzAvcHljYXhhdWg0ODAxZlRpZ20KMExLdlViSkUzSEp5MTZ3Rk40Zyt0bE4wZTRTRnFmNEhDeEVVUzRQRDQvb01WYVd6RHhOVWROYmhJVFpBUTRXTwpwNm5GSWorVG5xS2x3TWZPQUFBQUFBQUFBQUFBQUFBSEVCUWFJeXd3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCCkFCWEtTbWIxalB0bHpEVEg4dFRUemRxVHRIQVBHeTRieFdINEJ0UkNPNGVoOUhMTFNnQXFmZmU5RnpWZDl5aHMKdzhnc0dHQUxUTlh5WEswc3FuelgzN0ZhSzNTS2ZhZ0gxL1NyUFIxZGVzaEo0M3VZTjRRSEl4QXFQNGczNDFTRgo0bThsWGdXcTZ3S3dBbzMwK08vMnRxWHlGUWwrU3BVcExUbnNBZ3NIdVhma1dDdk93MUtiN0tOdjQwVXhRUVE0CmVsbVdyNHJrbHUxTGdZbWdsd1FxWXhoQ2dGdldLZkw2YWdkcHdZOG5OQUVNK1VsSmZpbmxQc0UzUzRtNUN2elMKNE01K1dIaGtHQkNuTGdocmRUa0Znc0lmdEVyK0ttUFdYdGVQRWhWLzBmcjNFYmJsT0FDc3B5VjM0NC9iSUE0UQpmaXhCRVhzN290WmRXZGtJVTAvRlo0cz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=";
        uploadCertificate(derBase64(issuerCertString));
        Certificate hybridCertificate = uploadCertificate(derBase64(certificateString));

        CertificateValidationCheckDto signatureCheck = certificateService
                .getCertificateValidationResult(hybridCertificate.getSecuredUuid())
                .getValidationChecks()
                .get(CertificateValidationCheck.SIGNATURE_VERIFICATION);

        Assertions.assertEquals(CertificateValidationStatus.VALID, signatureCheck.getStatus());
        Assertions
                .assertEquals("Signature verification successful. Alternative signature verification successful.",
                        signatureCheck.getMessage());
    }

    private static String derBase64(String base64Pem) throws CertificateException {
        X509Certificate certificate = CertificateUtil.parseUploadedCertificateContent(base64Pem);
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    @Test
    void testValidateDownloadsAndInsertsIssuerFromAia() throws Exception {
        // The CA is deliberately absent from the inventory so validate() must follow the AIA download path.
        KeyPair caKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        X509Certificate caCert = CertificateGeneratorHelper
                .generateCACertificateWithQcStatements(caKeyPair, "CN=AIA-Test-CA");

        KeyPair eeKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
        String caIssuersPath = "/aiaissuer.crt";
        X509Certificate eeCert = CertificateGeneratorHelper
                .generateEndEntityCertificateWithCaIssuers(caKeyPair, caCert, eeKeyPair, "CN=AIA-Test-EE",
                        LoopbackWireMock.url(mockServer) + caIssuersPath);

        // Serve the CA in DER format at the AIA URL.
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo(caIssuersPath))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/pkix-cert")
                                .withBody(caCert.getEncoded())));

        // Insert only the EE cert; CA is absent.
        Certificate eeEntity = certificateService
                .createCertificate(Base64.getEncoder().encodeToString(eeCert.getEncoded()), CertificateType.X509);

        String caFingerprint = CertificateUtil.getThumbprint(caCert);
        Assertions
                .assertTrue(certificateRepository.findByFingerprint(caFingerprint).isEmpty(),
                        "CA should not be in inventory before validate");

        certificateService.validate(eeEntity);
        // Reload to pick up the issuerCertificateUuid written by validate() on its own managed instance.
        eeEntity = certificateRepository.findByUuid(eeEntity.getUuid()).orElseThrow();

        // CA must have been downloaded and inserted via insertWithFingerprintConflictResolve.
        Optional<Certificate> insertedCa = certificateRepository.findByFingerprint(caFingerprint);
        Assertions
                .assertTrue(insertedCa.isPresent(), "CA certificate should have been downloaded from AIA and inserted");
        Assertions
                .assertNotNull(eeEntity.getIssuerCertificateUuid(), "EE issuer UUID should be set after AIA download");
        Assertions.assertEquals(insertedCa.get().getUuid(), eeEntity.getIssuerCertificateUuid());

        X509CertificateEntity ca = X509CertificateEntity.from(insertedCa.get());
        Assertions.assertTrue(ca.getQcCompliance(), "qcCompliance must be persisted");
        Assertions.assertFalse(ca.getQcSscd(), "qcSscd must be persisted as false");
        Assertions
                .assertEquals(List.of("ESIGN"), MetaDefinitions.deserializeArrayString(ca.getQcType()),
                        "qcType must be persisted");
        Assertions
                .assertEquals(List.of("CZ"), MetaDefinitions.deserializeArrayString(ca.getQcCcLegislation()),
                        "qcCcLegislation must be persisted");

        // Idempotency: a second validate must not re-download the CA (issuer is now in inventory).
        mockServer.resetRequests();
        certificateService.validate(eeEntity);
        mockServer.verify(0, WireMock.getRequestedFor(WireMock.urlPathEqualTo(caIssuersPath)));
    }

    // ── OcspAnswerTrust ───────────────────────────────────────────────────────

    @Nested
    class OcspAnswerTrust {

        private final OcspResponder ocspResponder = new OcspResponder();

        private WireMockServer ocspServer;

        private String ocspUrl;

        private CertificateGeneratorHelper.CertificateChainInfo chain;

        private Certificate endEntity;

        @BeforeEach
        void uploadChainCheckedByOcspResponder() throws Exception {
            ocspServer = LoopbackWireMock.start(ocspResponder);
            ocspServer
                    .stubFor(WireMock
                            .post(WireMock.urlPathEqualTo("/ocsp"))
                            .willReturn(aResponse()
                                    .withStatus(200)
                                    .withHeader("Content-Type", "application/ocsp-response")));
            ocspUrl = LoopbackWireMock.url(ocspServer) + "/ocsp";
            chain = CertificateGeneratorHelper
                    .generateCertificateWithIssuer(KeyAlgorithm.RSA, "CN=Ocsp-Trust-Ca", "CN=Ocsp-Trust-EndEntity",
                            ocspUrl);
            uploadCertificate(chain.getCaCertificateBase64Encoded());
            endEntity = uploadCertificate(chain.getEndEntityCertificateBase64Encoded());
        }

        @AfterEach
        void stopOcspResponder() {
            ocspServer.stop();
        }

        @Test
        void reportsValid_whenIssuerSignsGoodAnswer() throws Exception {
            // given
            ocspResponder.answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair()).build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.VALID);
        }

        @Test
        void reportsRevoked_whenIssuerSignsRevocation() throws Exception {
            // given
            var revocation = new RevokedStatus(new Date(), CRLReason.keyCompromise);
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withStatus(revocation)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.REVOKED);
        }

        @Test
        void reportsValid_whenAuthorizedResponderSignsAnswer() throws Exception {
            // given
            KeyPair responderKeyPair = freshRsaKeyPair();
            X509Certificate authorizedResponder = issueResponderCertificate(responderKeyPair,
                    KeyPurposeId.id_kp_OCSPSigning, calculateDate(24 * 30));
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, responderKeyPair)
                            .withSignerCertificate(authorizedResponder)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.VALID);
        }

        @Test
        void reportsValid_whenAuthorizedResponderUsesAnotherKeyAlgorithmThanIssuer() throws Exception {
            // given
            KeyPair ecResponderKeyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.ECDSA, null);
            X509Certificate authorizedResponder = issueResponderCertificate(ecResponderKeyPair,
                    KeyPurposeId.id_kp_OCSPSigning, calculateDate(24 * 30));
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, ecResponderKeyPair)
                            .withSignerCertificate(authorizedResponder)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.VALID);
        }

        @Test
        void reportsValid_whenAuthorizedResponderHasNoKeyUsage() throws Exception {
            // given
            KeyPair responderKeyPair = freshRsaKeyPair();
            KeyUsage noKeyUsage = null;
            X509Certificate responderWithoutKeyUsage = issueResponderCertificate(responderKeyPair, noKeyUsage,
                    KeyPurposeId.id_kp_OCSPSigning, calculateDate(24 * 30));
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, responderKeyPair)
                            .withSignerCertificate(responderWithoutKeyUsage)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.VALID);
        }

        @Test
        void reportsValid_whenAnswerExpiredWithinClockSkew() throws Exception {
            // given
            Date justPassedNextUpdate = Date.from(Instant.now().minus(Duration.ofMinutes(1)));
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withThisUpdate(calculateDate(-1))
                            .withNextUpdate(justPassedNextUpdate)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.VALID);
        }

        @Test
        void reportsValid_whenAnswerStartsWithinClockSkew() throws Exception {
            // given
            Date slightlyFutureThisUpdate = Date.from(Instant.now().plus(Duration.ofMinutes(1)));
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withThisUpdate(slightlyFutureThisUpdate)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.VALID);
        }

        @Test
        @ExtendWith(OutputCaptureExtension.class)
        void reportsFailed_whenAnswerIsSignedByUnrelatedKey(CapturedOutput output) throws Exception {
            // given
            KeyPair unrelatedKeyPair = freshRsaKeyPair();
            ocspResponder.answerWith(request -> anOcspResponse(request, unrelatedKeyPair).build());

            // when
            CertificateValidationCheckDto ocspCheck = checkOcsp();

            // then
            assertThat(ocspCheck.getStatus()).isEqualTo(CertificateValidationStatus.FAILED);
            assertThat(ocspCheck.getMessage())
                    .contains("signed by neither the issuer nor an OCSP responder the issuer authorized");
            assertThat(
                    output.getOut().lines().filter(line -> line.contains("Ignoring the OCSP response from " + ocspUrl)))
                    .isNotEmpty()
                    .allSatisfy(line -> assertThat(line).contains("WARN"));
        }

        @Test
        void reportsFailed_whenRevocationIsSignedByUnrelatedKey() throws Exception {
            // given
            KeyPair unrelatedKeyPair = freshRsaKeyPair();
            var revocation = new RevokedStatus(new Date(), CRLReason.keyCompromise);
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, unrelatedKeyPair).withStatus(revocation).build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenAuthorizedResponderCertificateDidNotSignTheAnswer() throws Exception {
            // given
            X509Certificate authorizedResponder = issueResponderCertificate(freshRsaKeyPair(),
                    KeyPurposeId.id_kp_OCSPSigning, calculateDate(24 * 30));
            KeyPair unrelatedKeyPair = freshRsaKeyPair();
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, unrelatedKeyPair)
                            .withSignerCertificate(authorizedResponder)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenResponderLacksOcspSigningUsage() throws Exception {
            // given
            KeyPair responderKeyPair = freshRsaKeyPair();
            X509Certificate clientAuthCertificate = issueResponderCertificate(responderKeyPair,
                    KeyPurposeId.id_kp_clientAuth, calculateDate(24 * 30));
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, responderKeyPair)
                            .withSignerCertificate(clientAuthCertificate)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenResponderIsIssuedByAnotherCaOfTheSameName() throws Exception {
            // given
            KeyPair otherCaKeyPair = freshRsaKeyPair();
            X509Certificate otherCaOfTheSameName = CertificateGeneratorHelper
                    .generateCACertificate(otherCaKeyPair,
                            chain.getCaCertificate().getSubjectX500Principal().getName());
            KeyPair responderKeyPair = freshRsaKeyPair();
            X509Certificate responderOfOtherCa = CertificateGeneratorHelper
                    .generateOcspResponderCertificate(otherCaKeyPair, otherCaOfTheSameName, responderKeyPair,
                            KeyPurposeId.id_kp_OCSPSigning, calculateDate(24 * 30));
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, responderKeyPair)
                            .withSignerCertificate(responderOfOtherCa)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenResponderIsIssuedByAnotherCaSharingTheIssuerKey() throws Exception {
            // given
            X509Certificate otherCaSharingTheKey = CertificateGeneratorHelper
                    .generateCACertificate(chain.getCaCertificateKeyPair(), "CN=Ocsp-Trust-Other-Ca");
            KeyPair responderKeyPair = freshRsaKeyPair();
            X509Certificate responderOfOtherCa = CertificateGeneratorHelper
                    .generateOcspResponderCertificate(chain.getCaCertificateKeyPair(), otherCaSharingTheKey,
                            responderKeyPair, KeyPurposeId.id_kp_OCSPSigning, calculateDate(24 * 30));
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, responderKeyPair)
                            .withSignerCertificate(responderOfOtherCa)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenResponderKeyUsageForbidsSigning() throws Exception {
            // given
            KeyPair responderKeyPair = freshRsaKeyPair();
            var keyEnciphermentOnly = new KeyUsage(KeyUsage.keyEncipherment);
            X509Certificate responderThatMayNotSign = issueResponderCertificate(responderKeyPair, keyEnciphermentOnly,
                    KeyPurposeId.id_kp_OCSPSigning, calculateDate(24 * 30));
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, responderKeyPair)
                            .withSignerCertificate(responderThatMayNotSign)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenResponderCertificateLacksOcspNoCheck() throws Exception {
            // given
            KeyPair responderKeyPair = freshRsaKeyPair();
            boolean noCheckExtension = false;
            X509Certificate responderNeedingRevocationCheck = CertificateGeneratorHelper
                    .generateOcspResponderCertificate(chain.getCaCertificateKeyPair(), chain.getCaCertificate(),
                            responderKeyPair, new KeyUsage(KeyUsage.digitalSignature), KeyPurposeId.id_kp_OCSPSigning,
                            noCheckExtension, calculateDate(24 * 30));
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, responderKeyPair)
                            .withSignerCertificate(responderNeedingRevocationCheck)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenResponderCertificateHasExpired() throws Exception {
            // given
            KeyPair responderKeyPair = freshRsaKeyPair();
            Date expiredAMinuteAgo = Date.from(Instant.now().minus(Duration.ofMinutes(1)));
            X509Certificate expiredResponder = issueResponderCertificate(responderKeyPair,
                    KeyPurposeId.id_kp_OCSPSigning, expiredAMinuteAgo);
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, responderKeyPair)
                            .withSignerCertificate(expiredResponder)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenAnswerIsForAnotherSerialNumber() throws Exception {
            // given
            BigInteger anotherSerialNumber = chain.getEndEntityCertificate().getSerialNumber().add(BigInteger.ONE);
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withSerialNumber(anotherSerialNumber)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenAnswerIsForAnotherIssuer() throws Exception {
            // given
            X509Certificate anotherIssuer = CertificateGeneratorHelper
                    .generateCACertificate(freshRsaKeyPair(), "CN=Another-Ca");
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withIssuer(anotherIssuer)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenAnswerIsForAnotherIssuerOfTheSameName() throws Exception {
            // given
            X509Certificate anotherIssuerOfTheSameName = CertificateGeneratorHelper
                    .generateCACertificate(freshRsaKeyPair(),
                            chain.getCaCertificate().getSubjectX500Principal().getName());
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withIssuer(anotherIssuerOfTheSameName)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenAnswerLabelsIssuerHashesWithAnotherAlgorithm() throws Exception {
            // given
            var unsupportedHashAlgorithm = new ASN1ObjectIdentifier("1.2.3.4.5");
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withHashAlgorithm(unsupportedHashAlgorithm)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenAnswerWithoutNextUpdateIsOld() throws Exception {
            // given
            Date thisUpdateAnHourAgo = calculateDate(-1);
            byte[] noNonce = null;
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withThisUpdate(thisUpdateAnHourAgo)
                            .withNonce(noNonce)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenAnswerIsStale() throws Exception {
            // given
            Date passedNextUpdate = calculateDate(-1);
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withThisUpdate(calculateDate(-2))
                            .withNextUpdate(passedNextUpdate)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenAnswerIsNotYetValid() throws Exception {
            // given
            Date futureThisUpdate = calculateDate(1);
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withThisUpdate(futureThisUpdate)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        @Test
        void reportsFailed_whenNonceDiffersFromRequest() throws Exception {
            // given
            byte[] nonceOfAnotherRequest = "another request".getBytes(StandardCharsets.US_ASCII);
            ocspResponder
                    .answerWith(request -> anOcspResponse(request, chain.getCaCertificateKeyPair())
                            .withNonce(nonceOfAnotherRequest)
                            .build());

            // when
            CertificateValidationStatus status = checkOcspStatus();

            // then
            assertThat(status).isEqualTo(CertificateValidationStatus.FAILED);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private CertificateValidationStatus checkOcspStatus() throws NotFoundException {
            return checkOcsp().getStatus();
        }

        private CertificateValidationCheckDto checkOcsp() throws NotFoundException {
            return certificateService
                    .getCertificateValidationResult(endEntity.getSecuredUuid())
                    .getValidationChecks()
                    .get(CertificateValidationCheck.OCSP_VERIFICATION);
        }

        private X509Certificate issueResponderCertificate(KeyPair responderKeyPair, KeyPurposeId purpose, Date notAfter)
                throws Exception {
            return issueResponderCertificate(responderKeyPair, new KeyUsage(KeyUsage.digitalSignature), purpose,
                    notAfter);
        }

        private X509Certificate issueResponderCertificate(KeyPair responderKeyPair, KeyUsage keyUsage,
                KeyPurposeId purpose, Date notAfter) throws Exception {
            return CertificateGeneratorHelper
                    .generateOcspResponderCertificate(chain.getCaCertificateKeyPair(), chain.getCaCertificate(),
                            responderKeyPair, keyUsage, purpose, true, notAfter);
        }

        /** Answers each OCSP request with what the test's answer function makes of it, as a real responder does. */
        private static final class OcspResponder implements ResponseDefinitionTransformerV2 {

            private final AtomicReference<Function<OCSPReq, OCSPResp>> answer = new AtomicReference<>();

            void answerWith(Function<OCSPReq, OCSPResp> ocspAnswer) {
                answer.set(ocspAnswer);
            }

            @Override
            public ResponseDefinition transform(ServeEvent serveEvent) {
                Function<OCSPReq, OCSPResp> ocspAnswer = answer.get();
                if (ocspAnswer == null) {
                    return serveEvent.getResponseDefinition();
                }
                try {
                    OCSPReq request = new OCSPReq(serveEvent.getRequest().getBody());
                    return ResponseDefinitionBuilder
                            .like(serveEvent.getResponseDefinition())
                            .withBody(ocspAnswer.apply(request).getEncoded())
                            .build();
                } catch (IOException e) {
                    throw new UncheckedIOException("The test OCSP responder could not answer the request", e);
                }
            }

            @Override
            public String getName() {
                return "ocsp-responder";
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static X509Certificate createSelfSignedCertificateWithCrl(String commonName, List<String> crlUrls,
            List<String> deltaCrlUrls, BigInteger serialNumber)
            throws CertIOException, NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        return createSelfSignedCertificateWithCrl(freshRsaKeyPair(), commonName, crlUrls, deltaCrlUrls, serialNumber);
    }

    private static X509Certificate createSelfSignedCertificateWithCrl(KeyPair pair, String commonName,
            List<String> crlUrls, List<String> deltaCrlUrls, BigInteger serialNumber)
            throws CertIOException, OperatorCreationException, CertificateException {
        DistributionPoint[] deltaCrlPoints = deltaCrlUrls == null ? null : createCrlDistributionPoints(deltaCrlUrls);
        return createSelfSignedCertificate(pair, commonName, crlUrls, deltaCrlPoints, serialNumber);
    }

    private static X509Certificate createSelfSignedCertificate(KeyPair pair, String commonName, List<String> crlUrls,
            DistributionPoint[] deltaCrlPoints, BigInteger serialNumber)
            throws CertIOException, OperatorCreationException, CertificateException {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());

        X500Name x500Name = new X500Name("CN=" + commonName);
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(x500Name, serialNumber, new Date(0),
                Date.from(Instant.parse("9999-12-31T23:59:59Z")), x500Name, subjectPublicKeyInfo);
        CRLDistPoint crlDistPoint = new CRLDistPoint(createCrlDistributionPoints(crlUrls));
        certificateBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);
        if (deltaCrlPoints != null) {
            certificateBuilder.addExtension(Extension.freshestCRL, false, new CRLDistPoint(deltaCrlPoints));
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(pair.getPrivate());
        X509CertificateHolder holder = certificateBuilder.build(signer);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        converter.setProvider(new BouncyCastleProvider());
        return converter.getCertificate(holder);
    }

    private static DistributionPoint[] createCrlDistributionPoints(List<String> urls) {
        List<DistributionPoint> list = new ArrayList<>();
        for (String url : urls) {
            DERIA5String deria5String = new DERIA5String(url);
            GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, deria5String);
            DistributionPointName distributionPointName = new DistributionPointName(new GeneralNames(generalName));
            list.add(new DistributionPoint(distributionPointName, null, null));
        }
        return list.toArray(new DistributionPoint[0]);
    }

    private static CertificateValidationStatus readCrlStatus(CertificateValidationResultDto result) {
        return result.getValidationChecks().get(CertificateValidationCheck.CRL_VERIFICATION).getStatus();
    }

    private static CertificateValidationCheckDto readCrlCheck(CertificateValidationResultDto result) {
        return result.getValidationChecks().get(CertificateValidationCheck.CRL_VERIFICATION);
    }

    private Optional<Crl> findStoredCrl(X509Certificate selfSignedIssuer) {
        String issuerDn = X500Name
                .getInstance(new PlatformX500NameStyle(true), selfSignedIssuer.getSubjectX500Principal().getEncoded())
                .toString();
        return crlRepository.findByIssuerDnAndSerialNumber(issuerDn, selfSignedIssuer.getSerialNumber().toString(16));
    }

    private Optional<CrlEntry> findStoredCrlEntry(X509Certificate selfSignedIssuer, BigInteger serialNumber) {
        return findStoredCrl(selfSignedIssuer)
                .flatMap(crl -> crlEntryRepository.findById(new CrlEntryId(crl.getUuid(), serialNumber.toString(16))));
    }

    private void replaceStub(String urlPath, byte[] body) {
        stopServing(urlPath);
        stubCrlPoint(urlPath, body);
    }

    private void stopServing(String urlPath) {
        mockServer
                .getStubMappings()
                .stream()
                .filter(s -> urlPath.equals(s.getRequest().getUrlPathPattern()))
                .findFirst()
                .ifPresent(s -> mockServer.removeStubMapping(s));
    }

    /**
     * Moves the stored CRL's next update ten minutes into the past, beyond the clock skew a stored CRL is still used
     * for, so the next check downloads the CRL again.
     */
    private void markStoredCrlDue(X509Certificate selfSignedIssuer) {
        Crl storedCrl = findStoredCrl(selfSignedIssuer).orElseThrow();
        storedCrl.setNextUpdate(Date.from(Instant.now().minus(Duration.ofMinutes(10))));
        crlRepository.save(storedCrl);
    }

    /**
     * Gives the stored CRL a newer base CRL number while its current delta CRL of the older base CRL stays stored, as
     * in a row that a base CRL refresh left without dropping the delta CRL.
     */
    private void keepStoredDeltaCrlUnderNewerBaseCrl(X509Certificate selfSignedIssuer, BigInteger baseCrlNumber) {
        Crl storedCrl = findStoredCrl(selfSignedIssuer).orElseThrow();
        storedCrl.setCrlNumber(baseCrlNumber.toString());
        crlRepository.save(storedCrl);
    }

    /**
     * Moves the stored delta CRL's next update ten minutes into the past, beyond the clock skew a stored delta CRL is
     * still used for, so the next check downloads it again.
     */
    private void markStoredDeltaCrlDue(X509Certificate selfSignedIssuer) {
        Crl storedCrl = findStoredCrl(selfSignedIssuer).orElseThrow();
        storedCrl.setNextUpdateDelta(Date.from(Instant.now().minus(Duration.ofMinutes(10))));
        crlRepository.save(storedCrl);
    }

    /** Runs the calls with one EntityManager bound to the thread, as open-in-view binds one to a web request. */
    private void runInOneRequest(ThrowingCallable calls) throws Throwable {
        EntityManager requestEntityManager = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager
                .bindResource(entityManagerFactory, new EntityManagerHolder(requestEntityManager));
        try {
            calls.call();
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            requestEntityManager.close();
        }
    }

    private static void assertCrlIgnoredWithWarning(CapturedOutput output, String crlUrl) {
        assertThat(output.getOut().lines().filter(line -> line.contains("Ignoring the CRL from " + crlUrl)))
                .isNotEmpty()
                .allSatisfy(line -> assertThat(line).contains("WARN"));
    }

    /** Uploads a CA and an end-entity certificate it issued whose authorityInfoAccess extension holds the value. */
    private Certificate uploadEndEntityWithAuthorityInfoAccess(byte[] authorityInfoAccess) throws Exception {
        KeyPair issuerKeyPair = freshRsaKeyPair();
        X509Certificate issuerCertificate = CertificateGeneratorHelper
                .generateCACertificate(issuerKeyPair, "CN=Malformed-Aia-Ca");
        X509Certificate endEntityCertificate = CertificateGeneratorHelper
                .generateEndEntityCertificateWithAuthorityInfoAccess(issuerKeyPair, issuerCertificate,
                        freshRsaKeyPair(), "CN=Malformed-Aia-EndEntity", authorityInfoAccess);
        uploadCertificate(Base64.getEncoder().encodeToString(issuerCertificate.getEncoded()));
        return uploadCertificate(Base64.getEncoder().encodeToString(endEntityCertificate.getEncoded()));
    }
}
