package com.czertainly.core.service;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.NameAndIdDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.v2.content.ObjectAttributeContentV2;
import com.czertainly.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateRelationType;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateRevocationDto;
import com.czertainly.api.model.core.v2.ClientCertificateSignRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.CertificateTestUtil;
import com.czertainly.core.util.CertificateUtil;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;

@SpringBootTest
class ClientOperationServiceV2Test extends BaseSpringBootTest {

    public static final String RA_PROFILE_NAME = "testRaProfile1";

    private static final String SAMPLE_PKCS10 = """
            -----BEGIN CERTIFICATE REQUEST-----
            MIICzDCCAbQCAQAwgYYxCzAJBgNVBAYTAkVOMQ0wCwYDVQQIDARub25lMQ0wCwYD
            VQQHDARub25lMRIwEAYDVQQKDAlXaWtpcGVkaWExDTALBgNVBAsMBG5vbmUxGDAW
            BgNVBAMMDyoud2lraXBlZGlhLm9yZzEcMBoGCSqGSIb3DQEJARYNbm9uZUBub25l
            LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMP/U8RlcCD6E8AL
            PT8LLUR9ygyygPCaSmIEC8zXGJung3ykElXFRz/Jc/bu0hxCxi2YDz5IjxBBOpB/
            kieG83HsSmZZtR+drZIQ6vOsr/ucvpnB9z4XzKuabNGZ5ZiTSQ9L7Mx8FzvUTq5y
            /ArIuM+FBeuno/IV8zvwAe/VRa8i0QjFXT9vBBp35aeatdnJ2ds50yKCsHHcjvtr
            9/8zPVqqmhl2XFS3Qdqlsprzbgksom67OobJGjaV+fNHNQ0o/rzP//Pl3i7vvaEG
            7Ff8tQhEwR9nJUR1T6Z7ln7S6cOr23YozgWVkEJ/dSr6LAopb+cZ88FzW5NszU6i
            57HhA7ECAwEAAaAAMA0GCSqGSIb3DQEBBAUAA4IBAQBn8OCVOIx+n0AS6WbEmYDR
            SspR9xOCoOwYfamB+2Bpmt82R01zJ/kaqzUtZUjaGvQvAaz5lUwoMdaO0X7I5Xfl
            sllMFDaYoGD4Rru4s8gz2qG/QHWA8uPXzJVAj6X0olbIdLTEqTKsnBj4Zr1AJCNy
            /YcG4ouLJr140o26MhwBpoCRpPjAgdYMH60BYfnc4/DILxMVqR9xqK1s98d6Ob/+
            3wHFK+S7BRWrJQXcM8veAexXuk9lHQ+FgGfD0eSYGz0kyP26Qa2pLTwumjt+nBPl
            rfJxaLHwTQ/1988G0H35ED0f9Md5fzoKi5evU1wG5WRxdEUPyt3QUXxdQ69i0C+7
            -----END CERTIFICATE REQUEST-----
            """;

    @Autowired
    private ClientOperationService clientOperationService;

    @MockitoBean
    private CryptographicOperationService cryptographicOperationService;

    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateEventHistoryRepository certificateEventHistoryRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
    @Autowired
    private CertificateRequestRepository certificateRequestRepository;

    private RaProfile raProfile;
    private AuthorityInstanceReference authorityInstanceReference;
    private Connector connector;
    private Certificate certificate;
    private CertificateContent certificateContent;

    private WireMockServer mockServer;

    private X509Certificate x509Cert;
    private AttributeEngine attributeEngine;

    @Autowired
    void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }


    @BeforeEach
    void setUp() throws GeneralSecurityException, IOException, NotFoundException, AttributeException {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReference = authorityInstanceReferenceRepository.save(authorityInstanceReference);

        // prepare attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid("6e9146a6-da8a-403f-99cb-d5d64d93ce1d");
        attribute.setName("endEntityProfile");
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("End entity");
        attribute.setDescription("description");
        attribute.setContentType(AttributeContentType.OBJECT);
        attribute.setType(AttributeType.DATA);
        properties.setRequired(true);
        properties.setReadOnly(false);
        properties.setVisible(true);
        attribute.setProperties(properties);
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(attribute));

        raProfile = new RaProfile();
        raProfile.setName(RA_PROFILE_NAME);
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile.setAuthorityInstanceReferenceUuid(authorityInstanceReference.getUuid());
        raProfile.setEnabled(true);

        raProfile = raProfileRepository.save(raProfile);
        List<RequestAttribute> requestAttributes = new ArrayList<>();
        requestAttributes.add(new RequestAttributeV2(UUID.fromString(attribute.getUuid()), "endEntityProfile", AttributeContentType.OBJECT, List.of(new ObjectAttributeContentV2(new NameAndIdDto(1, "profile")))));
        attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.RA_PROFILE, raProfile.getUuid()).connector(connector.getUuid()).build(), requestAttributes);
        certificateContent = new CertificateContent();
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCertificate");
        certificate.setSerialNumber("123456789");
        certificate.setCertificateContent(certificateContent);
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateContentId(certificateContent.getId());
        certificate.setRaProfile(raProfile);
        certificate = certificateRepository.save(certificate);

        raProfile = raProfileRepository.save(raProfile);

        InputStream keyStoreStream = CertificateServiceTest.class.getClassLoader().getResourceAsStream("client1.p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStoreStream, "123456".toCharArray());

        x509Cert = (X509Certificate) keyStore.getCertificate("1");
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testListIssueCertificateAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.okJson("[]")));

        List<BaseAttribute> attributes = clientOperationService.listIssueCertificateAttributes(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()), SecuredUUID.fromUUID(raProfile.getUuid()));
        Assertions.assertNotNull(attributes);
    }

    @Test
    void testListIssueCertificateAttributes_validationFail() {
        Assertions.assertThrows(NotFoundException.class, () -> clientOperationService.listIssueCertificateAttributes(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testValidateIssueCertificateAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        boolean result = clientOperationService.validateIssueCertificateAttributes(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()), SecuredUUID.fromUUID(raProfile.getUuid()), List.of());
        Assertions.assertTrue(result);
    }

    @Test
    void testValidateIssueCertificateAttributes_validationFail() {
        Assertions.assertThrows(NotFoundException.class,
                () -> clientOperationService.validateIssueCertificateAttributes(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), null));
    }


    @Test
    void testIssueCertificate() throws CertificateException {
        String certificateData = Base64.getEncoder().encodeToString(x509Cert.getEncoded());
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue"))
                .willReturn(WireMock.okJson("{ \"certificateData\": \"" + certificateData + "\" }")));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        ClientCertificateSignRequestDto request = new ClientCertificateSignRequestDto();
        request.setRequest(SAMPLE_PKCS10);
        request.setAttributes(List.of());
        Assertions.assertDoesNotThrow(() -> clientOperationService.issueCertificate(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), request, null));

        String csrWithAltKey = "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";
        request.setRequest(csrWithAltKey);
        Assertions.assertDoesNotThrow(() -> clientOperationService.issueCertificate(authorityInstanceReference.getSecuredParentUuid(), raProfile.getSecuredUuid(), request, null));
    }

    @Test
    void testIssueCertificate_validationFail_disabledRaProfile() {
        raProfile.setEnabled(false);
        raProfile = raProfileRepository.save(raProfile);
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueCertificate(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()), raProfile.getSecuredUuid(), null, null));
    }

    @Test
    void testRenewCertificate() throws CertificateException {
        String certificateData = Base64.getEncoder().encodeToString(x509Cert.getEncoded());
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/renew"))
                .willReturn(WireMock.okJson("{ \"certificateData\": \"" + certificateData + "\" }")));

        ClientCertificateRenewRequestDto request = ClientCertificateRenewRequestDto.builder().build();
        request.setRequest(SAMPLE_PKCS10);
        UUID certificateUuid = certificate.getUuid();
        certificate.setArchived(true);
        certificateRepository.save(certificate);
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.renewCertificateAction(certificateUuid, request, true));
        certificate.setArchived(false);
        certificateRepository.save(certificate);
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.renewCertificateAction(certificateUuid, request, true));
    }

    @Test
    void testRenewCertificate_validationFail_differentRaProfile() {
        RaProfile raProfile2 = new RaProfile();
        raProfile2.setName("testraprofile2");
        raProfile2.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile2.setAuthorityInstanceReferenceUuid(authorityInstanceReference.getUuid());
        raProfile2.setEnabled(true);
        raProfileRepository.save(raProfile2);

        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.renewCertificate(SecuredParentUUID.fromUUID(raProfile2.getAuthorityInstanceReferenceUuid()), raProfile2.getSecuredUuid(), certificate.getUuid().toString(), null));

        raProfileRepository.delete(raProfile2);
    }

    @Test
    void testListRevokeCertificateAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes"))
                .willReturn(WireMock.okJson("[]")));

        List<BaseAttribute> attributes = clientOperationService.listRevokeCertificateAttributes(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()), SecuredUUID.fromUUID(raProfile.getUuid()));
        Assertions.assertNotNull(attributes);
    }

    @Test
    void testListRevokeCertificateAttributes_validationFail() {
        Assertions.assertThrows(NotFoundException.class, () -> clientOperationService.listRevokeCertificateAttributes(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testValidateRevokeCertificateAttributes() throws ConnectorException, NotFoundException {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        boolean result = clientOperationService.validateRevokeCertificateAttributes(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()), SecuredUUID.fromUUID(raProfile.getUuid()), List.of());
        Assertions.assertTrue(result);
    }

    @Test
    void testValidateRevokeCertificateAttributes_validationFail() {
        Assertions.assertThrows(NotFoundException.class,
                () -> clientOperationService.validateRevokeCertificateAttributes(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()), SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), null));
    }

    @Test
    void testRevokeCertificate() {
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/revoke"))
                .willReturn(WireMock.ok()));
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes/validate"))
                .willReturn(WireMock.okJson("true")));

        ClientCertificateRevocationDto request = new ClientCertificateRevocationDto();
        request.setAttributes(List.of());
        Assertions.assertDoesNotThrow(() -> clientOperationService.revokeCertificateAction(certificate.getUuid(), request, true));
    }

    @Test
    void testRekeyCertificate() throws NotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, AttributeException, InvalidAlgorithmParameterException, CertificateException, SignatureException, InvalidKeyException, OperatorCreationException {
        stubAuthorityProviderAttributesEndpoints();

        CryptographicKey key = createCryptographicKey(null);
        CryptographicKey altKey = createCryptographicKey(null);
        CertificateContent content = new CertificateContent();
        X509Certificate x509Certificate = CertificateTestUtil.createHybridCertificate();
        content.setContent(Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));
        certificateContentRepository.save(content);
        certificate.setCertificateContent(content);
        certificate.setHybridCertificate(true);
        certificate.setAltKeyUuid(createCryptographicKey(null).getUuid());
        certificateRepository.save(certificate);

        ClientCertificateRekeyRequestDto request = new ClientCertificateRekeyRequestDto();
        request.setFormat(CertificateRequestFormat.PKCS10);
        request.setKeyUuid(key.getUuid());
        request.setTokenProfileUuid(key.getTokenProfileUuid());
        request.setSignatureAttributes(List.of());
        request.setAltKeyUuid(altKey.getUuid());
        request.setAltTokenProfileUuid(altKey.getTokenProfileUuid());
        request.setAltSignatureAttributes(List.of());
        Mockito.when(cryptographicOperationService.generateCsr(eq(key.getUuid()), eq(key.getTokenProfileUuid()), any(), anyList(), any(), eq(altKey.getTokenProfileUuid()), anyList())).thenReturn("MIIBUjCBvAIBADATMREwDwYDVQQDDAhuZXdfY2VydDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA52WsWllsOi/XtK8VcKHN63Mhk6awMboP9iuwgtPXzkFLV/wILHH+YPAJcS8dP037SZQlAng9dF+IoLHn7WFYmQqqgkObWoH1+5LxHjkPRRNPJLKPtxfM/V+IafsddK7a5TiVD+PiKjoWQaGHVEieozV1fK2BfqVbenKbYMupGVkCAwEAAaAAMA0GCSqGSIb3DQEBBAUAA4GBALtgmv31dFCSO+KnXWeaGEVr2H8g6O0D/RS8xoTRF4yHIgU84EXL5ZWUxhLF6mAXP1de0IfeEf95gGrU9FQ7tdUnwfsBZCIhHOQ/PdzVhRRhaVaPK8N+/g1GyXM/mC074u8y+VoyhHTqAlnbGwzyJkLnVwJ0/jLiRaTdvn7zFDWr");
        SecuredParentUUID authorityUuid = authorityInstanceReference.getSecuredParentUuid();
        SecuredUUID raProfileUuid = raProfile.getSecuredUuid();
        String certificateUuid = String.valueOf(certificate.getUuid());
        Assertions.assertDoesNotThrow(() -> clientOperationService.rekeyCertificate(authorityUuid, raProfileUuid, certificateUuid, request));

        certificate.setAltKeyUuid(null);
        certificateRepository.save(certificate);
        Assertions.assertDoesNotThrow(() -> clientOperationService.rekeyCertificate(authorityUuid, raProfileUuid, certificateUuid, request));

        certificate.setAltKeyUuid(altKey.getUuid());
        certificateRepository.save(certificate);
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.rekeyCertificate(authorityUuid, raProfileUuid, certificateUuid, request));

        certificate.setAltKeyUuid(null);
        certificateRepository.save(certificate);
        String fingerprint = CertificateUtil.getThumbprint(CertificateUtil.getAltPublicKey(x509Certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId())).getEncoded());
        request.setAltKeyUuid(createCryptographicKey(fingerprint).getUuid());
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.rekeyCertificate(authorityUuid, raProfileUuid, certificateUuid, request));

        request.setAltKeyUuid(null);
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.rekeyCertificate(authorityUuid, raProfileUuid, certificateUuid, request));

        certificate.setHybridCertificate(false);
        request.setAltKeyUuid(altKey.getUuid());
        certificateRepository.save(certificate);
        Assertions.assertDoesNotThrow(() -> clientOperationService.rekeyCertificate(authorityUuid, raProfileUuid, certificateUuid, request));
    }

    private void stubAuthorityProviderAttributesEndpoints() {
        mockServer.stubFor(WireMock
                .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                .willReturn(WireMock.okJson("[]")));
        mockServer.stubFor(WireMock
                .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
                .willReturn(WireMock.okJson("true")));
    }

    @Test
    void testRekeyAndRenewFromCsr() {
        stubAuthorityProviderAttributesEndpoints();
        String certificateHybridContent =
                """
                MIIXoDCCFoigAwIBAgIUalJUMfDEf/XyxRYQVI6cKrbtyiwwDQYJKoZIhvcNAQEL
                BQAwIDEeMBwGA1UEAwwVSHlicmlkZUNlcnRpZmljYXRlIENBMB4XDTI1MDYwNDEy
                MTIyMFoXDTI2MDYwNDEyMTIxOVowEjEQMA4GA1UEAwwHaHlicmlkMTCBnzANBgkq
                hkiG9w0BAQEFAAOBjQAwgYkCgYEA9y4Jl5ixO4PN5GCsRSEhzP9HXZW4ckfFngnW
                mG6l+LH7qKNl1ZpWHDrYz0DLk0og6/T4vMA6d26Ti/tI0Xw3cYntM+fwy2wXDNR+
                HGUZ/W+QiUfcMKkSIwUyYJFlWDSjPFC5IxUxR+w+D+lb1anW1xm7MchB4bhLuGD+
                +LHoLlMCAwEAAaOCFWIwghVeMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUlqNV
                ouCccyhFmyvO2F+APDhaHLYwEQYDVR0gBAowCDAGBgRVHSAAMBMGA1UdJQQMMAoG
                CCsGAQUFBwMBMB0GA1UdDgQWBBS7JkCr4cv1bDU3f0pGoztImuJeXTAOBgNVHQ8B
                Af8EBAMCBaAwgge/BgNVHUgEgge2MIIHsjALBglghkgBZQMEAyEDggehAE9u/9hl
                sevC0S0ZRTzndZ+FThMrBBVZSSsxX9WoXLCm25om4FaZhk6Cza2qRhhGUR4ITGY0
                G05yE/TNroLL1Um0h6GiN9HJXO7MiZ2tit4O8/hDOYAKXkVE7WCxisrUHnu4CAMx
                fLgfjdghdxpEQaXtseRPPkhf9MAbv+Tej1vFDQL5/s6uoSkEjBXccSlD8418Xvku
                JGS+AEAuE2mgv8i9oBYh5ju5XyrLI10MHsIxVXd4RPB5ukKiAxKqoqvyIPrpjgNv
                MA8ILeIlrN8hpbTHS9iaDily94LYDzAZbHtUXquj3Y+CxU3K6HSImG6nWZCk3kv3
                Y2TmNgORR7BtO8VkqCH8TK98UAK0ATTcrlDWRSiUuMrj9UEDUovPdrH92r8XVj07
                S0i1P/ZuXr4Np+uMEdU0gxijP/h4CnrTyIQzqvliBtiptavPexewX31PJYaDNk+6
                IWmD3HC82NBYuNADPgh757Bm96iZUvfmgjYTXHDgWgdhf3zFsKPRm5TYcYrs3XSm
                ALQSKvWszJ2ZKUG6bvPBbILsFm9Iccp0gU7SH6CtbvR30CII8I+r7FKWOGGkfN+V
                eNWvy/u19nHMcCU+l+i9odL1bthXUlDGyY2jDwIozDacnVekmJ0dreMZkTaeomF4
                zWekd0BeYnQpjvmIiW+hp1T9jQx8EA7TplimFwXKjTm6XJs1or6GzCO39qtEUnuh
                8aS/0jjvTv5vK9SD9ih3sfg4/uc5U/nel1b5qplzZ/HZWnxVpNyswbj3od4/BPbl
                ShCdJ+Wmr1tM7hYI4mMxOLUCOHMGJDtrMyVzjXRnO3PgD9VCSVaxLNebO3uctmP4
                dU6fbryLeaR2BnQsIK+V++/xeAjKkcEiqNYSSIEjrN5bQ1Z78oORieNm2v13OfQW
                bhQmN6AWN/4ATQfOdDsxAsFJX5flODD6mqpOroPwWDRpWYBoQPNFEpszmbSXMRuD
                T4cT/eTnTJKwWpkx9GORK3q1hrSlisgjhMkKCi+aAXdQf/WZQujk9M2Roklu7z9k
                SyyXtlGwTrqpXPUqvwSz5Z8Sk2x8CnVw317ocrsDaBjc1GerkfqkjtYXnsWzpjaj
                hEX6jPevI197R2Mt0CgEg+qFO8kmrsGln2LY6jwlZ0h06ttpjAFThO382lfH74ZL
                n++CFuHf+W+/wgYm43nzNXZjaYtJ5q4YqzK68C3b9+zV5cDISMKZl1z2r+Lmy8QB
                Iux6K4F1uA7ZPLAEb4SXLbpKUUA8BZMXxMLFIR9/bypN7dnu8h77SQx2TQnvHC6Z
                6Ev0UoRifacK8pIqOTWaKiVtrct0tTsKJS0KMkf6fgfy11xw+zbQX7eILUpn/q6U
                obGk6coKTMLjD0+baHuR/MWBE+seY67Cz/I7B12LF+kl73oJNybQFVh2cYgCNf7L
                4K5NJo6qxbQxw/8aQxfRJ+yUGuUBwt3rcELfpoK8IhsdjjdD2MMmC2PmKRO+FNsc
                /FOUjbCNq7CA4Vi6Xn344CGWtUTVAO2NWGZKcxN5i/7g6zpkQLsKu3ddpg0nBH+W
                lPQ5GBK/Gs5J7lDZqvX8wA7rjQ/41vrqiqKagW9vnkFFnCPH2ElSN5u9LdeF7Y6a
                89cCCoILWRkQLJSwKUuREDM5dwpWTO6fkDIoHMabVD17F5OPzaAYDB4Q/v7OvMuV
                TIpPTw+KreW/z176baFAEdMK0pS27k+Z0FAbGKIeCDEs2S91JMGH4fm7/hwYrqhu
                jF1uEKbFiMztqnes5yxbodTh5yoQl8BtYjHol1m4uKhpEDejsi1LibQ5zZicClet
                bW51VkmrTUxE9uAyUuxFXeNwkNxlpYLjk2oYdyzgL4NbYD4b7gAfEGui8QH9zLoo
                gAqE9FLC8kxnstsSTaZ9hlOosw25SEGC1CJitAjVq/VIgkYHvj39YAeVg4naWPYQ
                ynlks12C6hfyuL2xMUxNbc9rggKmgcxp2q/c3j4F4Fg4Q4mnD79eA16skQT/cWP+
                8oBEUH5GAVJQ5sWLfRzP6JTtJhbocHwckwW+x3zao1GYD3pvhO4xvBMXP43aHQzy
                Lw/WP8mUdH1cDkswg4gGrBjQ87E7rROkOg/GUdk9AkdOP4krTqnEpKplxU7lbo1f
                PzYfL5rWeYDkSCvydBqZW4+7tqVrolZP9C/EfMxvpe11rOKICmQSMyVoOyt5HYIH
                C8mSVwmZoQBUPptzJ9MIBLeZ2E+j6Uy+vvOFQgRtt7FCRIWrlhoAcASiD3gkAik6
                qLmWLSehQvh48yL6lH7aezDQumpz54CoLQpQcYNQx2IGhwKGplkuYa0pIyAcZGhl
                BxDZnVNlZkkH0VsGMMXwMUz0rWtZRD3nDOjBcr7i9hbqh7S1Prv7lBFB1ZoGyXYx
                5E2530W+DmZshNhUUaiwq6sgpq+NVy44oOeXYllQdcE1sic1+/pDEmuiBIJ7ZP59
                EvozumMChFRstYsVr4eDAIdqUGInR8iEaHxF6BVOKRL3q6SpUyvtIHtR2CnP+Z5y
                j7kYJiCEDVXwZNFFRIYlsF6DUGOW3QTdMZBfqQkFE9GtVNIyFS0hPv/hcKMCsHs9
                hZPy/gsGL9CDLhLn58Zqdny9GWgCHCilarPnMBQGA1UdSQQNMAsGCWCGSAFlAwQD
                EjCCDPsGA1UdSgSCDPIDggzuACVg4vua28/E936aoQ2KGqdZikwmSdTUvPl1rBeA
                0nstFX7yah3jTtwIZ8T3lEZq9Yj8/tuxTekq+39/SPTSu/hTEH4c9WQrsAqj7/Bh
                vDJNTW9EeYJpHNzUBot+a/mvf3dKSXsVrP9T4eHr0JHGnDctFHwsBep2KmujLKFp
                WTNRH/cWhLQm1WQhRRb7QpmdtdnFuGpextwaT4o/89aEA6Qfwgi6/GZJwWWN/13Z
                Ly9Lfdjv50iyjocxc/v9hWBPSxpjPx6jBdr9OsnkQARwBktBss8ezy6N9/UWEzhf
                X606XC1v5ZwX1pmTma3Uoh/X5Bw97h7EMfxFZeLRfHogWkNr41m0QBu2CgadYENc
                oLn1p2L25+ampOucmRntbbkOwrZ+HNimSAxvdFep/3YzRrFUcW0nukxSn0V+Ze9/
                ZgEquIJI4l2gQQAfep5JTAFugmUpZtJ/xWteToOlx1o0U6L+RpArvz49SLb7N/6c
                iad5jUJ6h5pfps7SZMSfwuen1it0VvyJ6QEiJF6Ft9pEBUHtPONKdeOAeJpz5J+b
                bqoc+BioUhUG4hHP0yMAARvaHqabG05JoA6sZWPKRwrZpxf0XHDM+VfTz59eA76+
                CqfyJJWtvKjSfEreWLBX/qHn0P1oDuEhucolJDjtKT8OIP/IjnbGFq/8oqm+1NNX
                p1wWpVSp0849R665v1mbKpXOTDHyUdI1VcU7jJD9F+DS5l3MO6mmu7A87Kx2hyVy
                8DemoHqglM+0o7wVy43ijQ5EFkRhWGqwCrmh4ppPdt1JPX3qjMZE9hmNpKqVrvu2
                5npDmA+GtRoZCOZ1WISmx+VW4Fb4lDtAFxmLqqiKTnL5SYUlPsj/nE2QUgWuu/cY
                KxWTooRI/i5hEvX96kq9h0+T1Zb+2BSG6Nv2TQdgAs0fJKGA1QXieG5NdkcX9gcy
                vnKbwwJVdVrJSLQ/Qjnutkc6AcFU+SgcIaxd9fzr47LdfVDEglFGw/1lTSFzpZ0J
                dK0pUSq8U7beyFjwEboVnEEuldwHf9m+oHxIwypmRZPkk40rwsITlVds0BmY35B/
                CK3Us9oEgfgfUgi8gLchuiyM0WPIJVXlgyUiKXd4ry0TE6/2zhuP88lvuXlkG7oM
                ZclsCTxYEOGteCXwH5tsPnxFjdeMofTTLsxdfJsbit9jgaw+O3g3/gl1aq2cVgmp
                VUP013531TmmGb7pcKymlLXa5y9CMWzpzXLOuqP327cto4M8cpbT+AbZNC79OyTB
                kn6aIn+xEyN7gT1TvbBJ6kRxUgAJ4gn3ww6eodjLcMr+bx8ZGOmfn4dX+K6qZ1OF
                7ZqSrIHuFOe74BcRk2gdHOVRTkdr9d0Vzhe8PSpPCJpNr1/oqdo1uR23Xfbp3c/J
                uswwt/qypsXYAYVCjlmI9jBNZUmvdnERYcGygm5b0J7kLhZhYQPFg8rQSHAxWxfD
                rbIvgIlbJENx05Bi07W29lyXDJ7Cyq5Zc2J014wDgPxGxStWyekCMUNOsq7cMrNo
                oMZG8gAJTzR7My2MBrCtISrqE0IKgW1pXM0xUu8h952ntk392nqAsY6ZquIY+B3r
                Efdx2jPUNGPZX9rgkQyMqiyYQXzvz66HkP4seRfBktXQqeIRQDPc7nfY591sT04G
                D2azrCAtmp+oFZd5FLD40lvbek2P9E/f/uy+6uSqSmWjKem9aoAiDE9tRw2vtNBp
                ZCx5bZAwu6jFaN0zEkOVJpXsQQq3a/Q3yAEcf+btMrKmCRYkKgXnxUEX6F8oAUIb
                UtE7fseYzGUNbphkYxt/v/3NI35rFYalCJopW+oUB0w2eavwmiqD4YaBFNW5rCGy
                GnrD7fkTlxBrMEQOqd3SPPLu/WO8cwrUO2b2fbnBV15YyVYAGF42aRyJvTr2HKLR
                3HxVC5f752PU/e9B77ujTsjdOlqEwgRBhYnNigb8uS7Z9dNf1KTpldYLsSvJ8Xr3
                c6EZC49RHwBIoK1N6gc+Ai6I6NJFVj4D5FRlR6GHfvZgL5G8uZZJJK9bb0sGh8Wx
                pBCKmbyGriYRmOrOxJYrv2zbqqDzblC23ttplpsf00v2MaQh57WHANvRSVJuWMWL
                YsUGxFR0hPB3MtrfEXrHJ3fTjDlfxeW5Y9RlnkJ0VdxiC/5tSHJMdF1UrjTC9v4v
                NEeRE5X5OOpp/0Yt8tRmMteOlK2er2J/hbIN/2T1mNsvzCwbWpjoD2+PSp6jMvDy
                7cs70Nsg5HthXcBp66mBkMxOUpjfvCSjXMGGwtaxzVhu8rG/NlSGwdkX0TAQlRqQ
                bmaKJ3waB+AZKwCmmXXqW1f0XIMFXgxsExLrQgBm0V6UDVYZQrty5OmGIh5kz6YW
                xG5ERpEIZVWrCDnUQuw44dAeTdkjPAXtVIy1O6g9RvM1L44+18MmrMO+rzUDc3E1
                6WmBkt7jA+TZVv4Ivp7/Q9SunMQ/nGi2qmxTMK4zesQ0zohp2qOPmi0C2Cu9bOOG
                LimZmYHjk56bpF/blIiNL8YjH+hmXJOhVZmDabo6bhVKb03XkJDi6fFrrOrzvHgR
                5h48vKo7vitfmP9y7T/SBHo/E0LqcTTGjWtvLEshuTBf+cyaL6A6/gVoDm8qun2o
                T6I0MdD5P10RgOEUWBCJ/j5aapbF5dRVxxydm6WGq8KSvxsm+DU7pOhoj7JWFLXZ
                bWZOHQOEt7zy7e/DTl5bXG2oujgQy4VTYsko7qT7CEAwa2eQ9VIbmeCHUfSt/ADj
                CG2Z9D4KQvUSnSRRK1CTpL5Qf1Kb6yt/viwhJ/mX6oubs9aV/E3GhaE6wE04hocW
                u1Q/slVD5kRNjEHb6I51pitd0wiVioVvpTfFQW57X/goc8sNz/lCKOv+kqjB6+6d
                jiXHDJs/6eVrZnnl6D1v6uYbQV188yo0bMRRE4/m5FSffg1I4GYt4sv9Irz4P/24
                2lw+UEP9MJuvdh+CrhWuipEnbdMgmpEjtPM2XtGalZruvtx0BvndZmJnPifUih4a
                V2KRALMZ6BYqsqLoY9wIdrTI/E+XOSpvQAzgQqcMNRcT9hXE1lBDJPa3HW2EsKTF
                NAZ4qB0tV/+hbo3g6CK5Mxq67Bl+iBsg0lpgh13/w5Wz8kLJeG6NqTkgmzRdV8OO
                DYZ+l2LjzU6EunPW2xJez1yv5u0i/Vty+3Bqusu/5q+hAacQkBkF99v5vg50Xa84
                wC7dloLJVnrR0SkP/ZVd3LxRm4frZDm966atBZYnc0CdyBqYxtaV47gDnvbj8pmk
                VLo5QToM8+8CDtMDc7HAJ/TN/hHKy6o6AnKaKESmRf8byJWdxmaTsL8qhXrki74r
                TBHT9lUTs6bBFz5HTYZYGy056ejOW9bdyhlRJvjxlv7EmL8OxEurpxODIVrW7QXU
                76gCm7+UZzm+T4gJ1k8kyVwP/hCQj+oe3xmBxAfXnUAo2mwG1PRt8RGcSkG4PfQK
                b7wl8Atj3VFLXvctU9CLG8USa+kNo6/ABAnUlbEsFAnvAtIbKc97Rj9tnUazjJLQ
                5N5biQbTcsoobZDNBDvsAWDCZaonrmTod9gGbbX3FBpXMy7GYN2xAiab1rxo6P2y
                t14P6SlkQZ+LufbLfUTaAl6RIXB6uNdrdn21sABmzm1MWRuVN0dyg1VC/bcnsWsP
                FsFpBZXpHmjXcT4okriSHQTUwgwecBfrwhMMJ8t8BZdfw28AzLn4eIUdCSrvcJhB
                EUiHnyM1sVDQzRRHigBUMPOv6uTTbPMRl+P4W/2ewOKkeb+fR15RzcMPP4YtkFIR
                eiCENVuUPlouAj3I5x0TQF55tJ0s2ZrF0TCM6EaHl4Ll4yPj1gjkcW4B7jsXZAYM
                Mpj8Osp2HYIebBHOvdlk8voPFk0CCyngg1Gdqc9CxYhFNfvzukmnHIjrZX/qCeTD
                t8Y0+h877J5HSF2XTj77xTyZ0+zKV6RFZ++Wr1KqERDW13G1e36NWm2OzSLdXsvO
                uF1hfhDFWQMjxNoh747Dtw9cPrI+5v/Sm+jGlFLNDBPb6nz1qAaTTosVp5gk9WsF
                Ow4QUa6aWP9kRIv0v9cccW+8Qn3gGFDeyBkDwh/A8x6RrKgqaKsLZkgK2bRqY1+7
                qzzcTpnKlQQSKVw1T1RiiTCPk8PAk8IFDtM7/FIfacG69BQ1Z0EwBSs7wihw3l2e
                ocqi/wOGlNhkqt1C/cHKj81znFnN/q7cozNQqV84Iqd/+T4/UFD7kfOfxRrKGHDj
                pCwq2JsnOiM2M8vvf7/NRyFM2o/YQrn/1fZH0WPPv70/1x/UCmJAsfHpVS4R8bJR
                ffncveQApL8sqNAIdq9FJoxDY89yqr2vqFw1QuGt6t2L+Yo9f/late9+qR0NzPyG
                4584EzGTn6UEZZi+xc7e8BxYd36No77V/ilMe5G/2QgbeoyZQkahxgAAAAAAAAAA
                AAAAAAAAAAAAAAUNFhwhJTANBgkqhkiG9w0BAQsFAAOCAQEAmfFMtDg4S6QBIhZR
                WA/rtof890doiLPIp3NDmAOQK9vggYDvhfjroK88MlzDzfT8vA1b9RR5NTNpM+Ct
                WtKZ+Jjnh4cVn/h5+PYkeNqWNrWVpupfuWD0lSIBn38cp0SSGtvfehl6LzLRS/oh
                VSjbbTX2v573E4fLnlNMbqzaSoaLiSPuZXz4bqYdpUDrQApALWFl32QUpyP8UeH8
                0O8Qv567aNj1+UFE2Hygh1cJdSEGUrVridaBBvBF2FrRggYO3vmZLhN6EHzzpKZB
                uffaADOzI/lZ+6ZO+sB7BhVK+cLigICTAOSxSWcXukOk1FogoJkr2OaN39EK5O95
                s66g8A==
                """;
        String differentKeysCsr = """
                -----BEGIN CERTIFICATE REQUEST-----
                MIId0jCCHTsCAQAwEjEQMA4GA1UEAxMHaHlicmlkMTCBnzANBgkqhkiG9w0BAQEF
                AAOBjQAwgYkCgYEAq7nSP64R/0esBa37i4nNXpYxWP6sCUnjA4i4zoWkuGBYBPzi
                onBvJ5qbQd2+MVi+cqwAeLbvzcoOmHgAazVkyIRBD2suwJJhzwWvB8KXnBWsWYmT
                MHZyPv6t1ymQ+yLg2SzGw6An4u1PMmU1+PvxiItTO7pi37KY4C6Q1/hbsf8CAwEA
                AaCCHH4wFAYDVR1JMQ0wCwYJYIZIAWUDBAMTMIIKPwYDVR1IMYIKNjCCCjIwCwYJ
                YIZIAWUDBAMTA4IKIQCpCerfK9QmnjXeEWCFMedaHMH9NORKz4SthwTFlUL9gL6e
                ce5xjS9iMIY9W286aa1QFa7Z6Smn6Za7cqQQkV17BPBEVNc8z3QAj54OXctczaBP
                CvZBytFNXENsiXMK3Vw6yey8olM+WAUhFeinuUP5ccyyySIVBGdMyndQFELryhpR
                vEmGq8M0HV5Q2gwqgvuYF3JJ/tHDMjns2Zhyo6n37YQUoUMtrr0+PNYnkgzt+1ZB
                2XgAtdpGaPqI8wi+G5kEUkqth3M1p6htTqpA6CHLchmDVkvcAZuPQw+8BD0umt1J
                hEwPeXRYabwvzMGjWtBI4csm9kP1w/HgQV52PiU7rRM6cyWQFr09kYNlO1PZ1hCK
                aHKqKQQg4C8GDPIcvzKP70WGCTRzIGdSnjSElTqg7vuiMksoZrvNoyJlU2IpRp9X
                uKDHX9Es9pj1xyYQYyMvw1opZx3USpibiBZvc77CEcVW5UelQOU/svqZG2bsmnba
                tOOfO9nAlX0fyl+CPu3fHBeItJLS+p0A3vsE0e42PaV0V4Aw+1fo1jv+E2TXHAdx
                ipbRpSfVWCJFQmB+t0n7+m7O1gxTMWf6R8qFqHiegBSjyBKKDYKPmSzH9gnHvjfa
                h/OEjiWoM6xywPCcB8OCg2qDZw+qCsXbbyzvu5Ifpw8cmMSJGS69EY5OyhP0X7xz
                wMP06sTfYLvz5dpWA43ZqOKyCtJVnxFYrG3zWTHd7tdJ+k6r6Ca9wLCor1xh5c2i
                XjgTKVsQnAr/LVwBnIfv3T1RATrRTeLui4yr6CsYl9grbIvV1oQnyrH4VmsyraBp
                eeQ+EE+unomMuhiqFInN1jWfgZF++vQvMNdn7SN2Yc38L13W13Xj709ND+UHlC1J
                f/ADjilxdVw/sA5C7uiHIQeIa+dii5yiLVrIqQcBJn58P7iljFKx/3JT1eoyUR2D
                saBGKu86X44ljj1HkGRyNfaA/PvQenZXdIphTzQlN4347M3E4loNzsoZjuftFNHV
                UELQxA9DsxdDlyHT0ZqBagcIAgkPBsPaVQSoboZ5EZMWcJZg6br4iXaT9Iy7lD7U
                13gnudpcln/kaIel+IX4kNBHXywbE17lS2W4/ehiGNKiHagohWmXV1E3SCyoFpwi
                ZjEGxEpkw5vy0kxsAsx/0LKEgybt3KTkdyhqxG5IBWCdQnvBxR9zxpa9wCqpWhD6
                1/YleKEZqIOnaSCCBgxtz6Er8B7Y5uSyrA6/SF1ivMmB06sz2Ge2D5wLLSB3N/vA
                yl/7RG4Z8vfAHmJLHVfe1cFTwx0+XcubFu5MYfgidrrn+ibK1TvYlp/MUlSqrCyR
                a7vAoq/zo7roOW45fTdz8WeE/Rl3aZ7ly6duZoRRJntB0cQclpcJ3K/DOiQWopbw
                WyobrVb+Bf5XyLTdn8wfSRJgzZvSfqu3T/RY36NPKMucwQQD9ElHH93JSbGCwoe9
                RfZP3cv6REhxDs+BoVhZWXLRV3guNtMLKaUhmvGHbrNUGWHPBTcbnRHtHy8hMh+M
                ktq9kye82o4d1TKt2ijattDMcBQkx2ancCIUthNJyxnBU1LD3CbN2omFuzeCQCmQ
                VVyVgoxErL+wuxF5+/zmeO59RCvVpy1brqyF3FeJ6mxkbmz0rWHkibURUHXxYO9M
                S7SGyWLLO9HH+CetJRk3Dgc7aOR1T+CTIwn8q/FVlitbGmGUwd871HyJaohTdRXe
                ifMxYTPFyGYVqagR1fuB3Qu2IyioEwOfEg6pr5phJQkJbMGagJ6Oc0GU9YVgn4pC
                bWEKBX6fLRMNH84Qx/Aj8WNcLi+Toq7I8P5ZhW8rYQb0meILdw4Dk0sVKDMWCJO4
                SgeurP730BfEOqD/yIxJiN/nz/iGY1EpIJEwNaawQMSgiaFsS5Cq76e+rGgdimB3
                et03nw2VAhrIiOe6Xyh1FXS6eIJHHt1I9oAdFOMZkWuUMOd0t0yqa/LKL4APB9Xu
                jmr6Z4qQdl++wkNJNTYKCr6BbEq4V2070CCKCibxzFOy3gDVs6yX/jlBya4vAvKS
                tjIqLY5ONbN0nhR+3DZ/oCBIF3rYLZ3vQVS531qVLScGAigY0xbmeNN+TWUbIGXJ
                Mp8xOlkzxhPQuHgm/41NkGE0hjONnQYez4hAJawwLT4es64OcUGZ3DbpykoonqJP
                B3kapBlh5qK9X68BjKLHCcpWdkJ1t/ln0XCZa+0wnW9Jby9c04zJzXuas9zGX0c/
                5IE3GpVj3GZrv8RBU5Xyo8U5ssxAoUh3TXN8L9dDe1x5l7uri8iNi3cl1TXJryQ5
                QDKKVhjWrivKn3Ia3zUq77M7VpjwpRGRogYK1p7smqdw7CKjK59AUWAi5NFBN1ur
                9xoH3Pm80ue/vMtvvSSIqCR4QMoXEpGFo/2txYHAhFcJFJHB+nsungkfhioryqDJ
                Anx3yLM3mcmvuL6IeDtB2S1FXIi/zsqL5qnNpE/IKLZVF3euzRsm1gUXSFb4/bH3
                D0M1S3ovLb3SDiiBp994kBkXF0ku4M8ASvp1KLl3LCwVkQobCDCepmxc6roxEHt1
                NQTAnliyKVnAwXy9B11Mw75U3FY9rxzY59sQqvkLKr1m2/BP9/XEJhZAl6VzNu73
                MmKyoiOGLhyb2sMyNV6GwYQxmFohMpO2td2VZqG3oUWlHpQa+zcQ1mM0La5lMz6o
                LWLjYHeEmFfM4ym/QRj/lCRWp7BzwPHoWf13ebrxg9ZTt+YuIZv2UHbcnKxCxPJZ
                PwASdvUVRSONFwq6WBVuFy0nqHlp/jNXbKwSNKC9BBX1LewsTE7eKijvPECFJKpC
                9iqpNXTz8jLQE0NcQavhvOyQqf56aDpJXkNAwXWbB0U9h7hEurhG9TxskpsdVFRI
                zXftle9xofB4TpdQg10mE2xuEkOmGoRkzXEA4Hn+i6LF18F/W2/C8xEmBeKSQHNu
                21QjdHu3lY0od0dubx24BNdDUoc4y54yTa6+sxZhLQwuHlXrGsxww3p2uSuDSFCJ
                lh/AewfE8WPQtUcDGLMzfU52Ry4mqndfbLhbBaEQQtCmXbp7JoDZIKYgWUGPZ65S
                IKszq4CRuG5D+RF/W6lQNPOfVGYWZeyYQJNweebv5N3z+oZuOIF6u0bLpablr/Yc
                ZX7HHxcFJScL4uJ+n6v+3O0czIM/ro/PJCoL7g1LlR5oh//cf3rLjvkmYbpXLcu7
                ToymVpjmf374WSu/JKrKbCQaRMcf9z6XEnMAs/fvWORMCkeCEJngF9PgwyCbmW0g
                QsX5PzU+x1IntWLLV3UYnOak7WPPYdFKzg/uMxvcyUgJOL39eyymgHedQtf1almf
                Yw2ND4Q+Dm7IC0U62stMnqdIIpwf4sYpmasHM772lPH2w3jKa/qLulmUZirN8dIe
                gT2ZKpaBRxmwXXvIkZVEy6NMI9T4ldUiSHm9hChK+zqO2Z66FFCMBZlKuZKx5Bqo
                YEieUDPxAQN5+IvR4OcwghIhBgNVHUoxghIYA4ISFACH3Ndjml4q49Vb0uL+7NzN
                Dbdtd923hJpl94YvdYZSVjGMzI/KbzUTkCGFKqcMtUkus9WEWLyFPIj7zan6cbyd
                i5PqrgUCkMJEIF4kpodoozzgKAAQ3VWu4Eop/dHsgZBRVRBqIFmjqM380DJ7TquX
                gS6EkDm6KraJks5w9lsmDnQL0qLY+GNfspK8Ep/ggkkHnFgU9AgcxlWpFCW0zqEi
                f8muSqY2/kqtkFFe6s1EdE3mFqVmaNWfG9+fsBf3y9KCck8sY+4MW29ZTAO8Ufbr
                rZc+Cbt1ghnMz/+V8gdjwPouvVmX5s6moL0Mb+4ABPplOTMB4ie0A0cjFuBPGYji
                27G2itwYB3eiNRtUsYoLX0IePAah3exrN834kmS01V0hfDlDPbIEKpDjdoVB+xie
                XliLJ9u+PdeLBAFPA8mVhpnYGBPD+FHIm37fWpGQLWeV0O2Gk2h5IKG1PVX6Eom/
                Z20LFjITDeoBRGqVtS/HYFDL53QYeIS7LQ/pQwpExUKvGUzM8I48tgSGwaImvJKt
                nK97LTnSanSYpwsK9Tz1oDRlz9H3Ag7q+b8jLosU21B4TLhbT6dH7z7N0SnYh5tW
                xoaObGVksJBhD/Zy3t2RfdOckppBKZmVlOUHcv01MrfKuXrF0SJvzpF9Md8+VB8L
                E/FlSCL+7pZMB3HUQmeBvX7oio094zhLN6oUe/QBDnXVX8TAYJXK3TfWAUFJYrmu
                9AO3XTsRdW/OAc4h4QXcZgasIfKab8jqR/oQqAdVi1KxCdZVCiyZVoXtAp8tB0Yr
                t4Pj8tTaDlvInORFNuletlbYUlBz4Z0R5MMajjzAhPrWw5K6mN+DtWZ9sFzHW1cc
                gVan22f4N0Uc9CsWtYvwLR4xQoVi+E5no7/ws8hPmm7h1IslDS7IDxayGo4F+Uqr
                FEanmMKg9mEU9KILWYgf26eQEORXE9T3SmWIxXMEAmOJJfkMYOitD9CP4+Pa5TaY
                MtNCzWyiYkw1/ra2/cnm18AJHJqpzbAeGoeMD/Vv7a6WXqbLfMKNKz5P3B+FTdxK
                L50sD9ozSI2FvwQ7NpEPBrnL7OncoPHGQi2NkGCyJK6AZf+1qxS/2v2asndj6GLb
                15qvPmgeyXtGTfZoFbcx0hb4QLx7EMILjtOrJzH9kEKi+EI+srL5shknYhRCGLdj
                74lS05HTnKHzOii+2HamL5AMP48iDR+zgvq7UyJ9LsdsBNeu41oQYOnmj8gdcH/0
                DssNysK4udLluzM4HTJ1kRWgafvneRyyjvtNNWpsbtcMlE0JqlAsysXmzWS5Xq+w
                ZbeuksuY1TpAhMvbTK+0LLSlljerCOJJh6YF/QpQMgjWB6461ZlpUj3q3Dxd/odt
                GeONAlClsqHovfvPzDTzk2F8KjXSSSK/lSbyIHmo1I6u8z3lBtLVpgt58VZ4a1fJ
                jbMePz5X0G6wYRlpcEOaUY1P5ALWJdk8gJyu/h2W9QhER7C2B5BFp7wJXeNQ5hOA
                cL+aU4Q04kxJkj70suOOgHkoP34SMTwWW7bWfMp6RalcF2LESSPUQaSVt2K4ha80
                A0ouFSfZo/1PeSXuezQpkM0SbToF98b5lONX3nmAH+KujKZJ/zynlrN7WTf+2MsB
                aXUPQh3qelkXFI3yFOt5er4mT1mw7aIAn1Ch6Br68Eq3EJ9z2K6bxvCv11JmtS95
                AJGGhw+D7T9esEsgDQMQ8g4/dSvclKDa5cvVB51X40RY7n4R0R/csuLty5qpsifj
                N1lEdLcY8MpSgwOgrWBFIF11vWjjmPmAtBc+VCFTiKrj8Eac4S3Juvz4tr3Iyxru
                zgVlbFyHoAb04+17UFucWPiF3N7ve+9wXxD+kjpR9CArXDmiQ0ibPB9A53TxkStq
                CJtf4redlgSkIfS8Wy/Oav4AVdye/AMgY7XY/O2ohrjWIY8ca6Ivg1zXXvxo/dRZ
                D6zsw/zTvh2H8a+JwOXV3ySeahIwtWGIx8qPfMDNF3+DGf9NJNjzxylomVjgOlgu
                MAlo4xjpm4Y42bibZprTEHrNTthu2vhF58UZ9G5KZd3fp2rT/9hdrLmmOael6sRp
                jS0vU97OefqvhtOw4x/HkdWd88m9U6jxheAfZ97yeXSkqJMOx4rENGvSiEXlzv8o
                ATJCaoeqybXiWE1QhspayJoCoj1NpYhA3eqgpR864iIprKWLvxQgvkbMyaw4q8is
                V91Pgoe2fSnhYz+VMsu3x7XLrapVgWD8X5e+3H/M8Vr1RUNDdze2ysmREZUOBA+A
                kgO+ehRQXJtUYHBcGKKMEefph4sVIWmZGY+zK6LU9D6cZT7gpJleBXIg1uH8jzoK
                Nz7iYRkSKyYWZmCnSMba9cUfummpEU5hC/tbW2joZwzoBQueZC1GpUDeo98QdE7Q
                dhxQbDT5gRnGXjP4BPRFi34e0EWHkKVkejJegzceiq8qHZ8Kpyb/GxAOYWIzp428
                cyrjDKJiKYEb3VGXfS/30RAQ9h8KYB6VCUkcpWIie/VvjZAfopbY6yVKol4S96oo
                UuWod1KmMO45G/xnIP79mGyPpfrgNG7qvE1cnyDYgrJCcOyfhddAZf518/ltXzW2
                ZdWOudTH2uDQ2m/C6pdnTCHKz1U8reBatp4e8eZntAh3tp8nHMz3OpvpqteNGEnm
                femyhC1m+meXzYVJ78bdyfALJoQRA6bLYfawhcg6jVShFkfcDbt65V7sNkqvGEoe
                GauUQioqgcEcpULOwhQPc8nzlB9bDWQc2TU9sHiNAkrDUqLuVSn/IXLJspvvxT2P
                PsTLqb1c55k0ujkbWcIvwKU8mPp0V6dywA2Mwktq36DFF0dA9moeHdN+CwjEplYR
                V7s34GxuTxSzgRbRscLsthwybSAxBTEsLu5zg23VHW//fzBCU2DionIXkQQlsW48
                fFHzoXBceJjcFLm/BeGGQl/aksJSSc0R125BkCm8/2TLF4k++eQlYXdWAtB3LXCZ
                su4thOXSs+Q+A4X8NlUe7b7OEqM62PPg5UJEGtFXRLQvzqnNdZdyETpzloGQj6wu
                3gZqt2VPpzROL7ZXWkBDo5w29KgQ5T/a2JSPbb8VBS0lEboJOlMmRT5e2rKOysl+
                HDeaTw1BD2+bPt/6JsA03kjewyFyWqBPJzpDZ43ME/1Pywx2gkUAnyUT9GkjnKuU
                /Dak5juHTmj3fVWR4nTHMI7ZZIv9ponZbFz2QaZZ9hdQkTk90TfcuwBPEhm59Qb3
                RN7Y6Hy5huqcV0eF4UZPpMSrBGLkoVCIB7UQrZMpTtKIff4TLz0QaTehvG4g2SNJ
                XD+GS4PREEkKN5CDFPe/OnDZyJYT8Rob4oRmANfqWSNRpMoqy4EVaDXqieN3nkj2
                nwlFCmy3K3MBIJhWCnqF0ZBnKHKHUTr7+473BCX+9XE+PqahAQiOqiH3jhZpwJr3
                eS34PLvcli00z0s07vk74LJv+Typ3/Qctm2bHNy/7fqAIFef0a7uWjlV1lBZlTZo
                NQYAys/S5i0d1kccFrUcfxG3niMtBb4sERXXIEDWU+QZP2x8u5B9UpLja0oeJ3u/
                QNrAoWEOKbdOe2xM5kpA03/tCI+oyDRvELiE7X1VCdZsiMlXI1mw0sz89aIzqMey
                7RFNtRYZczvx7LDZOM7/FZZctfOqe07nfPPbaJE/J++fMBt5FabB/Bb5jLUnb1bx
                rO4PAGGOxbQI1l+vPPsYnfKTmAp4dJMt/7ohZmdlouwVvbnhus4qiyUdFbj9iBy/
                DPYnyiRFwePCVDA1zaLvULKYbveZcqQBqrBG1T28jGNdPmQi2OVRMWkrcv7Tc7Hf
                hcL2W3WLKZu3y3G3VjYuuHkK5OoccpFC3C+bBF+fmGDI7M2WEngMDnW0RzVvZ0+K
                tGW/0n6e5QZ2UkjbTm/2cyl6jviRbfrKlnWEcOQewrTVm3ILEDRix0ouYpYcy1yb
                7lOGYOV8H1b6N0sqDptvPrm5hPFES/zMFCquCcqUis8xoG3Ci7FxmT6LfPuQyoLM
                i2nEZUO+ejfYaQtzgdPTakK5l0+raVVO8byuh6/61MRhiHQYmkRTurWRBGzczyGp
                RGkhEVI8nrWQ3yQksXeas6di0FziU6EfoWNs6qzpEvRTX1kmR9upOoiK2AqN7rwR
                iulO21zwsLBqIvIDLySj6Lvsfs6SbnrPMqqLH8hsQhoUoyD9zubBvNyRe3+PqVcX
                1FQReNX+/cscaxQTsqPv8sbaqvbt6r/UZB1EY5aaEHW/ZAGOkfrfJHAU/OTPmPoT
                RN3gcraY113uGezwkaF7rQO2ulJUqWcy14nb8WV27PZvlfQjPqI5mf4V9IkTz1eZ
                DPUtRAoKdBeIjgZLYGMEJTHwwCPdEPubm5BDX7gaiyt7Fb3M/xyAXlbrrX48/ht9
                HOtUM0FZgHM9fjZRHllXEPQywU8JEcIfltoJMRVm7hZvH0jrYXCX3JeRrsDvcC2B
                UhH5ZTPGWx5tZjNgfiwBXuYCwbgfb88ldUt/ktD9ODPzi3S/9rHPnVu3Cx3H+M3Y
                nemjs6mFkoUex7jc/ekLE5Jc/k4lLkaw8EbQGALufdRMpSCRUqTbh5AQypNfujVR
                kVcoW8DOMqteoz01sOi/46pBTOOvBHslnYe2zeH1/elyCpkB9pe2SN92ljx4es/u
                m1GrrEVV/o058wnYFDpdxVoSN8AnYGQ2d+KEYu6I4X5YEi43CpymGeVR+HmWhbyi
                XucW6r+mTFfhuK1nBk+Ky3xpCiioAig+MNK1/AQOi43uAZCLwUPhd+bZyii65LoA
                yiDwZXdhyvU2PTxhK1cHDUrE244+KHLb549MkMhb8Xci7sCuCvoL6mMx9ZK8rG1D
                brxbbm8XHhn1ZqNKe11WtRHl242t8R3W3DMzbK+lUpt8TZhcqZ2WZApRmAs4lEQY
                yZC3bMg+TMHQnlRcIb94WKnS3u5iPBDMoQncxE/MYpgO87mFJKsdSAg6ri4Qn3Ux
                97bs6C9bdr1IQPlVJ7f1KXJtVeCdoLdU+K3H7SweKuYtUqgT1CeUaLwL8FWT+K59
                Gxmrvh/8gz4zSfo/uxscPoghPoxoVzVrJtnc805fpz2dETO3+pDVzD/mJjx6EhAq
                YqKr/g/LWGONfmgql8WC93mfCHY8/DZTf705Cobrzi0P50Y6UbvGHNa/PZy7h+Cv
                gju8oc/QAhGvQmSEozc/4KpdZ5uNXgdeAkVWi6/IlEu1r0elzcsjY1Nwd3slAfqy
                Z55lYg8tf1wq3RkQZIbzDwy82rbUfWhPjnJUjSWu84NZH4wcNrL2dz2O4U7UKkWU
                I4nnxfmL7C6noJwTFXyAjiWJvgjdsXWi6FH8X+9m6dU/il4nrOORw9qOU+vdll4a
                6qUBXnIeneB4F1p7A2RJQvgdirtklrTNpLz7UKKgtrp9tR/cN74QyMaIeHdFULN5
                5i8MypHELEZkpaTF7/t3Ag0s/ehlRpCArbM8pamlvhZYtC4RfsUAQD0u+VzIXKYR
                zNUdx8kQM6LULI7eU2xoy+bkKZ2Ekb5UlT046xAmSlzZHWSTayORRcDmtEQ7AnYk
                SlhEVnnJxz8c0UoDBfYS/xN+fpsMWBKUcByhuuMiUFnNolKocqgzyhQiZJsn0mPc
                41OFOVOzfttXrIwAdeXIyeZM82SUfvnZyfn43HjHWF63i2ouaA9jfkPJFO6aAERv
                wh+0Ve0AWkrvjGuTGs4VmPibiAn2vjVIYP65S3czLxHTWfO2nuat3iPwLwCnIlfS
                670lOt5zw+FaPZoWpS75hWEYshzhSUU7vYkhB1a9sJrS8jhrRxf07cdZcqMte+lf
                rmqgw46r3X/zqz3up4RLzAhYtl3BH4ZRvrJAhrwuobB33Zuq4hbjHxmTdgnFuz1D
                tPqHG4Uj6O3IAx7oDdB/uF+h5CALynQqlwgqVRjdwN8UAqJLBtJqujMTvDHqzMbH
                3rHbhU/1AJFFFJ5awE2+IOZ/hUKd5NiQOMFIXdRQ8zQrs3osOUjbD+BC3vT1uJfu
                3lan6nqoBfdyvuQha6fFHm6Dr3BwKnX3QMRl7CdOYOziMcixrb2CqBqE4CFHaGaR
                ubFMEy7tzytc4nJ0xe71qxU2TU6GsfL6LlZ3r8vP1ucYiouRpKyyxGOi/XsEapGm
                2+DiMzSRuvNPU2qRq63L+QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgQGBsc
                IygwMA0GCSqGSIb3DQEBBAUAA4GBAD6JpF+9E+r9YOgiGj1LE5ArYGDwOyNLpl9t
                J6pMafFSRjBY6n15YsZDWMGWemfQuM+3IaY+iOVEqMeuC+Hl7UNAmPIP8W5gtITG
                Ug8KbA5AWmuoAjrYhT5opI3A3iCxXvQefeSRNvoJs1BYE9/6pt82WDq4phub/v/Q
                ZMtR7+9m
                -----END CERTIFICATE REQUEST-----
                """;
        String matchingKeysCsr = """
                -----BEGIN CERTIFICATE REQUEST-----
                MIIWLDCCFZUCAQAwEjEQMA4GA1UEAxMHaHlicmlkMTCBnzANBgkqhkiG9w0BAQEF
                AAOBjQAwgYkCgYEA9y4Jl5ixO4PN5GCsRSEhzP9HXZW4ckfFngnWmG6l+LH7qKNl
                1ZpWHDrYz0DLk0og6/T4vMA6d26Ti/tI0Xw3cYntM+fwy2wXDNR+HGUZ/W+QiUfc
                MKkSIwUyYJFlWDSjPFC5IxUxR+w+D+lb1anW1xm7MchB4bhLuGD++LHoLlMCAwEA
                AaCCFNgwFAYDVR1JMQ0wCwYJYIZIAWUDBAMhMIIHvwYDVR1IMYIHtjCCB7IwCwYJ
                YIZIAWUDBAMhA4IHoQBPbv/YZbHrwtEtGUU853WfhU4TKwQVWUkrMV/VqFywptua
                JuBWmYZOgs2tqkYYRlEeCExmNBtOchP0za6Cy9VJtIehojfRyVzuzImdrYreDvP4
                QzmACl5FRO1gsYrK1B57uAgDMXy4H43YIXcaREGl7bHkTz5IX/TAG7/k3o9bxQ0C
                +f7OrqEpBIwV3HEpQ/ONfF75LiRkvgBALhNpoL/IvaAWIeY7uV8qyyNdDB7CMVV3
                eETwebpCogMSqqKr8iD66Y4DbzAPCC3iJazfIaW0x0vYmg4pcveC2A8wGWx7VF6r
                o92PgsVNyuh0iJhup1mQpN5L92Nk5jYDkUewbTvFZKgh/EyvfFACtAE03K5Q1kUo
                lLjK4/VBA1KLz3ax/dq/F1Y9O0tItT/2bl6+DafrjBHVNIMYoz/4eAp608iEM6r5
                YgbYqbWrz3sXsF99TyWGgzZPuiFpg9xwvNjQWLjQAz4Ie+ewZveomVL35oI2E1xw
                4FoHYX98xbCj0ZuU2HGK7N10pgC0Eir1rMydmSlBum7zwWyC7BZvSHHKdIFO0h+g
                rW70d9AiCPCPq+xSljhhpHzflXjVr8v7tfZxzHAlPpfovaHS9W7YV1JQxsmNow8C
                KMw2nJ1XpJidHa3jGZE2nqJheM1npHdAXmJ0KY75iIlvoadU/Y0MfBAO06ZYphcF
                yo05ulybNaK+hswjt/arRFJ7ofGkv9I4707+byvUg/Yod7H4OP7nOVP53pdW+aqZ
                c2fx2Vp8VaTcrMG496HePwT25UoQnSflpq9bTO4WCOJjMTi1AjhzBiQ7azMlc410
                Zztz4A/VQklWsSzXmzt7nLZj+HVOn268i3mkdgZ0LCCvlfvv8XgIypHBIqjWEkiB
                I6zeW0NWe/KDkYnjZtr9dzn0Fm4UJjegFjf+AE0HznQ7MQLBSV+X5Tgw+pqqTq6D
                8Fg0aVmAaEDzRRKbM5m0lzEbg0+HE/3k50ySsFqZMfRjkSt6tYa0pYrII4TJCgov
                mgF3UH/1mULo5PTNkaJJbu8/ZEssl7ZRsE66qVz1Kr8Es+WfEpNsfAp1cN9e6HK7
                A2gY3NRnq5H6pI7WF57Fs6Y2o4RF+oz3ryNfe0djLdAoBIPqhTvJJq7BpZ9i2Oo8
                JWdIdOrbaYwBU4Tt/NpXx++GS5/vghbh3/lvv8IGJuN58zV2Y2mLSeauGKsyuvAt
                2/fs1eXAyEjCmZdc9q/i5svEASLseiuBdbgO2TywBG+Ely26SlFAPAWTF8TCxSEf
                f28qTe3Z7vIe+0kMdk0J7xwumehL9FKEYn2nCvKSKjk1miolba3LdLU7CiUtCjJH
                +n4H8tdccPs20F+3iC1KZ/6ulKGxpOnKCkzC4w9Pm2h7kfzFgRPrHmOuws/yOwdd
                ixfpJe96CTcm0BVYdnGIAjX+y+CuTSaOqsW0McP/GkMX0SfslBrlAcLd63BC36aC
                vCIbHY43Q9jDJgtj5ikTvhTbHPxTlI2wjauwgOFYul59+OAhlrVE1QDtjVhmSnMT
                eYv+4Os6ZEC7Crt3XaYNJwR/lpT0ORgSvxrOSe5Q2ar1/MAO640P+Nb66oqimoFv
                b55BRZwjx9hJUjebvS3Xhe2OmvPXAgqCC1kZECyUsClLkRAzOXcKVkzun5AyKBzG
                m1Q9exeTj82gGAweEP7+zrzLlUyKT08Piq3lv89e+m2hQBHTCtKUtu5PmdBQGxii
                HggxLNkvdSTBh+H5u/4cGK6oboxdbhCmxYjM7ap3rOcsW6HU4ecqEJfAbWIx6JdZ
                uLioaRA3o7ItS4m0Oc2YnApXrW1udVZJq01MRPbgMlLsRV3jcJDcZaWC45NqGHcs
                4C+DW2A+G+4AHxBrovEB/cy6KIAKhPRSwvJMZ7LbEk2mfYZTqLMNuUhBgtQiYrQI
                1av1SIJGB749/WAHlYOJ2lj2EMp5ZLNdguoX8ri9sTFMTW3Pa4ICpoHMadqv3N4+
                BeBYOEOJpw+/XgNerJEE/3Fj/vKARFB+RgFSUObFi30cz+iU7SYW6HB8HJMFvsd8
                2qNRmA96b4TuMbwTFz+N2h0M8i8P1j/JlHR9XA5LMIOIBqwY0POxO60TpDoPxlHZ
                PQJHTj+JK06pxKSqZcVO5W6NXz82Hy+a1nmA5Egr8nQamVuPu7ala6JWT/QvxHzM
                b6XtdaziiApkEjMlaDsreR2CBwvJklcJmaEAVD6bcyfTCAS3mdhPo+lMvr7zhUIE
                bbexQkSFq5YaAHAEog94JAIpOqi5li0noUL4ePMi+pR+2nsw0Lpqc+eAqC0KUHGD
                UMdiBocChqZZLmGtKSMgHGRoZQcQ2Z1TZWZJB9FbBjDF8DFM9K1rWUQ95wzowXK+
                4vYW6oe0tT67+5QRQdWaBsl2MeRNud9Fvg5mbITYVFGosKurIKavjVcuOKDnl2JZ
                UHXBNbInNfv6QxJrogSCe2T+fRL6M7pjAoRUbLWLFa+HgwCHalBiJ0fIhGh8RegV
                TikS96ukqVMr7SB7Udgpz/meco+5GCYghA1V8GTRRUSGJbBeg1Bjlt0E3TGQX6kJ
                BRPRrVTSMhUtIT7/4XCjArB7PYWT8v4LBi/Qgy4S5+fGanZ8vRloAhwopWqz5zCC
                DPsGA1UdSjGCDPIDggzuAOpCXUzuZGFuThBcIksWocpv9zJS3gijAaTcmKKUcFSp
                ZHwsFzeYzDZGgjyj9waKFhhnoteCDVe9BpNqhov2dj7MZGXQQr8lUpHidbFiXY2h
                0R4r4ZLHd1kphL5jfCmipYblsMIjIWzdywD9ApIVZ1avhcx0H6Ei8k2/KRsFHKF7
                8O+6r9i6H0qnSqVf5j6jYF+wzvxFjLjCCjFIl31EE9jU1ZH9csIt1AXMDszVI7xJ
                Yg1xQv2hJtECNTxrIURXZxcuFpEUg5KGXLqSf5CleEHEsa4k9lbw/qgzMaH95CrU
                vLrVekHU5qruRh2MMD1juYlH8H9LHZyaiCMPozaf39U/lGd15hA7IAxM3TLmo/Zk
                p82ImGfLhgPNJm9SzYaIEj+c/AFqgA55yBt0KlDTt4/Pk5JH8cOIAOI07oARQat5
                5Xe7QDUmh30rXzWga1tSjnZA9PDnlzIym020FNvMT5QVBmxMCxWTvdzKGX0qPWNW
                YQJPMYd0PBiwuro59Jwvm+K9TBOs78cUZAlrqNTJUUPkMpgx8ydh4Ok2MuoqDkGI
                BVBDSeGN5aYTz2TJdXZxPrNIgq8VLuVZyaS0ucVqLzLh8RTVzNjd4VEYfJNS2ZTx
                C6894+0lUUwh5+6uWrJVHM2mvmWBqz04tSPoPYQ8aTemmdbo+LM+XYbYtvWEHIZm
                M5SAxDnO/sRIR72AQl9M+08igHBPtfGu9aVTAVjKj0h9UAm843ocCTjhkzD/cEgW
                its+7RPZxoHxT8KtHZ/SAMWXiqnR18jVzfn9pvbWuLaxuD2CpSfY7fyjLOduuAEU
                51Et9Ovc5vOozwtnq7lhHFZC/B1gFFY/si1iVXUtKAJP9LrG/0Weoz3anwNH8r9y
                z4hoTGaDtkVR/pyAI7Q4HQlvOQ0UIc+uVbDkXwgO+y2/miJ2wtJX6efepxxbMpCx
                S6LEfG+sNe0MoeqCt9HrJHCGr0ybZu/woV1dhhsq0ZY7UYrNMZUxtSHq48pW4M6q
                tlWLz5R4pH/YL1fsIQwJ9DvJi3U7mTNWn/HDidqO95kJcg/YwTJ7AnjN6uODN4WG
                6l6s94N/ttZ1EvDBUNPnUHJXJ2iUZ1PILBRpDL31ubR6Zp+vC1yy2ZokwHzAoGoS
                P7y3K1JUcDpR3kd5wZuFiQgB7WqIufjvT6/o5iSMXOZ/8UuQFQ4GOV4U8PlfNqXJ
                8TFE5ffwPb4hmJnwvUsOEFlvXXLwDFHoNmRCGtcoRfZH01WGXSea+FmOWPjvFMtz
                x6kHiP5ric3m5Gu2RMVoi9BgDtvcX7ZCuh8YgB62vMbyaCoEotShr0ogOQOAF73O
                o6jgV86ShpRvBO9Z3+RxthQ/z9oQKO8tOm1brcvPvyc9+BuochYU+H2CzJfdtKJn
                ME36/aF06doKV0l4X24+yWwTR64VynNX4PE/8O0WNj7Zt5Cath5+krsVxmQ77V4z
                CFByZ9EdI+Kig83/pS1CNq/mbTnr5ueDwJOXVE3/QJr6jWaI+t/+1Qb0ts8ewanE
                Niqtn7l2qRlbZ+0YP8/5ZvXqrWkjipsEEUbd7weK6El+KODCIUt0lgyFx8WpX4lb
                ukP7xs6KsFAvhr4OxIgAXvU2498mOCFmo+t1CH+N0VYu/+O72Zs7k5R/NKotLThU
                /jg2zVD/YIhbevPXVkEcxwJhFp3tSduqku1Arbca8q3sldqm/WUx4Z+tOIeTBcmg
                nTTqkI0jJh7qPPyAgqJaaX9VmGXYn7MnsucpwqSw5gq5W0CO/jH1bVpmg1ZeEeKt
                dffXA5sgqg267p3P6IZLoXevGp8u3s3hHWJ47TzND6/RShYPJtHnBwy8vhTgRBYO
                Xjrw6TG/9t1XgfDZLMAzTQXlkf45Jy6WYk0hB4V/jYytdvXgT4DdaOkjXcxsuPuo
                baL+gigZS1jV4kdpAuPMQA9dQO5IDu5kbHBLUY8KmbOgDye2b/DgXEb/dXwxD58p
                VUW1nYPbMGVDpT7Xvpu/zZY0U1eAQfa+DUhFt6UFMgQogczsUPO+r3W/lNR/8fli
                SfzM28mYf3vMKJnmsbgfsFFxtx650/Ok552HLb7PEJteWV+EZ/pSXXAHLev83qDJ
                3rczopm4L/X+m3QTf0Xkhd1HomhKN+HR5pv3xN8RF8O45LySB03GME61HcZ/UpDO
                jD1Yb66l6DIijLLyDA1pxXT4zIHlA/sbISCPPRnBdQF3MgDkbn4fItZr5twkWc0P
                1sM07P/mNTJE0qHCH7vlUHwgSHIU88l8RozXoM0TvpWJAyD01eBD05mw4JdtZX9y
                eqkELJ2swOSRq8ghLOl0v0Oql1g7zoymNNzGLlr3Ov4xZPGjqbhEvBePvkMv2RCG
                hPjbQaZmRaRTHLDuAP8QoZ/89miHkg/nbPuNbZwbtN1nsTJkSvM57Xg6A8LMG/2H
                DmGRI6EbKa7a1RX6Snc8QH/PpNGeGohBwWj7RrqgX6Xyn9jtUAtNhbBh8myMvpUP
                fcEglpYwKOERqY9dZ54+IasL5WnwA9DdTND5Iwvdyg2rdvHcuo5pLwrkiG53EK99
                gcRDN8n11IC5Z00XJwRgTraFlKkXSYJS7mKqr4FrmXhdUfEpsRC1YGKCf/z5bElb
                1QAzbgT7hRZwHCUaSeGG45PdmSop9taiMlGoa+raopajAx/iKZMT3Jm3R8+7OeWR
                /sqH0EJxXUReoD1DuRwVsTifBbQBHsCWqRGoU1wMbJ3ORl1PUF4V1E0OUojMhL2c
                Nipdf2PZ6Dkwz0tjFMegWCykB4qgeocAhy3GvCpxr/3M2r1xMoCWShrI/hcvY+vN
                zvr06XMnLdz2AK4JPm+M8BJsf6GKjXNdo1ioouEfYhmMSatkVQvQrhm6HOgH/h0t
                UYFP1KRR/AlznMfFyIik1WYcoOmSj1wA4gILWTXONAS08uqiVUIxWBqmGL9nJcir
                7d5hKe42k7Ag3q7Nal6b2is3fwnKKddjufhemiD/m9kmMeDqKqJMryb+hlAa8YaI
                Eykbr036EbdKuyxoj+2Xcp+GVwOeWYwk22ZNGdeG/hqtQjTBz+Fy1dCLwUR55Aj4
                gUkmJy2VAcacK/1+b7X1vRg8DQksA4KgTmWD7YyHbB7G4FeMzkLpMZkOciwMQpy4
                KDWE0HAVJBxCNvn54rH9OgnNwLRKeGUMhJbzo8pK2jyoDEr+5b2O+q3J6UyCUlqf
                +4uBJ5F3Y8sQrnVBj7emutMo827Bv9dBgBi/G/9ou79NcS/8DIT1h+249C7Ayj3+
                n2+FbpTZlwzIOb7iweTijWRZXvGx133XSo7hf5ASuLnG1l/jLdVyBIbiQh7ILJoE
                PlsF6aOmsqWTb7/P6Oqjw+cD/CG2RzZweSdcUSDSFAqXEbB3Jo6uWYEm1+B2gJlh
                uUZwcFleO6lMcg16yJvJ5x60mi+W51PiC+sxrgSXm9Q8elgyb8RzaU8MvXFj2uYs
                0Uu6SwWYU9I8rgLftj+FOj0Nbmsr5Uhu1jB4qKr5wjOdGPAxADKkkqhpukNB9cII
                8DreLiYcUEAWaLQvukJvWv2zag7fe91xuelakmdj9u+ME7lfe4IU+oN6Vkd6gRPw
                NPzecb95PZxTO2yVWqjvzQ4VxaLFOPYE2G60TPmDhAq67oo+myo7NG5Y2Ejointc
                TeEkug1SUl5ucU2/y3V+r92L74zxFIAwYCL9sE14CNBaCnIfGIDFd6JcCuErYpzy
                AjRf1rmMCzQjS8EfzDqflapwa0VAdkP7dduTLFZ/Pavq+QNUTYdLamN3R7b2Wpqd
                qsn2PptrvmPwGJCTFho/8bX9B2C82lXZm8Vx1r5h6T0SEhp95Z57Prt7W0vBLdWi
                PtiNBVEMhUhmunwJvlD7pLj5bgcjvIBwe9QG2CN4xGznb9Be1hyMlsj0ZTV9eSwQ
                p+MrpVUPQgjv0+LnjH2u7QvAz1nUxQMFytO9AYaMJqOCZZJZykOvK9tWyVoTpLst
                KZVGiV/88LWoFhrazl+xpWJ1tMemA3/tCHQpKWJlingKTU17zbDfZKMeM8AbiTei
                k25nPVn1/Q9vsJA27etkJgOhHqKcmeKUaDvwQ3zBSLd7PoDcGbbrwQVo/ZRHz91G
                5NpO5TKVU01M5ZPY3+HFy8B5tq7muTbxwA5Zl4QommclCHd2XcCDj2dIv7e2gNHx
                XIi+sixAGVEcOMr//ZY+wSA6dE9QHjnV3SEms8YZ5wNAaWdBqedYHQD64ZFSOI+D
                x9SnsqQKn7beC8JKnLzbVgSlrdm4b1FhBqVin18ANv+/d9Baaanr7bYFPWszAtFg
                WxLXiLRtOZC7FYog4dnJeh161/rcFgIK74hqeDM/DU5Tu0LzJhsIaPZyGL5ldSdN
                DCwvepHR6jVhdLa3w+s1Pn6JtuHoRHaGmvQDChwjXW6CpbTN6vkLGJCox8ze5gAA
                AAAAAAAAAAcOFRomLjANBgkqhkiG9w0BAQQFAAOBgQAeM3e2qIkKB4icAQxQMjdL
                VJtAPsJy2iMoWlHg2YtBplgbDfeebU+7X+8PMM6VBWM9oWbgM+sJPT39zvDI3THM
                aeB0hYLgkse1PD0IOKj0NUO38BH9tzN2mlpmf1JzLvF28aPDCU/sQIRubi5NAu4p
                CPM1ge5eve8QRUsSlEyC/w==
                -----END CERTIFICATE REQUEST-----
                """;
        String csrWithoutAltKey = """
                -----BEGIN CERTIFICATE REQUEST-----
                MIIBUTCBuwIBADASMRAwDgYDVQQDEwdoeWJyaWQxMIGfMA0GCSqGSIb3DQEBAQUA
                A4GNADCBiQKBgQD3LgmXmLE7g83kYKxFISHM/0ddlbhyR8WeCdaYbqX4sfuoo2XV
                mlYcOtjPQMuTSiDr9Pi8wDp3bpOL+0jRfDdxie0z5/DLbBcM1H4cZRn9b5CJR9ww
                qRIjBTJgkWVYNKM8ULkjFTFH7D4P6VvVqdbXGbsxyEHhuEu4YP74seguUwIDAQAB
                oAAwDQYJKoZIhvcNAQEEBQADgYEARgLMUonAgPTXA8ojq+XjfQifn5+reL+PmrZr
                Qugaixie4quVynrBvWOjntvpcvUd+1Npv5OnzH1zUy0qevjlBHKgIU8Ik5eFEzix
                vYVNWa+wjIpPTCOR77Xy0x5BL6W3EtBtu/OTCNne2zxc/usyeXogA8xdrLh9aikH
                vgtpHCg=
                -----END CERTIFICATE REQUEST-----
                """;

        CertificateContent content = new CertificateContent();
        content.setContent(certificateHybridContent);
        certificateContentRepository.save(content);
        certificate.setCertificateContent(content);
        certificateRepository.save(certificate);
        ClientCertificateRekeyRequestDto rekeyRequest = new ClientCertificateRekeyRequestDto();
        rekeyRequest.setFormat(CertificateRequestFormat.PKCS10);
        rekeyRequest.setRequest(matchingKeysCsr);
        SecuredParentUUID authorityUuid = authorityInstanceReference.getSecuredParentUuid();
        SecuredUUID raProfileUuid = raProfile.getSecuredUuid();
        String certificateUuid = String.valueOf(certificate.getUuid());
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.rekeyCertificate(authorityUuid, raProfileUuid, certificateUuid, rekeyRequest));

        rekeyRequest.setRequest(csrWithoutAltKey);
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.rekeyCertificate(authorityUuid, raProfileUuid, certificateUuid, rekeyRequest));

        rekeyRequest.setRequest(differentKeysCsr);
        Assertions.assertDoesNotThrow(() -> clientOperationService.rekeyCertificate(authorityUuid, raProfileUuid, certificateUuid, rekeyRequest));

        ClientCertificateRenewRequestDto renewRequest = new ClientCertificateRenewRequestDto();
        renewRequest.setRequest(matchingKeysCsr);
        Assertions.assertDoesNotThrow(() -> clientOperationService.renewCertificate(authorityUuid, raProfileUuid, certificateUuid, renewRequest));

        renewRequest.setRequest(differentKeysCsr);
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.renewCertificate(authorityUuid, raProfileUuid, certificateUuid, renewRequest));
    }

    private CryptographicKey createCryptographicKey(String fingerprint) {
        CryptographicKey cryptographicKey = new CryptographicKey();
        TokenProfile tokenProfile = new TokenProfile();
        tokenProfileRepository.save(tokenProfile);
        cryptographicKey.setTokenProfileUuid(tokenProfile.getUuid());
        cryptographicKeyRepository.save(cryptographicKey);

        CryptographicKeyItem privateKey = new CryptographicKeyItem();
        privateKey.setKey(cryptographicKey);
        privateKey.setType(KeyType.PRIVATE_KEY);
        privateKey.setEnabled(true);
        privateKey.setState(KeyState.ACTIVE);
        privateKey.setKeyAlgorithm(KeyAlgorithm.RSA);
        cryptographicKeyItemRepository.save(privateKey);
        CryptographicKeyItem publicKey = new CryptographicKeyItem();
        publicKey.setKey(cryptographicKey);
        publicKey.setType(KeyType.PUBLIC_KEY);
        publicKey.setFingerprint(fingerprint);
        publicKey.setEnabled(true);
        publicKey.setState(KeyState.ACTIVE);
        publicKey.setKeyAlgorithm(KeyAlgorithm.RSA);
        cryptographicKeyItemRepository.save(publicKey);

        return cryptographicKey;
    }

    @Test
    void testRevokeCertificate_validationFail() {
        Assertions.assertThrows(NotFoundException.class, () -> clientOperationService.revokeCertificateAction(UUID.randomUUID(), null, true));
    }

    @Test
    void testCertificateActionsWithArchived() {
        certificate.setArchived(true);
        certificateRepository.save(certificate);
        UUID certificateUuid = certificate.getUuid();
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.issueCertificateAction(certificateUuid, true));
        ClientCertificateRenewRequestDto renewRequest = new ClientCertificateRenewRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> clientOperationService.renewCertificateAction(certificateUuid, renewRequest, true));

    }

    @Test
    void testHandleFailedOrRejectedEvent() throws NotFoundException, NoSuchAlgorithmException {
        CertificateRelation relation = new CertificateRelation();
        relation.setSuccessorCertificate(certificate);
        Certificate predCert = new Certificate();
        predCert.setCertificateContent(certificateContent);
        certificateRepository.save(predCert);
        relation.setPredecessorCertificate(predCert);
        relation.setRelationType(CertificateRelationType.PENDING);
        certificateRelationRepository.save(relation);
        UUID certificateUuid = certificate.getUuid();
        clientOperationService.issueCertificateRejectedAction(certificateUuid);
        Assertions.assertFalse(certificateRelationRepository.existsById(relation.getId()));
        certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow();
        Assertions.assertEquals(CertificateState.REJECTED, certificate.getState());

        certificateRelationRepository.save(relation);
        certificate.setState(CertificateState.REQUESTED);
        CertificateRequestEntity certificateRequest = new CertificateRequestEntity();
        certificateRequest.setContent("content");
        certificateRequestRepository.save(certificateRequest);
        certificate.setCertificateRequest(certificateRequest);
        certificate.setCertificateRequestUuid(certificateRequest.getUuid());
        certificateRepository.save(certificate);
        Assertions.assertThrows(CertificateOperationException.class, () -> clientOperationService.issueCertificateAction(certificateUuid, true));
        Assertions.assertFalse(certificateRelationRepository.existsById(relation.getId()));
        certificate = certificateRepository.findByUuid(certificateUuid).orElseThrow();
        Assertions.assertEquals(CertificateState.FAILED, certificate.getState());

        stubAuthorityProviderAttributesEndpoints();
        certificateRelationRepository.save(relation);
        certificate.setState(CertificateState.REQUESTED);
        certificateRepository.save(certificate);
        ClientCertificateRekeyRequestDto rekeyRequest = new ClientCertificateRekeyRequestDto();
        Assertions.assertThrows(CertificateOperationException.class, () -> clientOperationService.rekeyCertificateAction(certificateUuid, rekeyRequest, true));

        stubAuthorityProviderAttributesEndpoints();
        certificateRelationRepository.save(relation);
        certificate.setState(CertificateState.REQUESTED);
        certificateRepository.save(certificate);
        ClientCertificateRenewRequestDto renewRequest = new ClientCertificateRenewRequestDto();
        Assertions.assertThrows(CertificateOperationException.class, () -> clientOperationService.renewCertificateAction(certificateUuid, renewRequest, true));



    }
}
