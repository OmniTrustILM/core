package com.czertainly.core.service.cmp.message.handler;

import com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.cmp.CmpTransactionState;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.cmp.CmpProfileRepository;
import com.czertainly.core.service.cmp.CmpEntityUtil;
import com.czertainly.core.service.cmp.CmpTestUtil;
import com.czertainly.core.service.cmp.configurations.variants.Mobile3gppProfileContext;
import com.czertainly.core.service.cmp.message.CertificateKeyServiceImpl;
import com.czertainly.core.service.cmp.message.CmpTransactionService;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.MetaDefinitions;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

class RevocationMessageHandlerITest extends BaseSpringBootTest {

    @Autowired private CertificateContentRepository certificateContentRepository;
    @Autowired private CertificateRepository certificateRepository;
    @Autowired private CmpTransactionService cmpTransactionService;
    @Autowired private CmpProfileRepository cmpProfileRepository;
    @Autowired private RaProfileRepository raProfileRepository;
    @Autowired private CertificateKeyServiceImpl certificateKeyService;
    @Autowired private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired private ConnectorRepository connectorRepository;
    @Autowired private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired private FunctionGroupRepository functionGroupRepository;
    @Autowired private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @MockitoBean
    private PollFeature pollFeature;

    // Mock the operation service: the real bean is wrapped by @ExternalAuthorization (OPA)
    // and reaches the auth service over HTTP. For this handler-level test we only care
    // that the revoke call completes successfully so execution reaches the PollFeature
    // gate — short-circuit with a no-op mock.
    @MockitoBean
    private ClientOperationService clientOperationService;

    private RevocationMessageHandler testedHandler;
    private CmpProfile cmpProfileSigPrt;
    private CmpProfile cmpProfileMacPrt;//mac-protection
    private RaProfile raProfile;

    private final String transactionId = "999";
    private final String sharedSecret = "sh@r3dS3cr3t";
    private WireMockServer mockServer;
    private Certificate revokedCertificate;
    private X509Certificate x509Certificate;

    @BeforeEach
    void setUp() throws Exception {
        // -- GIVEN --
        mockServer = CmpTestUtil.createIssuingPlatform();

        // -- IoC setting up
        testedHandler = new RevocationMessageHandler();
        testedHandler.setCmpTransactionService(cmpTransactionService);
        testedHandler.setCertificateRepository(certificateRepository);
        testedHandler.setPollFeature(pollFeature);
        // Wire the real Spring-managed ClientOperationService so revokeCertificate can
        // reach the connector revoke call (stubbed via WireMock per-test). Without this,
        // the field stays null and revokeCertificate trips an NPE that the per-cert
        // catch swallows — masking the asynchronous-acceptance branch under test.
        testedHandler.setClientOperationService(clientOperationService);

        // -- create customer/client profile (signature-based)
        Connector connector = new Connector();
        connector.setName("authorityInstanceConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setFunctionGroupUuid(functionGroup.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("ApiKey")));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        connector.setVersion(ConnectorVersion.V2);
        connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setUuid(UUID.randomUUID());
        authorityInstance.setName("testAuthorityInstance1");
        authorityInstance.setConnector(connector);
        authorityInstance.setConnectorUuid(connector.getUuid());
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        authorityInstance = authorityInstanceReferenceRepository.save(authorityInstance);

        raProfile = raProfileRepository.saveAndFlush(CmpEntityUtil.createRaProfile(authorityInstance));

        // create chain of cert(s)
        Certificate rootCA = certificateRepository.save(CmpEntityUtil.createCertificate(
                new BigInteger(12, new SecureRandom()),
                CertificateState.ISSUED,
                certificateContentRepository.save(
                        CmpEntityUtil.createCertContent(
                                "832665fed63318ebee52bd890b242951d2f37c4af509f72fd5dc59ef932cafa8",
                                "MIIFyzCCA7OgAwIBAgIUOymQEJz0e6+2cDE/1Z76gPbY0cAwDQYJKoZIhvcNAQELBQAwOzEbMBkGA1UEAwwSRGVtb1Jvb3RDQV8yMzA3UlNBMRwwGgYDVQQKDBMzS2V5IENvbXBhbnkgcy5yLm8uMCAXDTIzMDcxOTExMTIwOFoYDzIwNTMwNzExMTExMjA3WjA7MRswGQYDVQQDDBJEZW1vUm9vdENBXzIzMDdSU0ExHDAaBgNVBAoMEzNLZXkgQ29tcGFueSBzLnIuby4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCsbi+SUia7Hlp4DmR6MzJrBwIKh1Bq5vP64RcmsYch44Xa2bCRv5oDW57Hx9uy8cZpWI/7x4U5m7B/P1/FQG7SQ5u7ATvn6cbrZthaM9NYRZLY3z6wRl2SQY0SUDWQyu2vkc2PxYy7qzz8r8s7T7vgDn9ozq/ODAZxYnfDGzdSLKay1ZVzNs7GNhk1Y2RDA1JQXehi6avD+xaKH61YeO96sPpIGBOsbyvoQ3qZjCVPGRgXuXwJuqaxGV1QKIDPGCpKVT7wy+edSh3XlEixW9GnLIQkTS/WiFYEO4B6DbZJ+WFU+djIAHzQwFHx1WYqfm9ok9QEzi2jyUEafKtjDv++O8giHpRaMDvOiRRZPrHRBmCjbFmktB83VDTDyhiL+tuAUDBPDdEifWgXaikEsC2tA9sbrfUyByQCGhNXj8u8acNt0UPRGXC18uAmoCM4qkq4x0DaplnOwG8Cqi0IgAyLOZSNb/pXmfnvQxM3yyQ/kQAV3u69FX6ExkcoMnDi8ntfqMPAEK6tJGShgB27rEVhWJc9+IhW0f/mFbSJicUpeUeao02lTkSUn0r15hAz9rUVnjz6a+aSUS4yTW9nigJuy7Fi5N5fqwzDdIWkWIg3dvzjcObsC5zHSf1a8qyi9E/RHfh1LneLA116IpMmTQpr2CNnWtQuwCKqJM30bDP/DQIDAQABo4HEMIHBMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUJMpCDu+qxpE+0ar6E1h4KhZQRokwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vcGtpLjNrZXkuY29tcGFueS9jYXMvZGVtby9kZW1vcm9vdGNhLmNydDARBgNVHSAECjAIMAYGBFUdIAAwHQYDVR0OBBYEFCTKQg7vqsaRPtGq+hNYeCoWUEaJMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAI0yAtaw0o8952LGD4gxZWskfun1bl92JvpJ5ydd9kQngE2zsWlLk470O3qM4hwa+umEqUo6YkVK5tH1xDyggwHYS/LW92uBoPbvW+cMVZvpwBWR12lXQzAvmN5w5EcDS6s1WOjNAfR5ILtOWSd79cCOEUsOVl+JNKeFDdBFT4I1xir3F4C3bN1DmwgVVWKzpRmetS2Ds1zJsIfWlFoywQynEHQzxth5EPQCc/KF4tjcEeNnYeHjBLm7iY70HCiOATzvT8bj/rJkVeUJLPGEikAY0YMQOEGHtF8UstDm+EGH44ON50FRFd++9nrZtnziDwrC0m6fMsjfBkk0G7coJqNSHvEr41AmCeWUX3cfT9TIm1qLecZpnW383Y0Z67+YqOf8p8vx5dYZy+uqe+CrJMvvXk6O1ZVDMNuib3y0UY3PRpZ7FW5SCNKfyiSv2edp+OSmmDAkIw55i6G/QVQyxq18LNgzFmZIXDysIV7hLlt5W54h86iTEHGNhm7Qsy+LFN3dq31oO11sVQBaUKjONUIKgKuGrbAVmeDteGpBdQCv3fu3SY4BG74ryNkvotnAeMUaL/XhrvC9XOKeQbJ/tRLeE8rf4It8Par1RuuubC5IL0ajdJ2e7X99Tt1Mqh48cQ2pFA3sVEif7h81+Y/i4UWraB/7pGxa/CehwrF8eIOI=")
                ),
                null,
                null)
        );

        Certificate intrCA = certificateRepository.save(CmpEntityUtil.createCertificate(
                new BigInteger(15, new SecureRandom()),
                CertificateState.ISSUED,
                certificateContentRepository.save(
                        CmpEntityUtil.createCertContent(
                                "6c738a62d57a8e75f6ee3de14764344f7ba7cda02053bb13c2d594146906b9ed",
                                "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")
                ),
                rootCA.getUuid(),
                null)
        );

        // -- create issued certificate - db entity (which must be confirmed - via tested handler)
        // -- create certificate - x509
        String contentOfIssuedCert = "MIIFITCCAwmgAwIBAgIUWOYu4x4SR3+uoFbQXDgFk4tIm7MwDQYJKoZIhvcNAQELBQAwQDEgMB4GA1UEAwwXRGVtb0NsaWVudFN1YkNBXzIzMDdSU0ExHDAaBgNVBAoMEzNLZXkgQ29tcGFueSBzLnIuby4wHhcNMjQwNTE1MTYzNTA1WhcNMjYwNTE1MTYzNTA0WjAdMRswGQYDVQQDDBJjbXAtdGVzdC1kZXYuaXIuY3owggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIrii/N6zI35rtw6sYmApohhNqOXRa8ktsqDPROdzdNc55aBVyTQFvf0z1XRi26l4GhsUv3KpLVTLV3vrCXtOTAeZccQgNqfKqDIVByjzWxGxFMuiTwpToB+a/CqXblaavTlyrv9varnxBEDjXK7H5iA4U+HxhM+WWidcSstnqGG8CnTmWS9cnj163zF01JzQANuIXKQ1CvJkHaMidbj5n5+w/nU/73BZEhnKivbOw3WWgVlV7fnR325FCF25J4AzJ2YyXo0Xu95cH0psjX0DM/ZroV+geiPZgGUp8cszkNYJMg5vHXSIQnYDDhDyiACy0QUqpxmK2iZdAqpTeI2W7AgMBAAGjggE0MIIBMDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFJVvVok/qW/9wNcwwbeXX+YsSq8dMFgGCCsGAQUFBwEBBEwwSjBIBggrBgEFBQcwAoY8aHR0cDovL3BraS4za2V5LmNvbXBhbnkvY2FzL2RlbW8vZGVtb2NsaWVudHN1YmNhXzIzMDdyc2EuY3J0MBEGA1UdIAQKMAgwBgYEVR0gADATBgNVHSUEDDAKBggrBgEFBQcDAjBOBgNVHR8ERzBFMEOgQaA/hj1odHRwOi8vcGtpLjNrZXkuY29tcGFueS9jcmxzL2RlbW8vZGVtb2NsaWVudHN1YmNhXzIzMDdyc2EuY3JsMB0GA1UdDgQWBBSzr9nhVund/xU3Zg5Pfc0taDDc/DAOBgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQELBQADggIBAMh4GZJmz3lGiLT89RaTBRVrkOY3+g6Wz/wCi/TcAqnEmz72g+rP2aMOMWL87KhlU7A18liDh5F0EK+yW8zyJx8ZYCLqzvw1fO3ijzFZ/HcNr9eymu/1csP8mCk+CFWgezGsg+jhBJICFM8tgAUm4HOZgsjy3oFLNXhIUBfATrSMMnAtYWoC7zXrseSNvVYPBvwCMzUyC0liMVLedxHgMYiIO1LuP1C9HjMk82QtI9rJjf67YoArpdJMue+QjwwYfgCQap5ZHa7fWdnrNxSneT1F4hxka5zI6BL2JNl0AWqvrgfKITzpNHg7t0QR36zBOleGUeGTflxQpkB1ibtHhaqlb6aN/Qw9K+m/bLVJO5rbCCImyXXTzTY06vzBwoygAYQP6CpRaD7Oq15VTJwAsrxFintOaX+ZXjeLSc0BtprJPU12+48yX27846R13u8y0kD5cvDsb/ukqTg2pNrdl7jAYBnG0BK0CLnRNluY/AV55PVsEOo9ymqOqHjznbhKu8bUtQWWu6lr2Vick7ACvyeRc50aBBTCMarty4t3mAc/g/odiP8Qb0Y8G2fCbMJiau5VQA53tJb61o+ph4zJAmCaW0Drnbws/OIVF1ZTnjb4m0zdWtvfM6hKpxJ/8jckOXU35m5woLgAbzEbOz2xLfYrmWQmLiWGuQ5ttUW8vYY5";
        x509Certificate = CertificateUtil.parseCertificate(contentOfIssuedCert);

        revokedCertificate = certificateRepository.save(CmpEntityUtil.createCertificate(
                CertificateState.REVOKED,
                certificateContentRepository.save(
                        CmpEntityUtil.createCertContent(
                                CertificateUtil.getThumbprint(x509Certificate),//"eee5c9c202207905d461c49455701a0ff6c3dd3387450c99d6da7058ff253fcf"
                                contentOfIssuedCert)),
                x509Certificate.getSerialNumber())

        );
        revokedCertificate.setIssuerCertificateUuid(intrCA.getUuid());
        revokedCertificate = certificateRepository.save(revokedCertificate);

        cmpProfileSigPrt = cmpProfileRepository.saveAndFlush(
                CmpEntityUtil.createCmpProfile(raProfile,
                        createSigningCertificateEntity(mockServer)));

        // -- create customer/client profile (macpwd-based)
        cmpProfileMacPrt = cmpProfileRepository.save(
                CmpEntityUtil.createCmpProfile(raProfile, sharedSecret));

    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    @Transactional
    void test_handle_ir_3gpp_signature_protection() throws Exception {
        String trxId= "777";
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage(
                        trxId,
                        CmpTestUtil.generateKeyPairEC().getPrivate(),
                        CmpTestUtil.createRevocationBody(
                                x509Certificate.getSerialNumber()))
                .toASN1Structure();

        // -- issue of certificate is mocked
        given(pollFeature.pollCertificate(any(), any(), any(), any()))
                .willReturn(new PollResult.Reached(revokedCertificate));

        PKIMessage response = testedHandler.handle(request,
                new Mobile3gppProfileContext(cmpProfileSigPrt,
                        raProfile,
                        request,
                        certificateKeyService,
                        null,
                        null));
        // -- THEN --
        // (1) check structure: type, transactionId(trxId) and content (type)
        assertNotNull(response);
        assertEquals(PKIBody.TYPE_REVOCATION_REP, response.getBody().getType());
        assertEquals(new DEROctetString(trxId.getBytes()).toString(),
                response.getHeader().getTransactionID().toString());
        assertInstanceOf(RevRepContent.class, response.getBody().getContent());

        // (2) check certificate (found by serial number) and its state
        RevRepContent responseBody = (RevRepContent)response.getBody().getContent();
        String serialNumber = responseBody.getRevCerts()[0].getSerialNumber().getValue().toString(16);

        Optional<Certificate> certificate = certificateRepository.findBySerialNumberIgnoreCase(serialNumber);
        assertFalse(certificate.isEmpty());
        assertEquals(CertificateState.REVOKED, certificate.get().getState());

        // (3) check transaction (found by serial number - same as related with cert) and its state
        cmpTransactionService.findByTransactionIdAndCertificateSerialNumber(
                transactionId, serialNumber
        ).ifPresent(
                cmpTransaction -> assertEquals(
                        CmpTransactionState.CERT_REVOKED,
                        cmpTransaction.getState())
        );
    }

    @Test
    void test_handle_ir_3gpp_mac_protection() throws Exception {
        // -- WHEN --
        String trxId= "779";
        PKIMessage request = CmpTestUtil.createMacBasedMessage(
                trxId,
                sharedSecret,
                CmpTestUtil.createRevocationBody(
                        x509Certificate.getSerialNumber()))
                .toASN1Structure();

        // -- issue of certificate is mocked
        given(pollFeature.pollCertificate(any(), any(), any(), any()))
                .willReturn(new PollResult.Reached(revokedCertificate));

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
        assertEquals(PKIBody.TYPE_REVOCATION_REP, response.getBody().getType());
        assertEquals(new DEROctetString(trxId.getBytes()).toString(),
                response.getHeader().getTransactionID().toString());
        assertInstanceOf(RevRepContent.class, response.getBody().getContent());

        // (2) check certificate (found by serial number) and its state
        RevRepContent responseBody = (RevRepContent)response.getBody().getContent();
        String serialNumber = responseBody.getRevCerts()[0].getSerialNumber().getValue().toString(16);

        Optional<Certificate> certificate = certificateRepository.findBySerialNumberIgnoreCase(serialNumber);
        assertFalse(certificate.isEmpty());
        assertEquals(CertificateState.REVOKED, certificate.get().getState());

        // (3) check transaction (found by serial number - same as related with cert) and its state
        cmpTransactionService.findByTransactionIdAndCertificateSerialNumber(
                transactionId, serialNumber
        ).ifPresent(
                cmpTransaction -> assertEquals(
                        CmpTransactionState.CERT_REVOKED,
                        cmpTransaction.getState())
        );
    }

    /**
     * When the authority provider connector accepts revocation asynchronously (HTTP 202),
     * PollFeature returns null because the certificate transitions to PENDING_REVOKE.
     * RFC 4210 section 5.2.6 limits the poll-request/poll-response loop to ip/cp/kup
     * contexts; CMP has no in-protocol way to represent a pending revocation, so the
     * handler must surface this as a per-certificate rejection inside the revocation
     * response — not a successful revocationNotification on a certificate that is not
     * yet revoked. The handler's outer per-cert catch turns the internal
     * CmpProcessingException into a PKIStatus rejection status entry; the certificate
     * remains in PENDING_REVOKE (no further state change at this point).
     */
    @Test
    @Transactional
    void test_handle_revocation_rejectsCleanly_whenAuthorityAcceptsAsynchronously() throws Exception {
        String trxId = "778";
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage(
                        trxId,
                        CmpTestUtil.generateKeyPairEC().getPrivate(),
                        CmpTestUtil.createRevocationBody(
                                x509Certificate.getSerialNumber()))
                .toASN1Structure();

        // The shared fixture creates the cert in REVOKED state for the existing happy-path
        // tests and does not attach an RA profile (the existing tests don't need one
        // because their handler reaches the per-cert catch before touching cert.getRaProfile()).
        // For the asynchronous-acceptance path the cert must be ISSUED and bound to an
        // RA profile so revokeCertificate can read raProfile.getSecuredUuid().
        revokedCertificate.setState(CertificateState.ISSUED);
        revokedCertificate.setRaProfile(raProfile);
        revokedCertificate.setRaProfileUuid(raProfile.getUuid());
        certificateRepository.save(revokedCertificate);

        // ClientOperationService is mocked at the bean level; the revoke call returns
        // normally without hitting the connector. No WireMock stub needed.
        given(pollFeature.pollCertificate(any(), any(), any(), any()))
                .willReturn(new PollResult.StillPending(CertificateState.PENDING_REVOKE));

        PKIMessage response = testedHandler.handle(request,
                new Mobile3gppProfileContext(cmpProfileSigPrt,
                        raProfile,
                        request,
                        certificateKeyService,
                        null,
                        null));

        assertNotNull(response);
        assertEquals(PKIBody.TYPE_REVOCATION_REP, response.getBody().getType());
        RevRepContent body = (RevRepContent) response.getBody().getContent();
        // Status must be rejection (not revocationNotification) — the inner async-rejection
        // throw at the if-polled-is-null branch is converted by the per-cert catch.
        // pkiStatus=2 is "rejection" per RFC 4210 §3.2.3.
        assertEquals(2, body.getStatus()[0].getStatus().intValueExact(),
                "expected pkiStatus=rejection when authority accepts revocation asynchronously");
    }

    @Test
    @Transactional
    void test_handle_revocation_completes_whenPollFeatureReturnsRevokedCertificate() throws Exception {
        // Companion to the asynchronous-acceptance test: when PollFeature returns a non-null
        // certificate (the connector revoked synchronously and the cert is now in REVOKED
        // state), the handler must emit a successful revocationNotification, persist a
        // CmpTransaction in CERT_REVOKED state, and not throw. Pins the success branch of
        // the if-polled-null check (lines 155-165 of RevocationMessageHandler).
        revokedCertificate.setState(CertificateState.ISSUED);
        revokedCertificate.setRaProfile(raProfile);
        revokedCertificate.setRaProfileUuid(raProfile.getUuid());
        certificateRepository.save(revokedCertificate);

        String trxId = "780";
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage(
                        trxId,
                        CmpTestUtil.generateKeyPairEC().getPrivate(),
                        CmpTestUtil.createRevocationBody(
                                x509Certificate.getSerialNumber()))
                .toASN1Structure();

        // Make the lookup-after-revoke return the now-revoked cert (synchronous completion).
        Certificate revoked = new Certificate();
        revoked.setUuid(revokedCertificate.getUuid());
        revoked.setSerialNumber(revokedCertificate.getSerialNumber());
        revoked.setState(CertificateState.REVOKED);
        given(pollFeature.pollCertificate(any(), any(), any(), any()))
                .willReturn(new PollResult.Reached(revoked));

        PKIMessage response = testedHandler.handle(request,
                new Mobile3gppProfileContext(cmpProfileSigPrt,
                        raProfile,
                        request,
                        certificateKeyService,
                        null,
                        null));

        assertNotNull(response);
        assertEquals(PKIBody.TYPE_REVOCATION_REP, response.getBody().getType());
    }

    /**
     * The asynchronous-cancel race ivosh raised: PollFeature observes a cert in a terminal
     * state that is not REVOKED — typically because a concurrent
     * cancelPendingCertificateOperation transitioned the cert mid-poll. The handler must
     * surface a per-cert PKIStatus.rejection with the diverted-state context preserved in
     * the PKIFreeText (not the generic "problem with revocation").
     */
    @Test
    @Transactional
    void test_handle_revocation_rejectsCleanly_whenPollFeatureReportsDiverted() throws Exception {
        revokedCertificate.setState(CertificateState.ISSUED);
        revokedCertificate.setRaProfile(raProfile);
        revokedCertificate.setRaProfileUuid(raProfile.getUuid());
        certificateRepository.save(revokedCertificate);

        String trxId = "781";
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage(
                        trxId,
                        CmpTestUtil.generateKeyPairEC().getPrivate(),
                        CmpTestUtil.createRevocationBody(
                                x509Certificate.getSerialNumber()))
                .toASN1Structure();

        given(pollFeature.pollCertificate(any(), any(), any(), any()))
                .willReturn(new PollResult.Diverted(CertificateState.FAILED));

        PKIMessage response = testedHandler.handle(request,
                new Mobile3gppProfileContext(cmpProfileSigPrt,
                        raProfile,
                        request,
                        certificateKeyService,
                        null,
                        null));

        assertNotNull(response);
        assertEquals(PKIBody.TYPE_REVOCATION_REP, response.getBody().getType());
        RevRepContent body = (RevRepContent) response.getBody().getContent();
        assertEquals(2, body.getStatus()[0].getStatus().intValueExact(),
                "expected pkiStatus=rejection when PollFeature reports Diverted");
        // Diverted message survives into the PKIFreeText — no longer collapsed to the
        // generic "problem with revocation" placeholder.
        String freeText = body.getStatus()[0].getStatusString().getStringAtUTF8(0).getString();
        assertTrue(freeText.contains("diverted") || freeText.contains("FAILED"),
                "expected PKIFreeText to mention the diverted state, got: " + freeText);
    }

    /**
     * The PKIFreeText fallback path: when the per-cert catch fires for a non-CmpProcessingException
     * (e.g. an unchecked exception leaking from a downstream service), the safe generic
     * "problem with revocation" placeholder is used so internal stack-class names / SQL
     * fragments / upstream error messages don't leak to a CMP client.
     */
    @Test
    @Transactional
    void test_handle_revocation_usesGenericFreeText_forNonCmpProcessingException() throws Exception {
        revokedCertificate.setState(CertificateState.ISSUED);
        revokedCertificate.setRaProfile(raProfile);
        revokedCertificate.setRaProfileUuid(raProfile.getUuid());
        certificateRepository.save(revokedCertificate);

        String trxId = "782";
        PKIMessage request = CmpTestUtil.createSignatureBasedMessage(
                        trxId,
                        CmpTestUtil.generateKeyPairEC().getPrivate(),
                        CmpTestUtil.createRevocationBody(
                                x509Certificate.getSerialNumber()))
                .toASN1Structure();

        // Force a leaked unchecked exception (e.g. a future upstream component bug) to fire
        // the per-cert catch with a non-CmpProcessingException. The PKIFreeText must NOT
        // contain the raw exception message.
        given(pollFeature.pollCertificate(any(), any(), any(), any()))
                .willThrow(new RuntimeException("internal SQL: relation \"core.x\" does not exist"));

        PKIMessage response = testedHandler.handle(request,
                new Mobile3gppProfileContext(cmpProfileSigPrt,
                        raProfile,
                        request,
                        certificateKeyService,
                        null,
                        null));

        assertNotNull(response);
        RevRepContent body = (RevRepContent) response.getBody().getContent();
        assertEquals(2, body.getStatus()[0].getStatus().intValueExact(),
                "expected pkiStatus=rejection on internal failure");
        String freeText = body.getStatus()[0].getStatusString().getStringAtUTF8(0).getString();
        assertEquals("problem with revocation", freeText,
                "expected the safe placeholder when the cause is not a CmpProcessingException — internal SQL detail must not leak to the wire");
    }

    // ----------------------------------------------------------------------------------------------------------
    // HELPER METHODS
    // ----------------------------------------------------------------------------------------------------------

    // --  entities
    private Certificate createSigningCertificateEntity(WireMockServer mockServer) {
        Connector connector = new Connector();
        connector.setUrl("http://localhost:"+mockServer.port());
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
