package com.otilm.core.integration.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObjectJSON;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.acme.Account;
import com.otilm.api.model.core.acme.AccountStatus;
import com.otilm.api.model.core.acme.Authorization;
import com.otilm.api.model.core.acme.AuthorizationStatus;
import com.otilm.api.model.core.acme.Challenge;
import com.otilm.api.model.core.acme.ChallengeStatus;
import com.otilm.api.model.core.acme.ChallengeType;
import com.otilm.api.model.core.acme.Directory;
import com.otilm.api.model.core.acme.Order;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.entity.acme.AcmeAuthorization;
import com.otilm.core.dao.entity.acme.AcmeChallenge;
import com.otilm.core.dao.entity.acme.AcmeNonce;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.acme.AcmeAccountRepository;
import com.otilm.core.dao.repository.acme.AcmeAuthorizationRepository;
import com.otilm.core.dao.repository.acme.AcmeChallengeRepository;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.acme.AcmeConstants;
import com.otilm.core.service.acme.AcmeExternalService;
import com.otilm.core.service.acme.ChallengeValidationResult;
import com.otilm.core.service.writer.AcmeChallengeWriter;
import com.otilm.core.util.AcmeCommonHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateTestUtil;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.InitialDirContext;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

class AcmeServiceITest extends BaseSpringBootTest {

    private static final String BASE_URI = "https://localhost:8443/api/acme/";
    private static final String RA_BASE_URI = BASE_URI + "raProfiles/";
    private static final String ACME_PROFILE_NAME = "testAcmeProfile1";
    private static final String RA_PROFILE_NAME = "testRaProfile1";
    private static final String ACME_PROFILE_NAME_2 = "testAcmeProfile2";
    private static final String RA_PROFILE_NAME_2 = "testRaProfile2";
    private static final String STALE_DNS_VALIDATION_TOKEN = "f5R9M-KeH3NR4Yqq8J2EUN2ZjkjLWAUxC9gnZgR9B_4";
    private static final String NONCE_HEADER_CUSTOM_PARAM = "nonce";
    private static final String URL_HEADER_CUSTOM_PARAM = "url";
    private static final String ACME_ACCOUNT_ID_VALID = "RMAl70zrRrs";
    private static final String ACME_ACCOUNT_ID_INVALID = "invalidAccountId";
    private static final String OTHER_ACCOUNT_ID = "otherAccount";
    private static final String AUTHORIZATION_ID_PENDING = "auth123";
    private static final String ORDER_ID_VALID = "order123";

    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AcmeNonceRepository acmeNonceRepository;

    @Autowired
    private AcmeAccountRepository acmeAccountRepository;

    @Autowired
    private AcmeProfileRepository acmeProfileRepository;

    @Autowired
    private AcmeOrderRepository acmeOrderRepository;

    @Autowired
    private AcmeAuthorizationRepository acmeAuthorizationRepository;

    @Autowired
    private AcmeChallengeWriter acmeChallengeWriter;

    @Autowired
    private AcmeChallengeRepository acmeChallengeRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateProtocolAssociationRepository certificateProtocolAssociationRepository;

    @Autowired
    private AcmeExternalService acmeService;

    private AcmeNonce acmeValidNonce;
    private JWSSigner rsa2048Signer;
    private RSAKey rsa2048PublicJWK;
    private JWSSigner newRsa2048Signer;
    private RSAKey newRsa2048PublicJWK;
    private String b64UrlCertificate;
    private String nonAcmeB64UrlCertificate;
    private Certificate certificate;
    private AcmeOrder order1;
    WireMockServer mockServer;

    @BeforeEach
    void setUp() throws JOSEException, NoSuchAlgorithmException, CertificateException, SignatureException,
            InvalidKeyException, NoSuchProviderException, OperatorCreationException {
        // prepare mock server
        mockServer = new WireMockServer(0);
        mockServer.start();

        mockAcmeRolePermissions();

        WireMock.configureFor("localhost", mockServer.port());

        mockServer
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching(
                                        "/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));

        mockServer
                .stubFor(WireMock
                        .get(WireMock
                                .urlPathMatching(
                                        "/v2/authorityProvider/authorities/[^/]+/certificates/revoke/attributes"))
                        .willReturn(WireMock.okJson("[]")));

        RSAKey rsa2048JWK = new RSAKeyGenerator(2048).generate();
        rsa2048PublicJWK = rsa2048JWK.toPublicJWK();
        rsa2048Signer = new RSASSASigner(rsa2048JWK);

        RSAKey newRsa2048JWK = new RSAKeyGenerator(2048).generate();
        newRsa2048PublicJWK = newRsa2048JWK.toPublicJWK();
        newRsa2048Signer = new RSASSASigner(newRsa2048JWK);

        KeyPair keyPair = rsa2048JWK.toKeyPair();
        X509Certificate x509Certificate = CertificateTestUtil.generateRandomX509Certificate(keyPair);
        String b64Certificate = Base64.getEncoder().encodeToString(x509Certificate.getEncoded());
        b64UrlCertificate = Base64.getUrlEncoder().encodeToString(x509Certificate.getEncoded());

        Connector connector = new Connector();
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setAuthorityInstanceUuid("1l");
        authorityInstanceReference.setConnector(connector);
        authorityInstanceReference = authorityInstanceReferenceRepository.save(authorityInstanceReference);

        RaProfile raProfile = new RaProfile();
        raProfile.setEnabled(true);
        raProfile.setName(RA_PROFILE_NAME);
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        raProfile = raProfileRepository.save(raProfile);

        RaProfile raProfile2 = new RaProfile();
        raProfile2.setEnabled(true);
        raProfile2.setName(RA_PROFILE_NAME_2);
        raProfile2.setAuthorityInstanceReference(authorityInstanceReference);
        raProfileRepository.save(raProfile2);

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent(b64Certificate);
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setCertificateContent(certificateContent);
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setRaProfile(raProfile);
        certificate = certificateRepository.save(certificate);

        certificateContent.setCertificate(certificate);
        certificateContentRepository.save(certificateContent);

        AcmeProfile acmeProfile = new AcmeProfile();
        acmeProfile.setRaProfile(raProfile);
        acmeProfile.setWebsite("sample website");
        acmeProfile.setTermsOfServiceUrl("sample terms");
        acmeProfile.setValidity(30);
        acmeProfile.setRetryInterval(30);
        acmeProfile.setDescription("sample description");
        acmeProfile.setName(ACME_PROFILE_NAME);
        acmeProfile.setDnsResolverPort("53");
        acmeProfile.setDnsResolverIp("localhost");
        acmeProfile.setTermsOfServiceChangeUrl("change url");
        acmeProfile.setEnabled(true);
        acmeProfile.setDisableNewOrders(false);
        acmeProfile.setRequireContact(true);
        acmeProfileRepository.save(acmeProfile);

        raProfile.setAcmeProfile(acmeProfile);
        raProfileRepository.save(raProfile);

        AcmeProfile acmeProfile2 = new AcmeProfile();
        acmeProfile2.setRaProfile(raProfile2);
        acmeProfile2.setWebsite("sample website");
        acmeProfile2.setTermsOfServiceUrl("sample terms");
        acmeProfile2.setValidity(30);
        acmeProfile2.setRetryInterval(30);
        acmeProfile2.setDescription("sample description");
        acmeProfile2.setName(ACME_PROFILE_NAME_2);
        acmeProfile2.setDnsResolverPort("53");
        acmeProfile2.setDnsResolverIp("localhost");
        acmeProfile2.setTermsOfServiceChangeUrl("change url");
        acmeProfile2.setEnabled(true);
        acmeProfile2.setDisableNewOrders(false);
        acmeProfile2.setRequireContact(true);
        acmeProfileRepository.save(acmeProfile2);

        raProfile2.setAcmeProfile(acmeProfile2);
        raProfileRepository.save(raProfile2);

        AcmeAccount acmeAccount = new AcmeAccount();
        acmeAccount.setStatus(AccountStatus.VALID);
        acmeAccount.setEnabled(true);
        acmeAccount.setAccountId(ACME_ACCOUNT_ID_VALID);
        acmeAccount.setTermsOfServiceAgreed(true);
        acmeAccount.setAcmeProfile(acmeProfile);
        acmeAccount.setRaProfile(raProfile);
        acmeAccount.setPublicKey(Base64.getEncoder().encodeToString(rsa2048JWK.toPublicKey().getEncoded()));
        acmeAccountRepository.save(acmeAccount);

        order1 = new AcmeOrder();
        order1.setOrderId(ORDER_ID_VALID);
        order1.setStatus(OrderStatus.VALID);
        order1.setAcmeAccount(acmeAccount);
        order1.setCertificateReference(certificate);
        order1.setCertificateReferenceUuid(certificate.getUuid());
        acmeOrderRepository.save(order1);

        AcmeAuthorization authorization1 = new AcmeAuthorization();
        authorization1.setAuthorizationId(AUTHORIZATION_ID_PENDING);
        authorization1.setStatus(AuthorizationStatus.PENDING);
        authorization1.setWildcard(false);
        authorization1.setOrderUuid(order1.getUuid());
        acmeAuthorizationRepository.save(authorization1);

        AcmeChallenge challenge2 = new AcmeChallenge();
        challenge2.setChallengeId("challenge123");
        challenge2.setStatus(ChallengeStatus.VALID);
        challenge2.setType(ChallengeType.HTTP01);
        challenge2.setToken("122324");
        challenge2.setAuthorizationUuid(authorization1.getUuid());
        acmeChallengeRepository.save(challenge2);

        Date expires = AcmeCommonHelper.addSeconds(new Date(), AcmeConstants.NONCE_VALIDITY);
        acmeValidNonce = new AcmeNonce();
        acmeValidNonce.setNonce("5pSv1vR6SEJryGlA0JRns6e376ZGjUt-CYxmqvwBEaY");
        acmeValidNonce.setCreated(new Date());
        acmeValidNonce.setExpires(expires);
        acmeNonceRepository.save(acmeValidNonce);

        // associate certificate with ACME protocol association
        CertificateProtocolAssociation certificateProtocolAssociation = new CertificateProtocolAssociation();
        certificateProtocolAssociation.setCertificate(certificate);
        certificateProtocolAssociation.setProtocol(CertificateProtocol.ACME);
        certificateProtocolAssociation.setProtocolProfileUuid(acmeProfile.getUuid());
        certificateProtocolAssociation.setAdditionalProtocolUuid(acmeAccount.getUuid());
        certificateProtocolAssociationRepository.save(certificateProtocolAssociation);

        certificate.setProtocolAssociation(certificateProtocolAssociation);
        certificateRepository.save(certificate);

        // create certificate without ACME protocol association
        X509Certificate nonAcmeX509Certificate = CertificateTestUtil.generateRandomX509Certificate(keyPair);
        String nonAcmeB64Certificate = Base64.getEncoder().encodeToString(nonAcmeX509Certificate.getEncoded());
        nonAcmeB64UrlCertificate = Base64.getUrlEncoder().encodeToString(nonAcmeX509Certificate.getEncoded());

        CertificateContent nonAcmeCertificateContent = new CertificateContent();
        nonAcmeCertificateContent.setContent(nonAcmeB64Certificate);
        nonAcmeCertificateContent = certificateContentRepository.save(nonAcmeCertificateContent);

        Certificate nonAcmeCertificate = new Certificate();
        nonAcmeCertificate.setCertificateContent(nonAcmeCertificateContent);
        nonAcmeCertificate.setState(CertificateState.ISSUED);
        nonAcmeCertificate.setValidationStatus(CertificateValidationStatus.VALID);
        nonAcmeCertificate.setRaProfile(raProfile);
        nonAcmeCertificate = certificateRepository.save(nonAcmeCertificate);

        nonAcmeCertificateContent.setCertificate(nonAcmeCertificate);
        certificateContentRepository.save(nonAcmeCertificateContent);
    }

    private void mockAcmeRolePermissions() {
        OpaResourceAccessResult resourceAccessAllowed = new OpaResourceAccessResult(true,
                List.of("AllResourcesAllowed"));
        OpaResourceAccessResult resourceAccessNotAllowed = new OpaResourceAccessResult(false, List.of());

        // By default, reject all
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenReturn(resourceAccessNotAllowed);

        // allow all ACME account actions
        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> req != null && req.getProperties().containsKey(Resource.ACME_ACCOUNT.getCode())),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        // allow all ACME Profile detail and list
        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.ACME_PROFILE, ResourceAction.LIST)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.ACME_PROFILE, ResourceAction.DETAIL)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        // Allow attribute members
        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.ATTRIBUTE, ResourceAction.MEMBERS)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        // Allow authorities detail, list and members
        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.AUTHORITY, ResourceAction.LIST)), any(),
                        any()))
                .thenReturn(resourceAccessAllowed);

        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.AUTHORITY, ResourceAction.DETAIL)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.AUTHORITY, ResourceAction.MEMBERS)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        // Allow certificates create, detail, issue, list, renew, revoke, update
        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.CERTIFICATE, ResourceAction.LIST)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.CERTIFICATE, ResourceAction.CREATE)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.CERTIFICATE, ResourceAction.DETAIL)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.CERTIFICATE, ResourceAction.RENEW)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.CERTIFICATE, ResourceAction.REVOKE)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.CERTIFICATE, ResourceAction.UPDATE)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        // Allow RA Profiles detail, list and members
        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.RA_PROFILE, ResourceAction.LIST)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.RA_PROFILE, ResourceAction.DETAIL)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

        when(opaClient
                .checkResourceAccess(any(),
                        argThat(req -> isRequestForResourceAction(req, Resource.RA_PROFILE, ResourceAction.MEMBERS)),
                        any(), any()))
                .thenReturn(resourceAccessAllowed);

    }

    private static boolean isRequestForResourceAction(OpaRequestedResource requestedResource, Resource resource,
            ResourceAction resourceAction) {
        return requestedResource != null && requestedResource.getProperties() != null
                && (requestedResource.getProperties().containsKey("name")
                        && requestedResource.getProperties().get("name").equals(resource.getCode()))
                && (requestedResource.getProperties().containsKey("action")
                        && requestedResource.getProperties().get("action").equals(resourceAction.getCode()));
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void testGetDirectory() throws AcmeProblemDocumentException, NotFoundException {
        URI requestUri = URI.create(BASE_URI + ACME_PROFILE_NAME + "/directory");
        ResponseEntity<Directory> directory = acmeService.getDirectory(ACME_PROFILE_NAME, requestUri, false);
        assertGetDirectory(directory);
    }

    @Test
    void testGetDirectory_raProfileBased() throws AcmeProblemDocumentException, NotFoundException {
        URI requestUri = URI.create(RA_BASE_URI + RA_PROFILE_NAME + "/directory");
        ResponseEntity<Directory> directory = acmeService.getDirectory(RA_PROFILE_NAME, requestUri, true);
        assertGetDirectory(directory);
    }

    private void assertGetDirectory(ResponseEntity<Directory> response) {
        Assertions.assertNotNull(response);
        // status code is 200
        Assertions.assertEquals(200, response.getStatusCode().value());

        Assertions.assertTrue(Objects.requireNonNull(response.getBody()).getNewOrder().endsWith("/new-order"));
        Assertions.assertTrue(response.getBody().getKeyChange().endsWith("/key-change"));
        Assertions.assertTrue(response.getBody().getNewAccount().endsWith("/new-account"));
        Assertions.assertTrue(response.getBody().getNewNonce().endsWith("/new-nonce"));
        Assertions.assertTrue(response.getBody().getRevokeCert().endsWith("/revoke-cert"));
    }

    @Test
    void testGetNonce() {
        URI requestUri = URI.create(BASE_URI + ACME_PROFILE_NAME + "/new-nonce");
        ResponseEntity<?> response = acmeService.getNonce(ACME_PROFILE_NAME, true, requestUri, false);
        assertGetNonce(response);
    }

    @Test
    void testGetNonce_raProfileBased() {
        URI requestUri = URI.create(RA_BASE_URI + RA_PROFILE_NAME + "/new-nonce");
        ResponseEntity<?> response = acmeService.getNonce(RA_PROFILE_NAME, true, requestUri, true);
        assertGetNonce(response);
    }

    private void assertGetNonce(ResponseEntity<?> response) {
        // status code is 200
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        // Nonce header is present
        Assertions.assertNotNull(response.getHeaders().get(AcmeConstants.NONCE_HEADER_NAME));
    }

    @Test
    void testNewAccount_acmeProfileBased_withExistingKey()
            throws AcmeProblemDocumentException, NotFoundException, URISyntaxException, JOSEException {
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME + "/new-account");
        ResponseEntity<Account> account = acmeService
                .newAccount(ACME_PROFILE_NAME, buildNewAccountRequestJSON_withExistingKey(requestUri), requestUri,
                        false);
        assertNewAccount(account);
    }

    @Test
    void testNewAccount_raProfileBased_withExistingKey()
            throws AcmeProblemDocumentException, NotFoundException, URISyntaxException, JOSEException {
        URI requestUri = new URI(RA_BASE_URI + RA_PROFILE_NAME + "/new-account");
        ResponseEntity<Account> account = acmeService
                .newAccount(RA_PROFILE_NAME, buildNewAccountRequestJSON_withExistingKey(requestUri), requestUri, true);
        assertNewAccount(account);
    }

    @Test
    void testNewAccount_acmeProfileBased_withNewKey()
            throws AcmeProblemDocumentException, NotFoundException, URISyntaxException, JOSEException {
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME + "/new-account");
        ResponseEntity<Account> account = acmeService
                .newAccount(ACME_PROFILE_NAME, buildNewAccountRequestJSON_withNewKey(requestUri), requestUri, false);
        assertNewAccount(account);
    }

    @Test
    void testNewAccount_raProfileBased_withNewKey()
            throws AcmeProblemDocumentException, NotFoundException, URISyntaxException, JOSEException {
        URI requestUri = new URI(RA_BASE_URI + RA_PROFILE_NAME + "/new-account");
        ResponseEntity<Account> account = acmeService
                .newAccount(RA_PROFILE_NAME, buildNewAccountRequestJSON_withNewKey(requestUri), requestUri, true);
        assertNewAccount(account);
    }

    private String buildNewAccountRequestJSON_withExistingKey(URI requestUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload(
                "{\"contact\":[\"mailto:test.test@test\"],\"termsOfServiceAgreed\":true, \"status\": \"deactivated\"}"));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .jwk(rsa2048PublicJWK)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    private String buildNewAccountRequestJSON_withNewKey(URI requestUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload(
                "{\"contact\":[\"mailto:test.test@test\"],\"termsOfServiceAgreed\":true, \"status\": \"deactivated\"}"));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .jwk(newRsa2048PublicJWK)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), newRsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    private void assertNewAccount(ResponseEntity<Account> account) {
        // status code is 200
        Assertions.assertEquals(HttpStatus.CREATED, account.getStatusCode());

        Assertions.assertNotNull(account);
        Assertions.assertNotNull(account.getHeaders().getLocation());
        Assertions.assertEquals(AccountStatus.VALID, Objects.requireNonNull(account.getBody()).getStatus());
    }

    @Test
    void testNewAccount_fail() throws URISyntaxException {
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME + "/new-account");
        Assertions
                .assertThrows(AcmeProblemDocumentException.class, () -> acmeService
                        .newAccount(ACME_PROFILE_NAME, buildNewAccountRequestJSON_fail(), requestUri, false));
    }

    @Test
    void testNewAccount_fail_raProfileBased() throws URISyntaxException {
        URI requestUri = new URI(RA_BASE_URI + RA_PROFILE_NAME + "/new-account");
        Assertions
                .assertThrows(AcmeProblemDocumentException.class, () -> acmeService
                        .newAccount(RA_PROFILE_NAME, buildNewAccountRequestJSON_fail(), requestUri, true));
    }

    private String buildNewAccountRequestJSON_fail() throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload("dfgdrtyufghgjghktyfghdtu"));
        jwsObjectJSON.sign(new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(rsa2048PublicJWK).build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    @Test
    void testOnlyReturnExistingAccount()
            throws URISyntaxException, JOSEException, AcmeProblemDocumentException, NotFoundException {
        URI requestUri = new URI(RA_BASE_URI + RA_PROFILE_NAME + "/new-account");
        ResponseEntity<Account> account = acmeService
                .newAccount(RA_PROFILE_NAME, buildOnlyReturnExistingAccountJSON(requestUri), requestUri, true);
        Assertions.assertEquals(HttpStatus.OK, account.getStatusCode());
        Assertions.assertNotNull(account);
        Assertions.assertEquals(AccountStatus.VALID, Objects.requireNonNull(account.getBody()).getStatus());
    }

    private String buildOnlyReturnExistingAccountJSON(URI requestUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload("{\"onlyReturnExisting\":true}"));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .jwk(rsa2048PublicJWK)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    @Test
    void testOnlyReturnExistingAccount_fail() throws URISyntaxException {
        URI requestUri = new URI(RA_BASE_URI + RA_PROFILE_NAME + "/new-account");
        Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .newAccount(RA_PROFILE_NAME, buildOnlyReturnExistingAccountJSON_fail(requestUri),
                                        requestUri, true));
    }

    private String buildOnlyReturnExistingAccountJSON_fail(URI requestUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload("{\"onlyReturnExisting\":true}"));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .jwk(newRsa2048PublicJWK)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), newRsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    @Test
    void testNewAccountOnExisting_wrongConfiguration() throws URISyntaxException {
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME_2 + "/new-account");
        Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .newAccount(ACME_PROFILE_NAME_2, buildNewAccountRequestJSON_withExistingKey(requestUri),
                                        requestUri, false));
    }

    @Test
    void testNewAccountOnExisting_wrongConfiguration_raProfileBased() throws URISyntaxException {
        URI requestUri = new URI(RA_BASE_URI + RA_PROFILE_NAME_2 + "/new-account");
        Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .newAccount(RA_PROFILE_NAME_2, buildNewAccountRequestJSON_withExistingKey(requestUri),
                                        requestUri, true));
    }

    @Test
    void testNewOrder() throws JOSEException, URISyntaxException, AcmeProblemDocumentException, NotFoundException {
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME + "/new-order");
        ResponseEntity<Order> order = acmeService
                .newOrder(ACME_PROFILE_NAME, buildNewOrderRequestJSON(requestUri, BASE_URI + ACME_PROFILE_NAME),
                        requestUri, false);
        assertNewOrder(order);
    }

    @Test
    void testNewOrder_raProfileBased()
            throws JOSEException, URISyntaxException, AcmeProblemDocumentException, NotFoundException {
        URI requestUri = new URI(RA_BASE_URI + RA_PROFILE_NAME + "/new-order");
        ResponseEntity<Order> order = acmeService
                .newOrder(RA_PROFILE_NAME, buildNewOrderRequestJSON(requestUri, RA_BASE_URI + RA_PROFILE_NAME),
                        requestUri, true);
        assertNewOrder(order);
    }

    private String buildNewOrderRequestJSON(URI requestUri, String baseUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(
                new Payload("{\"identifiers\":[{\"type\":\"dns\",\"value\":\"debian10.acme.local\"}]}"));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(baseUri + "/acct/" + ACME_ACCOUNT_ID_VALID)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    private void assertNewOrder(ResponseEntity<Order> order) {
        // status code is 201
        Assertions.assertEquals(HttpStatus.CREATED, order.getStatusCode());

        Assertions.assertNotNull(order.getBody());
        Assertions.assertEquals(OrderStatus.PENDING, order.getBody().getStatus());
        Assertions.assertEquals(1, order.getBody().getAuthorizations().size());
    }

    @Test
    void testNewOrder_Fail() throws URISyntaxException {
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME + "/new-order");
        Assertions
                .assertThrows(AcmeProblemDocumentException.class, () -> acmeService
                        .newOrder(ACME_PROFILE_NAME, buildNewOrderRequestJSON_fail(), requestUri, false));
    }

    @Test
    void testNewOrder_fail_raProfileBased() throws URISyntaxException {
        URI requestUri = new URI(RA_BASE_URI + RA_PROFILE_NAME + "/new-order");
        Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService.newOrder(RA_PROFILE_NAME, buildNewOrderRequestJSON_fail(), requestUri, true));
    }

    private String buildNewOrderRequestJSON_fail() throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload("dfgdrtyufghgjghktyfghdtu"));
        jwsObjectJSON.sign(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    @Test
    void testGetAuthorization()
            throws AcmeProblemDocumentException, NotFoundException, URISyntaxException, JOSEException {
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/authz/" + AUTHORIZATION_ID_PENDING);
        ResponseEntity<Authorization> authorization = acmeService
                .getAuthorization(ACME_PROFILE_NAME, AUTHORIZATION_ID_PENDING,
                        buildGetAuthorizationRequestJSON(requestUri, baseUri), requestUri, false);
        assertGetAuthorization(authorization);
    }

    @Test
    void testGetAuthorization_raProfileBased()
            throws AcmeProblemDocumentException, NotFoundException, URISyntaxException, JOSEException {
        String baseUri = RA_BASE_URI + RA_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/authz/" + AUTHORIZATION_ID_PENDING);
        ResponseEntity<Authorization> authorization = acmeService
                .getAuthorization(RA_PROFILE_NAME, AUTHORIZATION_ID_PENDING,
                        buildGetAuthorizationRequestJSON(requestUri, baseUri), requestUri, true);
        assertGetAuthorization(authorization);
    }

    private String buildGetAuthorizationRequestJSON(URI requestUri, String baseUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload(""));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(baseUri + "/acct/" + ACME_ACCOUNT_ID_VALID)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    private void assertGetAuthorization(ResponseEntity<Authorization> authorization) {
        // status code is 200
        Assertions.assertEquals(HttpStatus.OK, authorization.getStatusCode());

        Assertions.assertNotNull(authorization);
        Assertions.assertEquals(1, Objects.requireNonNull(authorization.getBody()).getChallenges().size());
        // is pending
        Assertions.assertEquals(AuthorizationStatus.PENDING, authorization.getBody().getStatus());
    }

    @Test
    void testFinalize() throws URISyntaxException, ConnectorException, CertificateException, AlreadyExistException,
            JOSEException, AcmeProblemDocumentException, JsonProcessingException {
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/order/" + ORDER_ID_VALID + "/finalize");
        certificate.setState(CertificateState.FAILED);
        certificateRepository.save(certificate);
        order1.setStatus(OrderStatus.PENDING);
        acmeOrderRepository.save(order1);
        Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .finalizeOrder(ACME_PROFILE_NAME, ORDER_ID_VALID,
                                        buildFinalizeRequestJSON(requestUri, baseUri), requestUri, false));
        AcmeAccount acmeAccount = acmeAccountRepository.findByUuid(order1.getAcmeAccountUuid()).orElseThrow();
        Assertions.assertEquals(1, acmeAccount.getFailedOrders());
        certificate.setState(CertificateState.ISSUED);
        certificateRepository.save(certificate);
        order1.setStatus(OrderStatus.PENDING);
        acmeOrderRepository.save(order1);
        Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .finalizeOrder(ACME_PROFILE_NAME, ORDER_ID_VALID,
                                        buildFinalizeRequestJSON(requestUri, baseUri), requestUri, false));
        acmeAccount = acmeAccountRepository.findByUuid(order1.getAcmeAccountUuid()).orElseThrow();
        Assertions.assertEquals(1, acmeAccount.getValidOrders());

        order1.setCertificateReference(null);
        order1.setCertificateReferenceUuid(null);
        order1.setStatus(OrderStatus.READY);
        acmeOrderRepository.save(order1);
        acmeService
                .finalizeOrder(ACME_PROFILE_NAME, ORDER_ID_VALID, buildFinalizeRequestJSON(requestUri, baseUri),
                        requestUri, false);
        acmeAccount = acmeAccountRepository.findByUuid(order1.getAcmeAccountUuid()).orElseThrow();
        Assertions.assertEquals(2, acmeAccount.getFailedOrders());

        mockServer
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching(
                                        "/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate"))
                        .willReturn(WireMock.okJson("true")));
        mockServer
                .stubFor(WireMock
                        .get(WireMock
                                .urlPathMatching(
                                        "/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        order1.setCertificateReference(null);
        order1.setCertificateReferenceUuid(null);
        order1.setStatus(OrderStatus.READY);
        acmeOrderRepository.save(order1);
        acmeService
                .finalizeOrder(ACME_PROFILE_NAME, ORDER_ID_VALID, buildFinalizeRequestJSON(requestUri, baseUri),
                        requestUri, false);
        acmeAccount = acmeAccountRepository.findByUuid(order1.getAcmeAccountUuid()).orElseThrow();
        Assertions.assertEquals(2, acmeAccount.getFailedOrders());
    }

    @Test
    void testFinalize_raProfileBased() throws URISyntaxException {
        String baseUri = RA_BASE_URI + RA_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/order/" + ORDER_ID_VALID + "/finalize");
        Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .finalizeOrder(RA_PROFILE_NAME, ORDER_ID_VALID,
                                        buildFinalizeRequestJSON(requestUri, baseUri), requestUri, true));
    }

    private String buildFinalizeRequestJSON(URI requestUri, String baseUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload(
                "{\"csr\":\"MIICdjCCAV4CAQIwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALeJvx7JWbwzobWL74KyHz0FjPqt0R5iOaOxiYqpfMY-ZVhMBkS0FqnCBQzMn5BkHukdx7HsIMkJ-sM01HVHJaRpgpf1zeTyRQjY7ESDikRL_1Ekxi6Sgf5unzB35aP2EBxiAaomG610HjpqSfGtOzEf12hy4jkcC446TT8nE9dm6CBf7XAoq9vXxXRjnAgdkr62yIzanXedDwdcNyk5EiiRWQXwW-L5Pex5808ip2gmE5Al5SPUiv8eDCq02QVDJ8Ln4UPYkxL1b6RMlfEgKLsGEZX0e-FC0w_fiBN48zrvHxqM2fdU7Ae8pRDwUOClYOxDkrvDv60RGikLlQZ45FcCAwEAAaAxMC8GCSqGSIb3DQEJDjEiMCAwHgYDVR0RBBcwFYITZGViaWFuMTAuYWNtZS5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAHlO0ZuPuYEtplU0gEUj88Yi1MWkrElx0JoTk7qonRsufu_Y2P_u-RrkWOzM3VJ08lNz90L_mnc8NOONMl_WlYWBywbUMsGar4Y_1x0ySOEdp5fg87rxY1b2jbSL7tPe4OV7yAebdCEzzXXBi3Ay9NoJAhwNONjyRp92vqT5-MWMXQyZvdcUMM38l6aNc9jof3EluNbgO7nWSle6MQJJvlEYwXx7ZPvvgxMfrRa-Yc_aWS7w25MSAODKKwvIivGn5q_owfd5AozYp0pymiLLbvAWhYVWL_-bGvJ13xpyfNPnGJIdwcY8zgikYPyBfbRmPyKJLPI4QnWz8GsWGiaUgjA\"}"));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(baseUri + "/acct/" + ACME_ACCOUNT_ID_VALID)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    @Test
    void testRevokeCert_fail() throws URISyntaxException, JOSEException {
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/revoke-cert");
        var requestJson = buildRevokeCertRequestJSON_fail(requestUri, baseUri);
        Assertions
                .assertThrows(NullPointerException.class,
                        () -> acmeService.revokeCertificate(ACME_PROFILE_NAME, requestJson, requestUri, false));

    }

    @Test
    void testRevokeCert_fail_raProfileBased() throws URISyntaxException, JOSEException {
        String baseUri = RA_BASE_URI + RA_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/revoke-cert");
        var requestJson = buildRevokeCertRequestJSON_fail(requestUri, baseUri);
        Assertions
                .assertThrows(NullPointerException.class,
                        () -> acmeService.revokeCertificate(RA_PROFILE_NAME, requestJson, requestUri, true));

    }

    @Test
    void testRevokeCert_fail_archivedCertificate() throws URISyntaxException {
        String baseUri = RA_BASE_URI + RA_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/revoke-cert");
        certificate.setArchived(true);
        certificateRepository.save(certificate);
        Assertions
                .assertThrows(AcmeProblemDocumentException.class, () -> acmeService
                        .revokeCertificate(ACME_PROFILE_NAME,
                                buildRevokeCertRequestJSON_withAccountKey(requestUri, baseUri, b64UrlCertificate),
                                requestUri, false));
    }

    private String buildRevokeCertRequestJSON_fail(URI requestUri, String baseUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload(
                "{\"certificate\":\"MIIFOzCCAyOgAwIBAgITGAAAA4HCMidgplmlrQAAAAADgTANBgkqhkiG9w0BAQ0FADA3MRcwFQYDVQQDDA5EZW1vIE1TIFN1YiBDQTEcMBoGA1UECgwTM0tleSBDb21wYW55IHMuci5vLjAeFw0yNDAzMTIxMTI3MDBaFw0yNjAzMTIxMTI3MDBaMBgxFjAUBgNVBAMTDXRmdC4za2V5LnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgoHj1WO_sXoqfcr7pm5KUjsAnmdjgzBbFwHCAvlDwsF8Z6B6i77AB-xLIUdcVLPu417mApEbH9Nu9jvcO_b2QEh_tDAczbug6SVMwgl7va3H5qGwg_0qepRHNWAMt1TWgY-rFZbUn1WLSO97armFjVPKK-AeuBVz4EQIqS1vxLLg0MxajR19euvkLBjbjYtjp7pwgHT2jMsccJ06bGN3Ik7wTZMnObfwxhhmwApEjyeDevVywopULc9zarvOSgFTnejlfOmwUBnnHlp8Xpq7P_izt1AhJkij9eElzSXnZUHAFQoQh3fQ6yelXFBxDOEAao8o3FR-R6Ss3kZ3mxkbjAgMBAAGjggFdMIIBWTAnBgNVHREEIDAegg10ZnQuM2tleS50ZXN0gg13d3cuM2tleS50ZXN0MB0GA1UdDgQWBBSA81KtARou26mp921nppmTGjC6BTAfBgNVHSMEGDAWgBSSwrzfVcXBk4VJB_esyR0LaAEHUTBNBgNVHR8ERjBEMEKgQKA-hjxodHRwOi8vbGFiMDIuM2tleS5jb21wYW55L2NybHMvZGVtby9EZW1vJTIwTVMlMjBTdWIlMjBDQS5jcmwwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vbGFiMDIuM2tleS5jb21wYW55L2Nhcy9kZW1vL0RlbW8lMjBNUyUyMFN1YiUyMENBLmNydDAhBgkrBgEEAYI3FAIEFB4SAFcAZQBiAFMAZQByAHYAZQByMA4GA1UdDwEB_wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQ0FAAOCAgEAb_N3sf9Kda5t_jsL_VQYW0OPiHD0V1QcwqiyplvclD7NahnV7QiUwS7V-QmHHD1V2_xkYNhlgkinu1SWbpJ8gAcLDbADfnMkaOZNr6dvKiDGw0Xppmfbha1Bbb3JA_DOHFrXBm3795mQDgaRuvPke0qyyL1DP9xAdxubQaYQDZA9WAYNztgVe3V4zngwzI6P6BiDQ7CgZLNv_e8e5ME4_MCeO0cUFxt7mzKIhH54wL4yY8DJ3LHVWXsMPntRMdvYWjYf-1Ivb5x2WvuU_SPcnCSyEj0qdcLlm9BWxbfM-5h4gXWvsCjG2anGLtsl5Ut3Sz1vvoM49N981pZEZDlNFlsBgYCF-MDKZwBOiX8uTgQkv5bqA7_tPvIgQI_JTbSYeqRtb4J6SH1_uRrhyU7w88PlSmZwkf5S5ZxX9eqjSEFENB7ARh4KaiHyYqTfYxAP6-EFs9dxBTQ5eQu2jFXy4xJG4g-r1KZujv6wgPoDZsbbqTfBg27_sQsTyzZqI1vL5UrCqxDSo-Pw9JPITYi8AdOffT0hkgQ7RmLHb6HYV7JqABmhZ3G9QQfuk2W7_o6l6jnpZM7pHEkZ30s54cIHgYG3JifXd2m6uxU6iX48mJy_VUZcVikxSbCg5eLlvq_HWnxk2DE_9PWjA_YxZs2Jtqpi2FtLCli2cykGGumhhJ0\",\"reason\":8}"));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(baseUri + "/acct/" + ACME_ACCOUNT_ID_VALID)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    @Test
    void testRevokeCert_withAccountKey() throws URISyntaxException, JOSEException, AcmeProblemDocumentException,
            ConnectorException, CertificateException {
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/revoke-cert");
        ResponseEntity<?> response = acmeService
                .revokeCertificate(ACME_PROFILE_NAME,
                        buildRevokeCertRequestJSON_withAccountKey(requestUri, baseUri, b64UrlCertificate), requestUri,
                        false);
        assertRevokeCert_withAccountKey(response);
    }

    @Test
    void testRevokeCert_withAccountKey_raProfileBased() throws URISyntaxException, JOSEException,
            AcmeProblemDocumentException, ConnectorException, CertificateException {
        String baseUri = RA_BASE_URI + RA_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/revoke-cert");
        ResponseEntity<?> response = acmeService
                .revokeCertificate(RA_PROFILE_NAME,
                        buildRevokeCertRequestJSON_withAccountKey(requestUri, baseUri, b64UrlCertificate), requestUri,
                        true);
        assertRevokeCert_withAccountKey(response);
    }

    @Test
    void testRevokeCert_withAccountKey_nonAcmeCertificate() throws URISyntaxException {
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/revoke-cert");
        AcmeProblemDocumentException thrown = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .revokeCertificate(ACME_PROFILE_NAME, buildRevokeCertRequestJSON_withAccountKey(
                                        requestUri, baseUri, nonAcmeB64UrlCertificate), requestUri, false));
        Assertions.assertEquals(thrown.getHttpStatusCode(), HttpStatus.FORBIDDEN.value());
    }

    @Test
    void testRevokeCert_withAccountKey_nonAcmeCertificate_raProfileBased() throws URISyntaxException {
        String baseUri = RA_BASE_URI + RA_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/revoke-cert");
        AcmeProblemDocumentException thrown = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .revokeCertificate(RA_PROFILE_NAME, buildRevokeCertRequestJSON_withAccountKey(
                                        requestUri, baseUri, nonAcmeB64UrlCertificate), requestUri, true));
        Assertions.assertEquals(thrown.getHttpStatusCode(), HttpStatus.FORBIDDEN.value());
    }

    @Test
    void testUpdateAccount() throws URISyntaxException, JOSEException, AcmeProblemDocumentException, NotFoundException {
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/update");
        acmeService
                .updateAccount(ACME_PROFILE_NAME, ACME_ACCOUNT_ID_VALID,
                        buildNewAccountRequestJSON_withExistingKey(requestUri), requestUri, false);
        AcmeAccount acmeAccount = acmeAccountRepository.findByAccountId(ACME_ACCOUNT_ID_VALID).orElseThrow();
        Assertions.assertEquals(1, acmeAccount.getFailedOrders());
    }

    private String buildRevokeCertRequestJSON_withAccountKey(URI requestUri, String baseUri, String certificate)
            throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(
                new Payload("{\"certificate\":\"" + certificate + "\",\"reason\":0}"));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(baseUri + "/acct/" + ACME_ACCOUNT_ID_VALID)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    private void assertRevokeCert_withAccountKey(ResponseEntity<?> response) {
        // status code is 200
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    public void testRevokeCert_withPrivateKey() throws URISyntaxException, JOSEException, AcmeProblemDocumentException,
            ConnectorException, CertificateException {
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME + "/revoke-cert");
        ResponseEntity<?> response = acmeService
                .revokeCertificate(ACME_PROFILE_NAME, buildRevokeCertRequestJSON_withPrivateKey(requestUri), requestUri,
                        false);
        assertRevokeCert_withPrivateKey(response);
    }

    @Test
    void testRevokeCert_withPrivateKey_raProfileBased() throws URISyntaxException, JOSEException,
            AcmeProblemDocumentException, ConnectorException, CertificateException {
        URI requestUri = new URI(RA_BASE_URI + RA_PROFILE_NAME + "/revoke-cert");
        ResponseEntity<?> response = acmeService
                .revokeCertificate(RA_PROFILE_NAME, buildRevokeCertRequestJSON_withPrivateKey(requestUri), requestUri,
                        true);
        assertRevokeCert_withPrivateKey(response);
    }

    private String buildRevokeCertRequestJSON_withPrivateKey(URI requestUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(
                new Payload("{\"certificate\":\"" + b64UrlCertificate + "\",\"reason\":0}"));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .jwk(rsa2048PublicJWK)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    private void assertRevokeCert_withPrivateKey(ResponseEntity<?> response) {
        // status code is 200
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    void testGetOrderList() throws AcmeProblemDocumentException, NotFoundException {
        URI requestUri = URI.create(BASE_URI + ACME_PROFILE_NAME + "/orders/" + ACME_ACCOUNT_ID_VALID);
        ResponseEntity<List<Order>> orders = acmeService
                .listOrders(ACME_PROFILE_NAME, ACME_ACCOUNT_ID_VALID, requestUri, false);
        assertGetOrderList(orders);
        order1.setStatus(OrderStatus.READY);
        order1.setExpires(Date.from(Instant.now().minus(1, ChronoUnit.DAYS)));
        acmeOrderRepository.save(order1);
        acmeService.listOrders(ACME_PROFILE_NAME, ACME_ACCOUNT_ID_VALID, requestUri, false);
        AcmeAccount acmeAccount = acmeAccountRepository.findByUuid(order1.getAcmeAccountUuid()).orElseThrow();
        Assertions.assertEquals(1, acmeAccount.getFailedOrders());
    }

    @Test
    void testGetOrderList_raProfileBased() throws AcmeProblemDocumentException, NotFoundException {
        URI requestUri = URI.create(RA_BASE_URI + RA_PROFILE_NAME + "/orders/" + ACME_ACCOUNT_ID_VALID);
        ResponseEntity<List<Order>> orders = acmeService
                .listOrders(RA_PROFILE_NAME, ACME_ACCOUNT_ID_VALID, requestUri, true);
        assertGetOrderList(orders);
    }

    private void assertGetOrderList(ResponseEntity<List<Order>> orders) {
        // status code is 200
        Assertions.assertEquals(HttpStatus.OK, orders.getStatusCode());
        Assertions.assertNotNull(orders);
    }

    @Test
    void testGetOrderListFail() {
        URI requestUri = URI.create(BASE_URI + ACME_PROFILE_NAME + "/orders/" + ACME_ACCOUNT_ID_INVALID);
        Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService.listOrders(ACME_PROFILE_NAME, ACME_ACCOUNT_ID_INVALID, requestUri, false));
    }

    @Test
    void testGetOrderList_fail_isRaProfileBased() {
        URI requestUri = URI.create(RA_BASE_URI + RA_PROFILE_NAME + "/orders/" + ACME_ACCOUNT_ID_INVALID);
        Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService.listOrders(RA_PROFILE_NAME, ACME_ACCOUNT_ID_INVALID, requestUri, true));
    }

    @Test
    void testGetOrder() throws AcmeProblemDocumentException, NotFoundException {
        URI requestUri = URI.create(BASE_URI + ACME_PROFILE_NAME + "/order/" + ORDER_ID_VALID);
        ResponseEntity<Order> orders = acmeService.getOrder(ACME_PROFILE_NAME, ORDER_ID_VALID, requestUri, false);
        assertGetOrder(orders);
    }

    @Test
    void testGetOrder_raProfileBased() throws AcmeProblemDocumentException, NotFoundException {
        URI requestUri = URI.create(RA_BASE_URI + RA_PROFILE_NAME + "/order/" + ORDER_ID_VALID);
        ResponseEntity<Order> orders = acmeService.getOrder(RA_PROFILE_NAME, ORDER_ID_VALID, requestUri, true);
        assertGetOrder(orders);
    }

    private void assertGetOrder(ResponseEntity<Order> orders) {
        // status code is 200
        Assertions.assertEquals(HttpStatus.OK, orders.getStatusCode());
        Assertions.assertNotNull(orders);
        // order status is VALID
        Assertions.assertEquals(OrderStatus.VALID, Objects.requireNonNull(orders.getBody()).getStatus());
    }

    @Test
    void testKeyRollover() throws JOSEException, AcmeProblemDocumentException, NotFoundException {
        URI requestUri = URI.create(BASE_URI + ACME_PROFILE_NAME + "/key-change");
        ResponseEntity<?> response = acmeService
                .keyRollover(ACME_PROFILE_NAME, buildKeyRolloverRequestJSON(requestUri, BASE_URI + ACME_PROFILE_NAME),
                        requestUri, false);
        assertKeyRollover(response);
    }

    @Test
    void testKeyRollover_raProfileBased() throws JOSEException, AcmeProblemDocumentException, NotFoundException {
        URI requestUri = URI.create(RA_BASE_URI + RA_PROFILE_NAME + "/key-change");
        ResponseEntity<?> response = acmeService
                .keyRollover(RA_PROFILE_NAME, buildKeyRolloverRequestJSON(requestUri, RA_BASE_URI + RA_PROFILE_NAME),
                        requestUri, true);
        assertKeyRollover(response);
    }

    private String buildKeyRolloverRequestJSON(URI requestUri, String baseUri) throws JOSEException {
        String account = baseUri + "/acct/" + ACME_ACCOUNT_ID_VALID;
        String oldKey = rsa2048PublicJWK.toString();

        JWSObjectJSON innerJwsObjectJSON = new JWSObjectJSON(
                new Payload("{\"account\":\"" + account + "\",\"oldKey\":" + oldKey + "}"));
        innerJwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .jwk(newRsa2048PublicJWK)
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), newRsa2048Signer);

        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload(innerJwsObjectJSON.serializeFlattened()));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(baseUri + "/acct/" + ACME_ACCOUNT_ID_VALID)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    private void assertKeyRollover(ResponseEntity<?> response) {
        // status code is 200
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        // contains Link header
        Assertions.assertNotNull(response.getHeaders().get("Link"));
    }

    /**
     * The expected record is accepted when the name also carries records left behind by earlier attempts, which a name
     * under continuous renewal regularly does.
     */
    @Test
    void testValidateChallenge_Dns01() throws AcmeProblemDocumentException, JOSEException, NotFoundException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        AcmeChallenge challenge = pendingDnsChallenge(pendingOrder("orderDns01"), "authDns01", "challengeDns01",
                "tokenDns01");

        try (var mockedContext = mockTxtRecords(STALE_DNS_VALIDATION_TOKEN,
                expectedDnsValidationToken(challenge.getToken()))) {
            ResponseEntity<Challenge> response = validateChallenge(challenge);

            Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
            Assertions.assertEquals(ChallengeStatus.VALID, Objects.requireNonNull(response.getBody()).getStatus());
            Assertions.assertNull(response.getBody().getError());

            AcmeChallenge updatedChallenge = reload(challenge);
            Assertions.assertEquals(ChallengeStatus.VALID, updatedChallenge.getStatus());
            Assertions.assertNotNull(updatedChallenge.getValidated());
            Assertions.assertEquals(AuthorizationStatus.VALID, updatedChallenge.getAuthorization().getStatus());
            Assertions
                    .assertEquals(OrderStatus.READY,
                            acmeOrderRepository.findByOrderId("orderDns01").orElseThrow().getStatus());
            Assertions.assertEquals(1, mockedContext.constructed().size());
        }
    }

    /**
     * A challenge whose records do not match invalidates its authorization and order, so a client waiting for the
     * authorization to settle learns that validation failed instead of polling a permanently pending one.
     */
    @Test
    void testValidateChallenge_Dns01_noMatchingRecord()
            throws AcmeProblemDocumentException, NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        AcmeChallenge challenge = pendingDnsChallenge(pendingOrder("orderDns01Invalid"), "authDns01Invalid",
                "challengeDns01Invalid", "tokenDns01Invalid");

        try (var mockedContext = mockTxtRecords(STALE_DNS_VALIDATION_TOKEN)) {
            ResponseEntity<Challenge> response = validateChallenge(challenge);

            Assertions.assertEquals(ChallengeStatus.INVALID, Objects.requireNonNull(response.getBody()).getStatus());
            Assertions.assertEquals(Problem.INCORRECT_RESPONSE.getType(), response.getBody().getError().getType());
            Assertions
                    .assertTrue(response
                            .getBody()
                            .getError()
                            .getDetail()
                            .contains(AcmeConstants.DNS_ACME_PREFIX + "example.com"));
            Assertions.assertFalse(response.getBody().getError().getDetail().contains(STALE_DNS_VALIDATION_TOKEN));

            AcmeChallenge updatedChallenge = reload(challenge);
            Assertions.assertEquals(ChallengeStatus.INVALID, updatedChallenge.getStatus());
            Assertions.assertNull(updatedChallenge.getValidated());
            Assertions.assertEquals(Problem.INCORRECT_RESPONSE, updatedChallenge.getErrorProblem());
            Assertions.assertEquals(AuthorizationStatus.INVALID, updatedChallenge.getAuthorization().getStatus());
            Assertions
                    .assertEquals(OrderStatus.INVALID,
                            acmeOrderRepository.findByOrderId("orderDns01Invalid").orElseThrow().getStatus());
        }
    }

    /**
     * A client may accept the same challenge more than once. A challenge that has already settled reports its recorded
     * state and is not validated again, so a repeated request cannot revive a failed authorization.
     */
    @Test
    void testValidateChallenge_Dns01_settledChallengeIsNotValidatedAgain() throws AcmeProblemDocumentException,
            JOSEException, NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        AcmeChallenge challenge = pendingDnsChallenge(pendingOrder("orderDns01Settled"), "authDns01Settled",
                "challengeDns01Settled", "tokenDns01Settled");
        challenge.setStatus(ChallengeStatus.INVALID);
        challenge.setErrorProblem(Problem.DNS);
        challenge.setErrorDetail("No TXT record found at " + AcmeConstants.DNS_ACME_PREFIX + "example.com");
        acmeChallengeRepository.save(challenge);

        try (var mockedContext = mockTxtRecords(expectedDnsValidationToken(challenge.getToken()))) {
            ResponseEntity<Challenge> response = validateChallenge(challenge);

            Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
            Assertions.assertEquals(ChallengeStatus.INVALID, Objects.requireNonNull(response.getBody()).getStatus());
            Assertions.assertEquals(Problem.DNS.getType(), response.getBody().getError().getType());
            Assertions.assertEquals(ChallengeStatus.INVALID, reload(challenge).getStatus());
            Assertions.assertTrue(mockedContext.constructed().isEmpty());
        }
    }

    /**
     * An authorization that has already failed is terminal (RFC 8555 section 7.1.6), so the challenge still pending
     * beside the failed one cannot revive it even once the record it expects is published.
     */
    @Test
    void testValidateChallenge_Dns01_failedAuthorizationIsNotRevived() throws AcmeProblemDocumentException,
            JOSEException, NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        AcmeChallenge challenge = pendingDnsChallenge(pendingOrder("orderDns01Failed"), "authDns01Failed",
                "challengeDns01Failed", "tokenDns01Failed");
        AcmeAuthorization authorization = challenge.getAuthorization();
        authorization.setStatus(AuthorizationStatus.INVALID);
        acmeAuthorizationRepository.save(authorization);

        try (var mockedContext = mockTxtRecords(expectedDnsValidationToken(challenge.getToken()))) {
            ResponseEntity<Challenge> response = validateChallenge(challenge);

            Assertions.assertEquals(ChallengeStatus.PENDING, Objects.requireNonNull(response.getBody()).getStatus());
            Assertions.assertEquals(ChallengeStatus.PENDING, reload(challenge).getStatus());
            Assertions
                    .assertEquals(AuthorizationStatus.INVALID,
                            acmeAuthorizationRepository
                                    .findByAuthorizationId("authDns01Failed")
                                    .orElseThrow()
                                    .getStatus());
            Assertions.assertTrue(mockedContext.constructed().isEmpty());
        }
    }

    /**
     * The recorded reason names the challenge record, so it grows with the identifier and can exceed the width a
     * generated schema gives a plain string column. It has to persist in full.
     */
    @Test
    void testValidateChallenge_recordedReasonPersistsInFull() {
        AcmeChallenge challenge = pendingDnsChallenge(pendingOrder("orderDns01Detail"), "authDns01Detail",
                "challengeDns01Detail", "tokenDns01Detail");
        String recordName = AcmeConstants.DNS_ACME_PREFIX + "a".repeat(250) + ".example.com";
        String detail = "No TXT record at " + recordName + " matches the expected key authorization";
        challenge.setErrorProblem(Problem.DNS);
        challenge.setErrorDetail(detail);

        acmeChallengeRepository.saveAndFlush(challenge);

        Assertions.assertTrue(detail.length() > 255);
        Assertions.assertEquals(detail, reload(challenge).getErrorDetail());
    }

    /**
     * An instance that does not yet propagate a failure leaves the authorization pending behind the failed challenge. A
     * client asking for that authorization is answered with the settled state instead of waiting for it to change.
     */
    @Test
    void testGetAuthorization_settlesAuthorizationLeftPendingBehindFailedChallenge() throws Exception {
        AcmeChallenge challenge = failedChallengeLeftUnpropagated("orderStale", "authStale", "challengeStale");
        int failedOrdersBefore = failedOrders(challenge);
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/authz/authStale");

        ResponseEntity<Authorization> response = acmeService
                .getAuthorization(ACME_PROFILE_NAME, "authStale", buildGetAuthorizationRequestJSON(requestUri, baseUri),
                        requestUri, false);

        Assertions.assertEquals(AuthorizationStatus.INVALID, Objects.requireNonNull(response.getBody()).getStatus());
        Assertions
                .assertEquals(AuthorizationStatus.INVALID,
                        acmeAuthorizationRepository.findByAuthorizationId("authStale").orElseThrow().getStatus());
        Assertions
                .assertEquals(OrderStatus.INVALID,
                        acmeOrderRepository.findByOrderId("orderStale").orElseThrow().getStatus());
        Assertions.assertEquals(failedOrdersBefore + 1, failedOrders(challenge));
    }

    @Test
    void testValidateChallenge_settlesAuthorizationLeftPendingBehindFailedChallenge() throws Exception {
        AcmeChallenge challenge = failedChallengeLeftUnpropagated("orderStaleChall", "authStaleChall",
                "challengeStaleChall");

        try (var mockedContext = mockTxtRecords(STALE_DNS_VALIDATION_TOKEN)) {
            ResponseEntity<Challenge> response = validateChallenge(challenge);

            Assertions.assertEquals(ChallengeStatus.INVALID, Objects.requireNonNull(response.getBody()).getStatus());
            Assertions
                    .assertEquals(AuthorizationStatus.INVALID,
                            acmeAuthorizationRepository
                                    .findByAuthorizationId("authStaleChall")
                                    .orElseThrow()
                                    .getStatus());
            Assertions
                    .assertEquals(OrderStatus.INVALID,
                            acmeOrderRepository.findByOrderId("orderStaleChall").orElseThrow().getStatus());
            Assertions.assertTrue(mockedContext.constructed().isEmpty());
        }
    }

    /**
     * An order left open behind a failed authorization is settled before it is answered, so it is reported the way an
     * invalid order is reported.
     */
    @Test
    void testGetOrder_settlesOrderLeftPendingBehindFailedAuthorization() throws Exception {
        AcmeOrder order = orderLeftOpenBehindFailedAuthorization("orderStaleGet", "authStaleGet", OrderStatus.PENDING);
        int failedOrdersBefore = failedOrders(order);
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME + "/order/orderStaleGet");

        ResponseEntity<Order> response = acmeService.getOrder(ACME_PROFILE_NAME, "orderStaleGet", requestUri, false);

        Assertions.assertEquals(OrderStatus.INVALID, Objects.requireNonNull(response.getBody()).getStatus());
        Assertions
                .assertEquals(OrderStatus.INVALID,
                        acmeOrderRepository.findByOrderId("orderStaleGet").orElseThrow().getStatus());
        Assertions.assertEquals(failedOrdersBefore + 1, failedOrders(order));
    }

    /**
     * An order cannot be finalized while one of its authorizations has failed, however it came to be ready.
     */
    @Test
    void testFinalizeOrder_refusesOrderLeftReadyBehindFailedAuthorization() throws Exception {
        orderLeftOpenBehindFailedAuthorization("orderStaleFin", "authStaleFin", OrderStatus.READY);
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/order/orderStaleFin/finalize");

        AcmeProblemDocumentException refused = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .finalizeOrder(ACME_PROFILE_NAME, "orderStaleFin",
                                        buildFinalizeRequestJSON(requestUri, baseUri), requestUri, false));

        Assertions.assertEquals(Problem.ORDER_NOT_READY.getType(), refused.getProblemDocument().getType());
        Assertions
                .assertEquals(OrderStatus.INVALID,
                        acmeOrderRepository.findByOrderId("orderStaleFin").orElseThrow().getStatus());
    }

    /**
     * The order is asked for before its authorization ever was: the failed challenge under the still-pending
     * authorization is what settles it.
     */
    @Test
    void testGetOrder_settlesOrderWhoseAuthorizationIsStillPendingBehindFailedChallenge() throws Exception {
        failedChallengeLeftUnpropagated("orderStaleChall2", "authStaleChall2", "challengeStaleChall2");
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME + "/order/orderStaleChall2");

        ResponseEntity<Order> response = acmeService.getOrder(ACME_PROFILE_NAME, "orderStaleChall2", requestUri, false);

        Assertions.assertEquals(OrderStatus.INVALID, Objects.requireNonNull(response.getBody()).getStatus());
        Assertions
                .assertEquals(AuthorizationStatus.INVALID,
                        acmeAuthorizationRepository.findByAuthorizationId("authStaleChall2").orElseThrow().getStatus());
        Assertions
                .assertEquals(OrderStatus.INVALID,
                        acmeOrderRepository.findByOrderId("orderStaleChall2").orElseThrow().getStatus());
    }

    @Test
    void testFinalizeOrder_refusesOrderWhoseAuthorizationIsStillPendingBehindFailedChallenge() throws Exception {
        AcmeChallenge challenge = failedChallengeLeftUnpropagated("orderStaleFin2", "authStaleFin2",
                "challengeStaleFin2");
        AcmeOrder order = challenge.getAuthorization().getOrder();
        order.setStatus(OrderStatus.READY);
        acmeOrderRepository.save(order);
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/order/orderStaleFin2/finalize");

        AcmeProblemDocumentException refused = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .finalizeOrder(ACME_PROFILE_NAME, "orderStaleFin2",
                                        buildFinalizeRequestJSON(requestUri, baseUri), requestUri, false));

        Assertions.assertEquals(Problem.ORDER_NOT_READY.getType(), refused.getProblemDocument().getType());
        Assertions
                .assertEquals(AuthorizationStatus.INVALID,
                        acmeAuthorizationRepository.findByAuthorizationId("authStaleFin2").orElseThrow().getStatus());
        Assertions
                .assertEquals(OrderStatus.INVALID,
                        acmeOrderRepository.findByOrderId("orderStaleFin2").orElseThrow().getStatus());
    }

    /**
     * A certificate has already been issued for the order, so a challenge validated afterwards leaves the order and the
     * account's counts as they are.
     */
    @Test
    void testValidateChallenge_leavesAnOrderWithAnIssuedCertificateAlone() throws Exception {
        AcmeChallenge challenge = pendingDnsChallenge(order1, "authIssued", "challengeIssued", "tokenIssued");
        int failedOrdersBefore = failedOrders(challenge);

        try (var mockedContext = mockTxtRecords(expectedDnsValidationToken(challenge.getToken()))) {
            ResponseEntity<Challenge> response = validateChallenge(challenge);

            Assertions.assertEquals(ChallengeStatus.VALID, Objects.requireNonNull(response.getBody()).getStatus());
            Assertions
                    .assertEquals(OrderStatus.VALID,
                            acmeOrderRepository.findByOrderId(ORDER_ID_VALID).orElseThrow().getStatus());
            Assertions.assertEquals(failedOrdersBefore, failedOrders(challenge));
            Assertions.assertEquals(1, mockedContext.constructed().size());
        }
    }

    /**
     * A multi-identifier order has an authorization per identifier and becomes ready only once every one of them has
     * been proven.
     */
    @Test
    void testValidateChallenge_multiIdentifierOrderBecomesReadyOnlyWhenEveryAuthorizationIsValid() throws Exception {
        AcmeOrder order = pendingOrder("orderMulti");
        AcmeChallenge first = pendingDnsChallenge(order, "authMulti1", "challengeMulti1", "tokenMulti1");
        AcmeChallenge second = pendingDnsChallenge(order, "authMulti2", "challengeMulti2", "tokenMulti2");

        try (var mockedContext = mockTxtRecords(expectedDnsValidationToken(first.getToken()))) {
            validateChallenge(first);
        }
        Assertions
                .assertEquals(OrderStatus.PENDING,
                        acmeOrderRepository.findByOrderId("orderMulti").orElseThrow().getStatus());

        try (var mockedContext = mockTxtRecords(expectedDnsValidationToken(second.getToken()))) {
            validateChallenge(second);
        }
        Assertions
                .assertEquals(OrderStatus.READY,
                        acmeOrderRepository.findByOrderId("orderMulti").orElseThrow().getStatus());
    }

    /**
     * Two accepts of one challenge can overlap: the second finds the challenge settled under the order lock and leaves
     * the recorded outcome alone instead of applying its own.
     */
    @Test
    void testWriter_leavesAChallengeSettledMeanwhileAlone() {
        AcmeChallenge challenge = failedChallengeLeftUnpropagated("orderRaced", "authRaced", "challengeRaced");
        AcmeAuthorization authorization = challenge.getAuthorization();
        authorization.setStatus(AuthorizationStatus.INVALID);
        acmeAuthorizationRepository.save(authorization);

        AcmeChallenge outcome = acmeChallengeWriter
                .applyValidationResult(authorization.getOrder().getUuid(), "challengeRaced",
                        ChallengeValidationResult.success());

        Assertions.assertEquals(ChallengeStatus.INVALID, outcome.getStatus());
        Assertions.assertEquals(AuthorizationStatus.INVALID, reload(challenge).getAuthorization().getStatus());
    }

    /**
     * The failed-order count is incremented in the database, so counting twice yields two whatever the entity held.
     */
    @Test
    void testWriter_countsFailedOrdersInTheDatabase() {
        UUID accountUuid = order1.getAcmeAccountUuid();
        int before = acmeAccountRepository.findByUuid(accountUuid).orElseThrow().getFailedOrders();

        acmeChallengeWriter.countFailedOrder(accountUuid);
        acmeChallengeWriter.countFailedOrder(accountUuid);

        Assertions
                .assertEquals(before + 2,
                        acmeAccountRepository.findByUuid(accountUuid).orElseThrow().getFailedOrders());
    }

    /**
     * An authorization left pending behind a failed challenge is settled before its expiry is enforced, so the request
     * is still refused but the rows no longer stay pending.
     */
    @Test
    void testGetAuthorization_settlesAnExpiredStaleAuthorizationBeforeRefusingIt() throws Exception {
        AcmeChallenge challenge = failedChallengeLeftUnpropagated("orderStaleExp", "authStaleExp", "challengeStaleExp");
        AcmeAuthorization authorization = challenge.getAuthorization();
        authorization.setExpires(new Date(System.currentTimeMillis() - 60_000));
        acmeAuthorizationRepository.save(authorization);
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/authz/authStaleExp");

        Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .getAuthorization(ACME_PROFILE_NAME, "authStaleExp",
                                        buildGetAuthorizationRequestJSON(requestUri, baseUri), requestUri, false));

        Assertions
                .assertEquals(AuthorizationStatus.INVALID,
                        acmeAuthorizationRepository.findByAuthorizationId("authStaleExp").orElseThrow().getStatus());
        Assertions
                .assertEquals(OrderStatus.INVALID,
                        acmeOrderRepository.findByOrderId("orderStaleExp").orElseThrow().getStatus());
    }

    /**
     * An order left open behind a failed authorization is settled before its expiry is enforced, so the request is
     * still refused but the row no longer stays open.
     */
    @Test
    void testGetOrder_settlesAnExpiredStaleOrderBeforeRefusingIt() throws Exception {
        AcmeOrder order = orderLeftOpenBehindFailedAuthorization("orderStaleExpired", "authStaleExpired",
                OrderStatus.READY);
        order.setExpires(new Date(System.currentTimeMillis() - 60_000));
        acmeOrderRepository.save(order);
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME + "/order/orderStaleExpired");

        AcmeProblemDocumentException refused = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService.getOrder(ACME_PROFILE_NAME, "orderStaleExpired", requestUri, false));

        Assertions.assertEquals(Problem.MALFORMED.getType(), refused.getProblemDocument().getType());
        Assertions
                .assertEquals(OrderStatus.INVALID,
                        acmeOrderRepository.findByOrderId("orderStaleExpired").orElseThrow().getStatus());
    }

    /**
     * A client deactivates an authorization by posting its status (RFC 8555 section 7.5.2).
     */
    @Test
    void testGetAuthorization_deactivatesTheAuthorizationOnRequest() throws Exception {
        pendingDnsChallenge(pendingOrder("orderDeact"), "authDeact", "challengeDeact", "tokenDeact");
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/authz/authDeact");

        ResponseEntity<Authorization> response = acmeService
                .getAuthorization(ACME_PROFILE_NAME, "authDeact", buildDeactivateRequestJSON(requestUri, baseUri),
                        requestUri, false);

        Assertions
                .assertEquals(AuthorizationStatus.DEACTIVATED, Objects.requireNonNull(response.getBody()).getStatus());
        Assertions
                .assertEquals(AuthorizationStatus.DEACTIVATED,
                        acmeAuthorizationRepository.findByAuthorizationId("authDeact").orElseThrow().getStatus());
        Assertions
                .assertEquals(OrderStatus.INVALID,
                        acmeOrderRepository.findByOrderId("orderDeact").orElseThrow().getStatus());
    }

    /**
     * A request that both settles a stale sibling and deactivates the asked-for authorization runs in one transaction;
     * the settlement of the sibling must survive the second lock on the order.
     */
    @Test
    void testGetAuthorization_deactivationKeepsTheSettlementOfAStaleSibling() throws Exception {
        AcmeOrder order = pendingOrder("orderDeactSibling");
        AcmeChallenge stale = pendingDnsChallenge(order, "authDeactStale", "challengeDeactStale", "tokenDeactStale");
        stale.setStatus(ChallengeStatus.INVALID);
        acmeChallengeRepository.save(stale);
        pendingDnsChallenge(order, "authDeactTarget", "challengeDeactTarget", "tokenDeactTarget");
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/authz/authDeactTarget");

        acmeService
                .getAuthorization(ACME_PROFILE_NAME, "authDeactTarget", buildDeactivateRequestJSON(requestUri, baseUri),
                        requestUri, false);

        Assertions
                .assertEquals(AuthorizationStatus.INVALID,
                        acmeAuthorizationRepository.findByAuthorizationId("authDeactStale").orElseThrow().getStatus());
        Assertions
                .assertEquals(AuthorizationStatus.DEACTIVATED,
                        acmeAuthorizationRepository.findByAuthorizationId("authDeactTarget").orElseThrow().getStatus());
        Assertions
                .assertEquals(OrderStatus.INVALID,
                        acmeOrderRepository.findByOrderId("orderDeactSibling").orElseThrow().getStatus());
    }

    /**
     * An authorization can be read or deactivated only by the account that placed its order.
     */
    @Test
    void testGetAuthorization_refusesAnotherAccount() throws Exception {
        pendingDnsChallenge(pendingOrder("orderForeign"), "authForeign", "challengeForeign", "tokenForeign");
        otherAccount();
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/authz/authForeign");

        AcmeProblemDocumentException refused = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .getAuthorization(ACME_PROFILE_NAME, "authForeign",
                                        signedByOtherAccount("{\"status\":\"deactivated\"}", requestUri, baseUri),
                                        requestUri, false));

        Assertions.assertEquals(Problem.UNAUTHORIZED.getType(), refused.getProblemDocument().getType());
        Assertions
                .assertEquals(AuthorizationStatus.PENDING,
                        acmeAuthorizationRepository.findByAuthorizationId("authForeign").orElseThrow().getStatus());
    }

    @Test
    void testGetAuthorization_refusesAKeySuppliedInline() throws Exception {
        pendingDnsChallenge(pendingOrder("orderInlineKey"), "authInlineKey", "challengeInlineKey", "tokenInlineKey");
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/authz/authInlineKey");
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload(""));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .jwk(rsa2048PublicJWK)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);

        AcmeProblemDocumentException refused = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService
                                .getAuthorization(ACME_PROFILE_NAME, "authInlineKey",
                                        jwsObjectJSON.serializeFlattened(), requestUri, false));

        Assertions.assertEquals(Problem.MALFORMED.getType(), refused.getProblemDocument().getType());
    }

    /**
     * An order can be finalized only by the account that placed it.
     */
    @Test
    void testFinalizeOrder_refusesAnotherAccount() throws Exception {
        AcmeOrder order = pendingOrder("orderForeignFin");
        order.setStatus(OrderStatus.READY);
        acmeOrderRepository.save(order);
        otherAccount();
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/order/orderForeignFin/finalize");

        AcmeProblemDocumentException refused = Assertions
                .assertThrows(AcmeProblemDocumentException.class, () -> acmeService
                        .finalizeOrder(ACME_PROFILE_NAME, "orderForeignFin",
                                signedByOtherAccount("{\"csr\":\"\"}", requestUri, baseUri), requestUri, false));

        Assertions.assertEquals(Problem.UNAUTHORIZED.getType(), refused.getProblemDocument().getType());
        Assertions
                .assertEquals(OrderStatus.READY,
                        acmeOrderRepository.findByOrderId("orderForeignFin").orElseThrow().getStatus());
    }

    private AcmeAccount otherAccount() throws JOSEException {
        AcmeAccount other = new AcmeAccount();
        other.setStatus(AccountStatus.VALID);
        other.setEnabled(true);
        other.setAccountId(OTHER_ACCOUNT_ID);
        other.setTermsOfServiceAgreed(true);
        other.setAcmeProfile(order1.getAcmeAccount().getAcmeProfile());
        other.setRaProfile(order1.getAcmeAccount().getRaProfile());
        other.setPublicKey(Base64.getEncoder().encodeToString(newRsa2048PublicJWK.toPublicKey().getEncoded()));
        return acmeAccountRepository.save(other);
    }

    private String signedByOtherAccount(String payload, URI requestUri, String baseUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload(payload));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(baseUri + "/acct/" + OTHER_ACCOUNT_ID)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), newRsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    /**
     * A request that deactivates whatever it is addressed to: the payload is the same for an account and for an
     * authorization (RFC 8555 sections 7.3.6 and 7.5.2).
     */
    private String buildDeactivateRequestJSON(URI requestUri, String baseUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload("{\"status\":\"deactivated\"}"));
        jwsObjectJSON
                .sign(new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(baseUri + "/acct/" + ACME_ACCOUNT_ID_VALID)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(), rsa2048Signer);
        return jwsObjectJSON.serializeFlattened();
    }

    @Test
    void testValidateChallenge_refusesAnAuthorizationWithoutAnIdentifier() {
        AcmeChallenge challenge = pendingDnsChallenge(pendingOrder("orderNoId"), "authNoId", "challengeNoId",
                "tokenNoId");
        AcmeAuthorization authorization = challenge.getAuthorization();
        authorization.setIdentifier(null);
        acmeAuthorizationRepository.save(authorization);

        AcmeProblemDocumentException refused = Assertions
                .assertThrows(AcmeProblemDocumentException.class, () -> validateChallenge(challenge));

        Assertions.assertEquals(Problem.SERVER_INTERNAL.getType(), refused.getProblemDocument().getType());
        Assertions.assertEquals(ChallengeStatus.PENDING, reload(challenge).getStatus());
    }

    /**
     * An order the previous behaviour let finalize despite a failed authorization already has its certificate. Polling
     * that authorization settles it, but the order keeps its status and is not counted as failed.
     */
    @Test
    void testGetAuthorization_doesNotFailAnOrderWhoseCertificateWasIssued() throws Exception {
        AcmeChallenge challenge = failedChallengeLeftUnpropagated("orderIssuedStale", "authIssuedStale",
                "challengeIssuedStale");
        AcmeOrder order = challenge.getAuthorization().getOrder();
        order.setStatus(OrderStatus.READY);
        order.setCertificateReference(order1.getCertificateReference());
        order.setCertificateReferenceUuid(order1.getCertificateReferenceUuid());
        acmeOrderRepository.save(order);
        int failedOrdersBefore = failedOrders(order);
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/authz/authIssuedStale");

        ResponseEntity<Authorization> response = acmeService
                .getAuthorization(ACME_PROFILE_NAME, "authIssuedStale",
                        buildGetAuthorizationRequestJSON(requestUri, baseUri), requestUri, false);

        Assertions.assertEquals(AuthorizationStatus.INVALID, Objects.requireNonNull(response.getBody()).getStatus());
        Assertions
                .assertEquals(OrderStatus.READY,
                        acmeOrderRepository.findByOrderId("orderIssuedStale").orElseThrow().getStatus());
        Assertions.assertEquals(failedOrdersBefore, failedOrders(order));
    }

    /**
     * An invalid order is a protocol state, so it is reported with that status rather than as a server fault.
     */
    @Test
    void testGetOrder_reportsAnInvalidOrderWithItsStatus() throws Exception {
        AcmeOrder order = pendingOrder("orderInvalidReport");
        order.setStatus(OrderStatus.INVALID);
        acmeOrderRepository.save(order);
        URI requestUri = new URI(BASE_URI + ACME_PROFILE_NAME + "/order/orderInvalidReport");

        ResponseEntity<Order> response = acmeService
                .getOrder(ACME_PROFILE_NAME, "orderInvalidReport", requestUri, false);

        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertEquals(OrderStatus.INVALID, Objects.requireNonNull(response.getBody()).getStatus());
    }

    /**
     * The status an order takes from its certificate is decided under the order lock and counted once, so two requests
     * polling the same order between them record one transition rather than one each.
     */
    @Test
    void testWriter_countsACertificateDerivedTransitionOnce() {
        UUID accountUuid = order1.getAcmeAccountUuid();
        order1.setStatus(OrderStatus.PROCESSING);
        acmeOrderRepository.save(order1);
        int validBefore = acmeAccountRepository.findByUuid(accountUuid).orElseThrow().getValidOrders();

        AcmeOrder first = acmeChallengeWriter.reconcileCertificateStatus(order1.getUuid());
        AcmeOrder second = acmeChallengeWriter.reconcileCertificateStatus(order1.getUuid());

        Assertions.assertEquals(OrderStatus.VALID, first.getStatus());
        Assertions.assertEquals(OrderStatus.VALID, second.getStatus());
        Assertions
                .assertEquals(validBefore + 1,
                        acmeAccountRepository.findByUuid(accountUuid).orElseThrow().getValidOrders());
    }

    /**
     * Deactivating an account counts each order it closes in the database, so a count recorded while the orders were
     * being locked survives the account being written back.
     */
    @Test
    void testUpdateAccount_deactivationKeepsACountRecordedWhileItRan() throws Exception {
        AcmeOrder open = pendingOrder("orderDeactCount");
        UUID accountUuid = open.getAcmeAccountUuid();
        int failedBefore = acmeAccountRepository.findByUuid(accountUuid).orElseThrow().getFailedOrders();
        // stands in for a challenge that failed while the deactivation was acquiring its order locks
        acmeChallengeWriter.countFailedOrder(accountUuid);
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/acct/" + ACME_ACCOUNT_ID_VALID);

        acmeService
                .updateAccount(ACME_PROFILE_NAME, ACME_ACCOUNT_ID_VALID,
                        buildDeactivateRequestJSON(requestUri, baseUri), requestUri, false);

        AcmeAccount reloaded = acmeAccountRepository.findByUuid(accountUuid).orElseThrow();
        Assertions.assertEquals(AccountStatus.DEACTIVATED, reloaded.getStatus());
        Assertions
                .assertEquals(OrderStatus.INVALID,
                        acmeOrderRepository.findByOrderId("orderDeactCount").orElseThrow().getStatus());
        // the concurrent count, plus every order this deactivation closed
        Assertions.assertTrue(reloaded.getFailedOrders() >= failedBefore + 2);
    }

    /**
     * The state an instance without failure propagation leaves behind: the challenge is invalid, nothing else is.
     */
    private AcmeChallenge failedChallengeLeftUnpropagated(String orderId, String authorizationId, String challengeId) {
        AcmeChallenge challenge = pendingDnsChallenge(pendingOrder(orderId), authorizationId, challengeId,
                "token-" + challengeId);
        challenge.setStatus(ChallengeStatus.INVALID);
        acmeChallengeRepository.save(challenge);
        return challenge;
    }

    private AcmeOrder orderLeftOpenBehindFailedAuthorization(String orderId, String authorizationId,
            OrderStatus orderStatus) {
        AcmeOrder order = pendingOrder(orderId);
        order.setStatus(orderStatus);
        acmeOrderRepository.save(order);
        AcmeAuthorization authorization = pendingDnsChallenge(order, authorizationId, "challenge-" + authorizationId,
                "token-" + authorizationId).getAuthorization();
        authorization.setStatus(AuthorizationStatus.INVALID);
        acmeAuthorizationRepository.save(authorization);
        return order;
    }

    private int failedOrders(AcmeChallenge challenge) {
        return failedOrders(challenge.getAuthorization().getOrder());
    }

    private int failedOrders(AcmeOrder order) {
        return acmeAccountRepository.findByUuid(order.getAcmeAccountUuid()).orElseThrow().getFailedOrders();
    }

    private AcmeOrder pendingOrder(String orderId) {
        AcmeOrder order = new AcmeOrder();
        order.setOrderId(orderId);
        order.setStatus(OrderStatus.PENDING);
        order.setAcmeAccount(order1.getAcmeAccount());
        acmeOrderRepository.save(order);
        return order;
    }

    private AcmeChallenge pendingDnsChallenge(AcmeOrder order, String authorizationId, String challengeId,
            String token) {
        AcmeAuthorization authorization = new AcmeAuthorization();
        authorization.setAuthorizationId(authorizationId);
        authorization.setStatus(AuthorizationStatus.PENDING);
        authorization.setIdentifier("{\"type\":\"dns\",\"value\":\"example.com\"}");
        authorization.setOrderUuid(order.getUuid());
        authorization.setOrder(order);
        acmeAuthorizationRepository.save(authorization);

        AcmeChallenge challenge = new AcmeChallenge();
        challenge.setChallengeId(challengeId);
        challenge.setStatus(ChallengeStatus.PENDING);
        challenge.setType(ChallengeType.DNS01);
        challenge.setToken(token);
        challenge.setAuthorizationUuid(authorization.getUuid());
        challenge.setAuthorization(authorization);
        acmeChallengeRepository.save(challenge);
        return challenge;
    }

    private ResponseEntity<Challenge> validateChallenge(AcmeChallenge challenge)
            throws NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, AcmeProblemDocumentException {
        URI requestUri = URI.create(BASE_URI + ACME_PROFILE_NAME + "/chall/" + challenge.getChallengeId());
        return acmeService.validateChallenge(ACME_PROFILE_NAME, challenge.getChallengeId(), requestUri, false);
    }

    private AcmeChallenge reload(AcmeChallenge challenge) {
        return acmeChallengeRepository.findByChallengeId(challenge.getChallengeId()).orElseThrow();
    }

    private String expectedDnsValidationToken(String token) throws JOSEException, NoSuchAlgorithmException {
        String keyAuthorization = AcmeCommonHelper.createKeyAuthorization(token, rsa2048PublicJWK.toPublicKey());
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(keyAuthorization.getBytes(StandardCharsets.UTF_8));
        return Base64URL.encode(digest).toString();
    }

    /**
     * Stands in for the DNS provider, which returns every TXT record of a name as a separate value of one {@code TXT}
     * attribute.
     */
    private static MockedConstruction<InitialDirContext> mockTxtRecords(String... txtValues) {
        BasicAttribute records = new BasicAttribute(AcmeConstants.DNS_RECORD_TYPE);
        for (String txtValue : txtValues) {
            records.add(txtValue);
        }
        Attributes attributes = new BasicAttributes(true);
        attributes.put(records);
        return mockConstruction(InitialDirContext.class,
                (mock, context) -> when(mock.getAttributes(anyString(), any(String[].class))).thenReturn(attributes));
    }
}
