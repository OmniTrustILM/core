package com.otilm.core.service.acme;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.acme.AccountStatus;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.core.certificate.request.ProtocolRequestAttributeValidator;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.entity.acme.AcmeNonce;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.acme.AcmeAccountRepository;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.util.AcmeCommonHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateTestUtil;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObjectJSON;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

/**
 * ACME `finalizeOrder` must pre-validate request attributes synchronously in `validateCSR`, so a policy violation surfaces immediately as {@link Problem#BAD_CSR}.
 */
@Transactional
class AcmeFinalizeRequestAttributeValidationTest extends BaseSpringBootTest {

    private static final String BASE_URI = "https://localhost:8443/api/acme/";
    private static final String ACME_PROFILE_NAME = "testAcmeProfileRequestAttrs";
    private static final String RA_PROFILE_NAME = "testRaProfileRequestAttrs";
    private static final String NONCE_HEADER_CUSTOM_PARAM = "nonce";
    private static final String URL_HEADER_CUSTOM_PARAM = "url";
    private static final String ACME_ACCOUNT_ID_VALID = "RMAl70zrRrsRA";
    private static final String ORDER_ID_VALID = "orderRequestAttrs123";

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
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private AcmeExternalService acmeService;

    @MockitoBean
    private ProtocolRequestAttributeValidator protocolRequestAttributeValidator;

    private AcmeNonce acmeValidNonce;
    private JWSSigner rsa2048Signer;
    private AcmeOrder order;

    @BeforeEach
    void seedReadyAcmeOrderAndSigner() throws Exception {
        mockAcmeRolePermissions();

        RSAKey rsa2048JWK = new RSAKeyGenerator(2048).generate();
        rsa2048Signer = new RSASSASigner(rsa2048JWK);

        KeyPair keyPair = rsa2048JWK.toKeyPair();
        X509Certificate x509Certificate = CertificateTestUtil.generateRandomX509Certificate(keyPair);
        String b64Certificate = Base64.getEncoder().encodeToString(x509Certificate.getEncoded());

        Connector connector = new Connector();
        connector.setUrl("http://localhost:0");
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

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent(b64Certificate);
        certificateContent = certificateContentRepository.save(certificateContent);

        Certificate certificate = new Certificate();
        certificate.setCertificateContent(certificateContent);
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setRaProfile(raProfile);
        certificateRepository.save(certificate);

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

        AcmeAccount acmeAccount = new AcmeAccount();
        acmeAccount.setStatus(AccountStatus.VALID);
        acmeAccount.setEnabled(true);
        acmeAccount.setAccountId(ACME_ACCOUNT_ID_VALID);
        acmeAccount.setTermsOfServiceAgreed(true);
        acmeAccount.setAcmeProfile(acmeProfile);
        acmeAccount.setRaProfile(raProfile);
        acmeAccount.setPublicKey(Base64.getEncoder().encodeToString(rsa2048JWK.toPublicKey().getEncoded()));
        acmeAccountRepository.save(acmeAccount);

        order = new AcmeOrder();
        order.setOrderId(ORDER_ID_VALID);
        order.setStatus(OrderStatus.READY);
        order.setAcmeAccount(acmeAccount);
        acmeOrderRepository.save(order);

        Date expires = AcmeCommonHelper.addSeconds(new Date(), AcmeConstants.NONCE_VALIDITY);
        acmeValidNonce = new AcmeNonce();
        acmeValidNonce.setNonce("Kh4vY-nX7t1oQoK6vT1Frq4Vv1uK6RQKZQKfSTOZ9Ho");
        acmeValidNonce.setCreated(new Date());
        acmeValidNonce.setExpires(expires);
        acmeNonceRepository.save(acmeValidNonce);
    }

    @Test
    void rejectsFinalizeWithBadCsr_whenCsrViolatesRequestAttributes() throws Exception {
        // given — pre-validation (validateCSR) rejects the CSR with a request-attribute policy violation
        var violationDetail = "CSR is missing required request attribute 'commonName'";
        doThrow(new RequestAttributePolicyViolationException(violationDetail, List.of()))
                .when(protocolRequestAttributeValidator).validate(Mockito.any(), Mockito.any());
        String baseUri = BASE_URI + ACME_PROFILE_NAME;
        URI requestUri = new URI(baseUri + "/order/" + ORDER_ID_VALID + "/finalize");
        String finalizeRequestJson = buildFinalizeRequestJSON(requestUri, baseUri);

        // when / then — the violation surfaces immediately as BAD_CSR carrying only the safe detail
        assertThatThrownBy(() -> acmeService.finalizeOrder(ACME_PROFILE_NAME, ORDER_ID_VALID, finalizeRequestJson, requestUri, false))
                .isInstanceOfSatisfying(AcmeProblemDocumentException.class, ex -> {
                    assertThat(ex.getProblemDocument().getType()).isEqualTo(Problem.BAD_CSR.getType());
                    assertThat(ex.getMessage())
                            .contains(violationDetail)
                            .doesNotContainIgnoringCase("sql")
                            .doesNotContain("com.otilm")
                            .doesNotContain("Exception");
                });

        // and — the order is NOT driven to INVALID; synchronous pre-validation is the whole point
        assertThat(acmeOrderRepository.findByOrderId(ORDER_ID_VALID).orElseThrow().getStatus())
                .isNotEqualTo(OrderStatus.INVALID);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private String buildFinalizeRequestJSON(URI requestUri, String baseUri) throws JOSEException {
        JWSObjectJSON jwsObjectJSON = new JWSObjectJSON(new Payload(
                "{\"csr\":\"MIICdjCCAV4CAQIwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALeJvx7JWbwzobWL74KyHz0FjPqt0R5iOaOxiYqpfMY-ZVhMBkS0FqnCBQzMn5BkHukdx7HsIMkJ-sM01HVHJaRpgpf1zeTyRQjY7ESDikRL_1Ekxi6Sgf5unzB35aP2EBxiAaomG610HjpqSfGtOzEf12hy4jkcC446TT8nE9dm6CBf7XAoq9vXxXRjnAgdkr62yIzanXedDwdcNyk5EiiRWQXwW-L5Pex5808ip2gmE5Al5SPUiv8eDCq02QVDJ8Ln4UPYkxL1b6RMlfEgKLsGEZX0e-FC0w_fiBN48zrvHxqM2fdU7Ae8pRDwUOClYOxDkrvDv60RGikLlQZ45FcCAwEAAaAxMC8GCSqGSIb3DQEJDjEiMCAwHgYDVR0RBBcwFYITZGViaWFuMTAuYWNtZS5sb2NhbDANBgkqhkiG9w0BAQsFAAOCAQEAHlO0ZuPuYEtplU0gEUj88Yi1MWkrElx0JoTk7qonRsufu_Y2P_u-RrkWOzM3VJ08lNz90L_mnc8NOONMl_WlYWBywbUMsGar4Y_1x0ySOEdp5fg87rxY1b2jbSL7tPe4OV7yAebdCEzzXXBi3Ay9NoJAhwNONjyRp92vqT5-MWMXQyZvdcUMM38l6aNc9jof3EluNbgO7nWSle6MQJJvlEYwXx7ZPvvgxMfrRa-Yc_aWS7w25MSAODKKwvIivGn5q_owfd5AozYp0pymiLLbvAWhYVWL_-bGvJ13xpyfNPnGJIdwcY8zgikYPyBfbRmPyKJLPI4QnWz8GsWGiaUgjA\"}"));
        jwsObjectJSON.sign(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(baseUri + "/acct/" + ACME_ACCOUNT_ID_VALID)
                        .customParam(NONCE_HEADER_CUSTOM_PARAM, acmeValidNonce.getNonce())
                        .customParam(URL_HEADER_CUSTOM_PARAM, requestUri.toString())
                        .build(),
                rsa2048Signer
        );
        return jwsObjectJSON.serializeFlattened();
    }

    private void mockAcmeRolePermissions() {
        OpaResourceAccessResult resourceAccessAllowed = new OpaResourceAccessResult(true, List.of("AllResourcesAllowed"));
        OpaResourceAccessResult resourceAccessNotAllowed = new OpaResourceAccessResult(false, List.of());

        when(
                opaClient.checkResourceAccess(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())
        ).thenReturn(resourceAccessNotAllowed);

        when(
                opaClient.checkResourceAccess(Mockito.any(), Mockito.argThat(req ->
                        req != null && req.getProperties().containsKey(Resource.ACME_ACCOUNT.getCode())
                ), Mockito.any(), Mockito.any())
        ).thenReturn(resourceAccessAllowed);

        when(
                opaClient.checkResourceAccess(
                        Mockito.any(),
                        Mockito.argThat(req -> isRequestForResourceAction(req, Resource.ACME_PROFILE, ResourceAction.DETAIL)),
                        Mockito.any(),
                        Mockito.any()
                )
        ).thenReturn(resourceAccessAllowed);

        when(
                opaClient.checkResourceAccess(
                        Mockito.any(),
                        Mockito.argThat(req -> isRequestForResourceAction(req, Resource.RA_PROFILE, ResourceAction.DETAIL)),
                        Mockito.any(),
                        Mockito.any()
                )
        ).thenReturn(resourceAccessAllowed);
    }

    private static boolean isRequestForResourceAction(OpaRequestedResource requestedResource, Resource resource, ResourceAction resourceAction) {
        return requestedResource != null && requestedResource.getProperties() != null &&
                (requestedResource.getProperties().containsKey("name") && requestedResource.getProperties().get("name").equals(resource.getCode())) &&
                (requestedResource.getProperties().containsKey("action") && requestedResource.getProperties().get("action").equals(resourceAction.getCode()));
    }
}
