package com.czertainly.core.service.acme.integration;

import com.czertainly.api.model.client.acme.AcmeProfileRequestDto;
import com.czertainly.api.model.client.authority.AuthorityInstanceRequestDto;
import com.czertainly.api.model.client.raprofile.ActivateAcmeForRaProfileRequestDto;
import com.czertainly.api.model.client.raprofile.AddRaProfileRequestDto;
import com.czertainly.api.model.core.acme.Account;
import com.czertainly.api.model.core.acme.AcmeProfileDto;
import com.czertainly.api.model.core.acme.Authorization;
import com.czertainly.api.model.core.acme.AuthorizationStatus;
import com.czertainly.api.model.core.acme.Challenge;
import com.czertainly.api.model.core.acme.ChallengeStatus;
import com.czertainly.api.model.core.acme.ChallengeType;
import com.czertainly.api.model.core.acme.OrderStatus;
import com.czertainly.api.model.core.authority.AuthorityInstanceDto;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.raprofile.RaProfileDto;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.Connector2FunctionGroup;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.entity.acme.AcmeAuthorization;
import com.czertainly.core.dao.entity.acme.AcmeChallenge;
import com.czertainly.core.dao.entity.acme.AcmeOrder;
import com.czertainly.core.dao.entity.acme.AcmeProfile;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.Connector2FunctionGroupRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
import com.czertainly.core.dao.repository.AcmeProfileRepository;
import com.czertainly.core.dao.repository.acme.AcmeAuthorizationRepository;
import com.czertainly.core.dao.repository.acme.AcmeChallengeRepository;
import com.czertainly.core.dao.repository.acme.AcmeNonceRepository;
import com.czertainly.core.dao.repository.acme.AcmeOrderRepository;
import com.czertainly.core.messaging.model.ActionMessage;
import com.czertainly.core.messaging.jms.producers.ActionProducer;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.AcmeProfileService;
import com.czertainly.core.service.AuthorityInstanceService;
import com.czertainly.core.service.RaProfileService;
import com.czertainly.core.service.acme.AcmeService;
import com.czertainly.core.service.acme.AcmeTestUtil;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.MetaDefinitions;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import org.awaitility.Awaitility;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

/**
 * End-to-end integration test for the ACME (RFC 8555) protocol implementation.
 *
 * <p>Exercises the full certificate lifecycle through the service layer:
 * <ol>
 *   <li>Infrastructure setup – connector, authority instance, RA profile, ACME profile</li>
 *   <li>Account creation ({@code POST /new-account})</li>
 *   <li>Order creation ({@code POST /new-order})</li>
 *   <li>HTTP-01 challenge authorization ({@code GET /authz/{id}}) – validated via direct DB state update</li>
 *   <li>Order finalization ({@code POST /order/{id}/finalize}) with PKCS#10 CSR</li>
 *   <li>Order status verification ({@code GET /order/{id}})</li>
 *   <li>Certificate download ({@code GET /cert/{id}})</li>
 * </ol>
 *
 * <p>The external Authority Provider connector is stubbed with WireMock.
 * Challenge HTTP validation is simulated by directly setting the entity state in the database,
 * which is appropriate for a service-layer integration test.
 * Certificate issuance via the connector is driven through the real
 * {@link com.czertainly.core.service.v2.ClientOperationService} code path: the
 * {@link ActionProducer} is spied on so that each {@code ActionMessage} is dispatched
 * synchronously to {@code issueCertificateAction} instead of being sent over RabbitMQ.
 */
public class AcmeProtocolFlowITest extends BaseSpringBootTest {

    // ── Spring beans ──────────────────────────────────────────────────────────

    @Autowired
    private AuthorityInstanceService authorityInstanceService;
    @Autowired
    private RaProfileService raProfileService;
    @Autowired
    private AcmeProfileService acmeProfileService;
    @Autowired
    private AcmeService acmeService;
    @Autowired
    private ClientOperationService clientOperationService;

    @MockitoSpyBean
    private ActionProducer actionProducer;

    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AcmeNonceRepository acmeNonceRepository;
    @Autowired
    private AcmeOrderRepository acmeOrderRepository;
    @Autowired
    private AcmeProfileRepository acmeProfileRepository;
    @Autowired
    private AcmeAuthorizationRepository acmeAuthorizationRepository;
    @Autowired
    private AcmeChallengeRepository acmeChallengeRepository;

    // ── Test constants ────────────────────────────────────────────────────────

    private static final String ACME_PROFILE_NAME = "testAcmeProfile";
    private static final String AUTHORITY_UUID = UUID.randomUUID().toString();
    private static final String CONNECTOR_NAME = "testConnector";
    private static final String DOMAIN_NAME = "localhost"; // Localhost is required for HTTP-01 challenge simulation.
    private static final String KIND_NAME = "MOCK_EJBCA";
    private static final String RA_PROFILE_NAME = "testRaProfile";
    private static final String RA_PROFILE_NAME_2 = "testRaProfile2";

    // ── Per-test state ────────────────────────────────────────────────────────

    private final ObjectMapper objectMapper = new ObjectMapper();
    private KeyPairGenerator keyPairGenerator;
    private WireMockServer wireMockServer;
    private KeyPair acmeKeyPair;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @BeforeEach
    public void setUpAcme() throws NoSuchAlgorithmException {
        wireMockServer = new WireMockServer(0);
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());

        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        acmeKeyPair = keyPairGenerator.generateKeyPair();

        // Intercept ActionProducer to drive certificate issuance synchronously, bypassing RabbitMQ. ISSUE messages
        // are forwarded directly to issueCertificateAction; all other action types remain no-ops.
        Mockito.doAnswer(inv -> {
            ActionMessage msg = inv.getArgument(0);
            if (msg.getResourceAction() == ResourceAction.ISSUE) {
                clientOperationService.issueCertificateAction(msg.getResourceUuid(), false);
            }
            return null;
        }).when(actionProducer).produceMessage(Mockito.any());
    }

    @AfterEach
    public void tearDownAcme() {
        wireMockServer.stop();
    }

    // ── Test ──────────────────────────────────────────────────────────────────

    /**
     * Happy-path end-to-end flow: account → order → challenge → finalize → download.
     */
    @Test
    public void acmeFullCertificateLifecycleFlow() throws Exception {

        // ── Step 1: Infrastructure ────────────────────────────────────────────
        Connector connector = createConnector();
        AuthorityInstanceDto authorityInstance = createAuthorityInstance(connector);
        RaProfileDto raProfile = createRaProfile(authorityInstance);
        createAcmeProfile(raProfile, authorityInstance);

        // ── Step 2: Account creation ──────────────────────────────────────────
        String acmeAccountId = createAcmeAccount();

        // ── Step 3: Order creation ────────────────────────────────────────────
        OrderAndId order = createAcmeOrder(acmeAccountId);

        // ── Step 4: Challenge authorisation ───────────────────────────────────
        validateChallenge(order, acmeAccountId);

        // ── Step 5: Order finalisation ────────────────────────────────────────
        finalizeOrder(order.orderId, acmeAccountId);

        // ── Step 6: Wait for async certificate issuance ───────────────────────
        // finalizeOrder triggers an @Async task that calls issueCertificateAction
        // via the ActionProducer doAnswer; poll until the order reaches VALID.
        awaitOrderStatus(order.orderId, OrderStatus.VALID);

        // ── Step 7: Verify order status ───────────────────────────────────────
        ResponseEntity<com.czertainly.api.model.core.acme.Order> orderResponse = acmeService.getOrder(
                ACME_PROFILE_NAME, order.orderId,
                new URI("/acme/" + ACME_PROFILE_NAME + "/order/" + order.orderId), false);
        Assertions.assertNotNull(orderResponse.getBody());
        Assertions.assertEquals(OrderStatus.VALID, orderResponse.getBody().getStatus());

        // ── Step 8: Certificate download ──────────────────────────────────────
        String certUrl = orderResponse.getBody().getCertificate();
        String certificateId = certUrl.substring(certUrl.lastIndexOf('/') + 1);
        ResponseEntity<org.springframework.core.io.Resource> downloadResponse = acmeService.downloadCertificate(
                ACME_PROFILE_NAME, certificateId,
                new URI("/acme/" + ACME_PROFILE_NAME + "/cert/" + certificateId), false);
        Assertions.assertEquals(200, downloadResponse.getStatusCode().value());
        Assertions.assertNotNull(downloadResponse.getBody());
    }

    /**
     * Ensure a change to the default RA Profile is reflected in existing ACME accounts.
     *
     * <p>When an ACME account is created through the ACME-Profile-based flow it is marked with
     * {@code isDefaultRaProfile = true}. If the ACME Profile is later updated to a different RA Profile
     * via {@link AcmeProfileService#updateRaProfile}, all such accounts must have their RA profiles updated
     * so that subsequent certificate operations are issued under the new RA Profile.
     *
     * <p>This test verifies that after switching the ACME Profile from
     * {@value #RA_PROFILE_NAME} to {@value #RA_PROFILE_NAME_2}, a new order finalized on the
     * existing account results in a certificate associated with {@value #RA_PROFILE_NAME_2}.
     */
    @Test
    public void acmeRaProfileChangeReflectedInExistingAccount() throws Exception {

        // ── Step 1: Infrastructure with raProfile1 ────────────────────────────
        Connector connector = createConnector();
        AuthorityInstanceDto authorityInstance = createAuthorityInstance(connector);
        RaProfileDto raProfile1 = createRaProfile(authorityInstance);
        AcmeProfileDto acmeProfile = createAcmeProfile(raProfile1, authorityInstance);

        // ── Step 2: Create an ACME account – raProfile1 is snapshotted ──────────
        String acmeAccountId = createAcmeAccount();

        // ── Step 3: Place a new order on the existing account ─────────────────
        OrderAndId order1 = createAcmeOrder(acmeAccountId);

        // ── Step 4: Challenge and finalization ────────────────────────────────
        validateChallenge(order1, acmeAccountId);
        finalizeOrder(order1.orderId, acmeAccountId);
        awaitOrderStatus(order1.orderId, OrderStatus.VALID);

        // ── Step 5: Create raProfile2 and update the ACME Profile to use it ──
        RaProfileDto raProfile2 = createSecondRaProfile(authorityInstance);
        acmeProfileService.updateRaProfile(
                SecuredUUID.fromString(acmeProfile.getUuid()),
                raProfile2.getUuid());

        // ── Step 6: Assert that the ACME Profile's RA Profile was persisted correctly ──
        AcmeProfile reloadedAcmeProfile = acmeProfileRepository.findByUuid(UUID.fromString(acmeProfile.getUuid())).orElseThrow();
        Assertions.assertEquals(UUID.fromString(raProfile2.getUuid()), reloadedAcmeProfile.getRaProfileUuid(),
                "ACME Profile ra_profile_uuid must be persisted to the database after updateRaProfile");

        // ── Step 7: Place a new order on the same ACME account ─────────────────
        OrderAndId order2 = createAcmeOrder(acmeAccountId);

        // ── Step 8: Challenge, finalize, and await the new order ──────────────
        validateChallenge(order2, acmeAccountId);
        finalizeOrder(order2.orderId, acmeAccountId);
        awaitOrderStatus(order2.orderId, OrderStatus.VALID);

        // ── Step 9: Assert certificate reflects the updated RA Profile ────────
        AcmeOrder acmeOrder = acmeOrderRepository.findByOrderId(order2.orderId).orElseThrow();
        Assertions.assertNotNull(acmeOrder.getCertificateReferenceUuid(), "Issued certificate must not be null");
        Certificate certificate = certificateRepository
                .findByUuid(acmeOrder.getCertificateReferenceUuid()).orElseThrow();
        Assertions.assertEquals(
                UUID.fromString(raProfile2.getUuid()),
                certificate.getRaProfileUuid(),
                "Certificate should be issued under the updated RA Profile (" + RA_PROFILE_NAME_2 + ")");
    }

    // ── Infrastructure setup helpers ──────────────────────────────────────────

    /**
     * Registers a WireMock-backed Authority Provider connector and its function group.
     */
    private Connector createConnector() {
        wireMockServer.stubFor(get(urlMatching("/v1/authorityProvider/" + KIND_NAME + "/attributes"))
                .willReturn(okJson("[]")));
        wireMockServer.stubFor(get(urlMatching("/v1/authorityProvider/authorities/" + AUTHORITY_UUID + "/raProfile/attributes"))
                .willReturn(okJson("[]")));
        wireMockServer.stubFor(get(urlMatching("/v2/authorityProvider/authorities/" + AUTHORITY_UUID + "/certificates/issue/attributes"))
                .willReturn(okJson("[]")));
        wireMockServer.stubFor(get(urlMatching("/v2/authorityProvider/authorities/" + AUTHORITY_UUID + "/certificates/revoke/attributes"))
                .willReturn(okJson("[]")));
        wireMockServer.stubFor(post(urlMatching("/v1/authorityProvider/authorities"))
                .willReturn(okJson("{ \"uuid\": \"" + AUTHORITY_UUID + "\" }")));
        wireMockServer.stubFor(post(urlMatching("/v1/authorityProvider/authorities/" + AUTHORITY_UUID + "/caCertificates"))
                .willReturn(okJson("{ \"certificates\": [] }")));
        wireMockServer.stubFor(post(urlMatching("/v1/authorityProvider/" + KIND_NAME + "/attributes/validate"))
                .willReturn(okJson("true")));
        wireMockServer.stubFor(post(urlMatching("/v1/authorityProvider/authorities/" + AUTHORITY_UUID + "/raProfile/attributes/validate"))
                .willReturn(okJson("true")));
        wireMockServer.stubFor(post(urlMatching("/v2/authorityProvider/authorities/" + AUTHORITY_UUID + "/certificates/issue/attributes/validate"))
                .willReturn(okJson("true")));
        wireMockServer.stubFor(post(urlMatching("/v2/authorityProvider/authorities/" + AUTHORITY_UUID + "/certificates/revoke/attributes/validate"))
                .willReturn(okJson("true")));

        Connector connector = new Connector();
        connector.setName(CONNECTOR_NAME);
        connector.setUrl("http://localhost:" + wireMockServer.port());
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector.setVersion(ConnectorVersion.V2);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of(KIND_NAME)));
        connector2FunctionGroupRepository.save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        return connectorRepository.save(connector);
    }

    private AuthorityInstanceDto createAuthorityInstance(Connector connector) throws Exception {
        AuthorityInstanceRequestDto request = new AuthorityInstanceRequestDto();
        request.setName("testAuthority");
        request.setConnectorUuid(connector.getUuid().toString());
        request.setKind(KIND_NAME);
        request.setAttributes(List.of());
        return authorityInstanceService.createAuthorityInstance(request);
    }

    private RaProfileDto createRaProfile(AuthorityInstanceDto authorityInstance) throws Exception {
        AddRaProfileRequestDto request = new AddRaProfileRequestDto();
        request.setName(RA_PROFILE_NAME);
        request.setAttributes(List.of());
        RaProfileDto raProfile = raProfileService.addRaProfile(
                SecuredParentUUID.fromString(authorityInstance.getUuid()), request);
        raProfileService.enableRaProfile(
                SecuredParentUUID.fromString(authorityInstance.getUuid()),
                SecuredUUID.fromString(raProfile.getUuid()));
        return raProfile;
    }

    private AcmeProfileDto createAcmeProfile(RaProfileDto raProfile, AuthorityInstanceDto authorityInstance) throws Exception {
        AcmeProfileRequestDto request = new AcmeProfileRequestDto();
        request.setName(ACME_PROFILE_NAME);
        request.setRaProfileUuid(raProfile.getUuid());
        request.setDnsResolverIp("8.8.8.8");
        request.setDnsResolverPort("53");

        AcmeProfileDto acmeProfileDto = acmeProfileService.createAcmeProfile(request);
        acmeProfileService.enableAcmeProfile(SecuredUUID.fromString(acmeProfileDto.getUuid()));

        ActivateAcmeForRaProfileRequestDto activateRequest = new ActivateAcmeForRaProfileRequestDto();
        activateRequest.setIssueCertificateAttributes(List.of());
        activateRequest.setRevokeCertificateAttributes(List.of());
        raProfileService.activateAcmeForRaProfile(
                SecuredParentUUID.fromString(authorityInstance.getUuid()),
                SecuredUUID.fromString(raProfile.getUuid()),
                SecuredUUID.fromString(acmeProfileDto.getUuid()),
                activateRequest);

        return acmeProfileDto;
    }

    private RaProfileDto createSecondRaProfile(AuthorityInstanceDto authorityInstance) throws Exception {
        AddRaProfileRequestDto request = new AddRaProfileRequestDto();
        request.setName(RA_PROFILE_NAME_2);
        request.setAttributes(List.of());
        RaProfileDto raProfile = raProfileService.addRaProfile(
                SecuredParentUUID.fromString(authorityInstance.getUuid()), request);
        raProfileService.enableRaProfile(
                SecuredParentUUID.fromString(authorityInstance.getUuid()),
                SecuredUUID.fromString(raProfile.getUuid()));
        return raProfile;
    }

    // ── ACME flow helpers ─────────────────────────────────────────────────────

    private record OrderAndId(
            com.czertainly.api.model.core.acme.Order order,
            String orderId) {
    }

    /**
     * Sends {@code POST /new-account} and returns the assigned account ID.
     */
    private String createAcmeAccount() throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("termsOfServiceAgreed", true);
        payload.put("contact", List.of("mailto:admin@example.com"));

        String jws = createJws(payload, "/acme/" + ACME_PROFILE_NAME + "/new-account", null);
        ResponseEntity<Account> response = acmeService.newAccount(
                ACME_PROFILE_NAME, jws,
                new URI("/acme/" + ACME_PROFILE_NAME + "/new-account"), false);
        Assertions.assertEquals(201, response.getStatusCode().value());
        Assertions.assertNotNull(response.getHeaders().getLocation());

        String location = response.getHeaders().getLocation().toString();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    /**
     * Sends {@code POST /new-order} for {@value #DOMAIN_NAME} and returns the response.
     */
    private OrderAndId createAcmeOrder(String accountId) throws Exception {
        Map<String, Object> payload = new HashMap<>();
        Map<String, String> identifier = new HashMap<>();
        identifier.put("type", "dns");
        identifier.put("value", DOMAIN_NAME);
        payload.put("identifiers", List.of(identifier));

        String jws = createJws(payload, "/acme/" + ACME_PROFILE_NAME + "/new-order", accountId);
        ResponseEntity<com.czertainly.api.model.core.acme.Order> response = acmeService.newOrder(
                ACME_PROFILE_NAME, jws,
                new URI("/acme/" + ACME_PROFILE_NAME + "/new-order"), false);
        Assertions.assertEquals(201, response.getStatusCode().value());

        com.czertainly.api.model.core.acme.Order order = response.getBody();
        Assertions.assertNotNull(order);
        Assertions.assertNotNull(response.getHeaders().getLocation());
        String orderLocation = response.getHeaders().getLocation().toString();
        String orderId = orderLocation.substring(orderLocation.lastIndexOf('/') + 1);
        return new OrderAndId(order, orderId);
    }

    /**
     * Retrieves the authorization, finds the HTTP-01 challenge, and simulates validation
     * by directly updating entity state in the database.
     */
    private void validateChallenge(OrderAndId order, String accountId) throws Exception {
        Assertions.assertNotNull(order.order.getAuthorizations());
        String authzUrl = order.order.getAuthorizations().getFirst();
        String authzId = authzUrl.substring(authzUrl.lastIndexOf('/') + 1);

        String jws = createJws(null, "/acme/" + ACME_PROFILE_NAME + "/authz/" + authzId, accountId);
        ResponseEntity<Authorization> authzResponse = acmeService.getAuthorization(
                ACME_PROFILE_NAME, authzId, jws,
                new URI("/acme/" + ACME_PROFILE_NAME + "/authz/" + authzId), false);
        Authorization authz = authzResponse.getBody();
        Assertions.assertNotNull(authz);

        Challenge httpChallenge = authz.getChallenges().stream()
                .filter(c -> c.getType().equals(ChallengeType.HTTP01))
                .findFirst()
                .orElseThrow();
        String challengeId = httpChallenge.getUrl().substring(httpChallenge.getUrl().lastIndexOf('/') + 1);

        // Simulate successful HTTP-01 validation by directly setting the entity state.
        AcmeChallenge acmeChallenge = acmeChallengeRepository.findByChallengeId(challengeId).orElseThrow();
        AcmeAuthorization acmeAuthorization = acmeAuthorizationRepository
                .findByAuthorizationId(acmeChallenge.getAuthorization().getAuthorizationId()).orElseThrow();
        AcmeOrder acmeOrder = acmeOrderRepository.findByUuid(acmeAuthorization.getOrderUuid()).orElseThrow();

        acmeChallenge.setStatus(ChallengeStatus.VALID);
        acmeChallenge.setValidated(new Date());
        acmeAuthorization.setStatus(AuthorizationStatus.VALID);
        acmeOrder.setStatus(OrderStatus.READY);

        acmeChallengeRepository.save(acmeChallenge);
        acmeAuthorizationRepository.save(acmeAuthorization);
        acmeOrderRepository.save(acmeOrder);

        ResponseEntity<com.czertainly.api.model.core.acme.Order> updatedOrder = acmeService.getOrder(
                ACME_PROFILE_NAME, order.orderId,
                new URI("/acme/" + ACME_PROFILE_NAME + "/order/" + order.orderId), false);
        Assertions.assertNotNull(updatedOrder.getBody());
        Assertions.assertEquals(OrderStatus.READY, updatedOrder.getBody().getStatus());
    }

    /**
     * Builds a CSR and sends {@code POST /order/{id}/finalize}.
     */
    private void finalizeOrder(String orderId, String accountId) throws Exception {
        KeyPair csrKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate testCert = AcmeTestUtil.createTestCertificate(csrKeyPair, DOMAIN_NAME);
        String certData = Base64.getEncoder().encodeToString(testCert.getEncoded());
        // Mock the actual certificate issuance.
        wireMockServer.stubFor(post(urlMatching("/v2/authorityProvider/authorities/" + AUTHORITY_UUID + "/certificates/issue"))
                .willReturn(okJson("{ \"certificateData\": \"" + certData + "\" }")));

        PKCS10CertificationRequest csr = AcmeTestUtil.createCsr(csrKeyPair, DOMAIN_NAME);
        String base64Csr = Base64.getUrlEncoder().withoutPadding().encodeToString(csr.getEncoded());

        Map<String, Object> payload = new HashMap<>();
        payload.put("csr", base64Csr);

        String jws = createJws(payload, "/acme/" + ACME_PROFILE_NAME + "/order/" + orderId + "/finalize", accountId);
        ResponseEntity<com.czertainly.api.model.core.acme.Order> response = acmeService.finalizeOrder(
                ACME_PROFILE_NAME, orderId, jws,
                new URI("/acme/" + ACME_PROFILE_NAME + "/order/" + orderId + "/finalize"), false);
        Assertions.assertEquals(200, response.getStatusCode().value());
    }

    /**
     * Polls via {@link AcmeService#getOrder} (which recomputes order status from the
     * certificate state on each call) until the expected status is reached or a
     * terminal failure state is detected, failing the test if the timeout (10 s)
     * is exceeded.
     */
    private void awaitOrderStatus(String orderId, OrderStatus expected) throws Exception {
        URI orderUri = new URI("/acme/" + ACME_PROFILE_NAME + "/order/" + orderId);
        Awaitility.await("Order " + orderId + " reaches " + expected)
                .atMost(10, TimeUnit.SECONDS)
                .pollInterval(200, TimeUnit.MILLISECONDS)
                .pollInSameThread()
                .failFast("Order reached INVALID status",
                        () -> {
                            ResponseEntity<com.czertainly.api.model.core.acme.Order> r =
                                    acmeService.getOrder(ACME_PROFILE_NAME, orderId, orderUri, false);
                            return r.getBody() != null && r.getBody().getStatus() == OrderStatus.INVALID;
                        })
                .until(() -> {
                    ResponseEntity<com.czertainly.api.model.core.acme.Order> r =
                            acmeService.getOrder(ACME_PROFILE_NAME, orderId, orderUri, false);
                    return r.getBody() != null && r.getBody().getStatus() == expected;
                });
    }

    // ── JWS helper ────────────────────────────────────────────────────────────

    /**
     * Delegates to {@link AcmeTestUtil#createJwsRequest} with the shared key pair and nonce repository.
     */
    private String createJws(Object payload, String url, String accountId) throws Exception {
        return AcmeTestUtil.createJwsRequest(
                objectMapper, acmeKeyPair, acmeNonceRepository,
                payload, url, accountId, ACME_PROFILE_NAME);
    }
}
