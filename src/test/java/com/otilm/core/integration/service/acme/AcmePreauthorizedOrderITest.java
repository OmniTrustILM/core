package com.otilm.core.integration.service.acme;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.acme.Account;
import com.otilm.api.model.core.acme.AcmeIdentifierAuthorizationMode;
import com.otilm.api.model.core.acme.AcmeIdentifierMatchType;
import com.otilm.api.model.core.acme.AcmePreauthorizedIdentifierDto;
import com.otilm.api.model.core.acme.AuthorizationStatus;
import com.otilm.api.model.core.acme.Order;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.acme.AcmeAuthorization;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.acme.AcmeAuthorizationRepository;
import com.otilm.core.dao.repository.acme.AcmeChallengeRepository;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import com.otilm.core.service.acme.AcmeExternalService;
import com.otilm.core.service.acme.AcmeTestUtil;
import com.otilm.core.util.BaseSpringBootTest;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

/**
 * What an ACME profile's pre-authorization policy does to an order: which authorizations are created valid and carry no
 * challenge, when the order is ready at creation, and what PREAUTHORIZED_ONLY refuses.
 *
 * <p>
 * The matching itself is covered by {@code AcmeIdentifierPolicyTest}; what is pinned here is the wiring — that the
 * policy is consulted at order creation, that a covered identifier produces no challenge row, and that a refused order
 * leaves nothing behind.
 */
class AcmePreauthorizedOrderITest extends BaseSpringBootTest {

    private static final String PROFILE_NAME = "preauthProfile";
    private static final String NEW_ACCOUNT_PATH = "/acme/" + PROFILE_NAME + "/new-account";
    private static final String NEW_ORDER_PATH = "/acme/" + PROFILE_NAME + "/new-order";

    @Autowired
    private AcmeExternalService acmeService;
    @Autowired
    private AcmeProfileRepository acmeProfileRepository;
    @Autowired
    private AcmeOrderRepository acmeOrderRepository;
    @Autowired
    private AcmeAuthorizationRepository acmeAuthorizationRepository;
    @Autowired
    private AcmeChallengeRepository acmeChallengeRepository;
    @Autowired
    private AcmeNonceRepository acmeNonceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private AcmeProfile acmeProfile;
    private KeyPair accountKeyPair;
    private String accountId;

    @BeforeEach
    void setUpProfileAndAccount() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        accountKeyPair = generator.generateKeyPair();

        Connector connector = new Connector();
        connector.setVersion(ConnectorVersion.V1);
        connectorRepository.save(connector);
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setConnectorUuid(connector.getUuid());
        authorityInstanceReferenceRepository.save(authority);
        RaProfile raProfile = new RaProfile();
        raProfile.setName("preauthRaProfile");
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReference(authority);
        raProfileRepository.save(raProfile);

        acmeProfile = new AcmeProfile();
        acmeProfile.setName(PROFILE_NAME);
        acmeProfile.setEnabled(true);
        acmeProfile.setDisableNewOrders(false);
        acmeProfile.setRaProfile(raProfile);
        acmeProfile.setRetryInterval(30);
        acmeProfile.setValidity(3600);
        acmeProfileRepository.save(acmeProfile);

        accountId = registerAccount();
    }

    @Test
    void aCoveredIdentifierIsAuthorizedAtCreationWithNoChallenge() throws Exception {
        policy(entry("apps.example.com", AcmeIdentifierMatchType.SUBDOMAIN, false));

        Order order = newOrder("web.apps.example.com").getBody();

        Assertions.assertEquals(OrderStatus.READY, order.getStatus(), "nothing is left to prove");
        Assertions.assertEquals(OrderStatus.READY, storedOrder().getStatus());
        AcmeAuthorization authorization = onlyAuthorization();
        Assertions.assertEquals(AuthorizationStatus.VALID, authorization.getStatus());
        Assertions.assertEquals(0, challengeCount(authorization), "a valid authorization has nothing to answer");
    }

    @Test
    void anUncoveredIdentifierKeepsTheUsualChallenges() throws Exception {
        policy(entry("apps.example.com", AcmeIdentifierMatchType.SUBDOMAIN, false));

        Order order = newOrder("other.example.com").getBody();

        Assertions.assertEquals(OrderStatus.PENDING, order.getStatus());
        AcmeAuthorization authorization = onlyAuthorization();
        Assertions.assertEquals(AuthorizationStatus.PENDING, authorization.getStatus());
        Assertions.assertEquals(2, challengeCount(authorization), "http-01 and dns-01, exactly as today");
    }

    @Test
    void anOrderMixingCoveredAndUncoveredIsNotReady() throws Exception {
        policy(entry("apps.example.com", AcmeIdentifierMatchType.SUBDOMAIN, false));

        Order order = newOrder("web.apps.example.com", "other.example.com").getBody();

        Assertions.assertEquals(OrderStatus.PENDING, order.getStatus(), "one identifier is still unproven");
        List<AcmeAuthorization> authorizations = acmeAuthorizationRepository.findAll();
        Assertions.assertEquals(2, authorizations.size());
        Assertions.assertEquals(1, authorizations.stream().filter(this::isValidWithNoChallenge).count());
        Assertions
                .assertEquals(1,
                        authorizations
                                .stream()
                                .filter(a -> a.getStatus() == AuthorizationStatus.PENDING && challengeCount(a) == 2)
                                .count());
    }

    @Test
    void aProfileWithNoPolicyBehavesExactlyAsBefore() throws Exception {
        Order order = newOrder("anything.example.com").getBody();

        Assertions.assertEquals(OrderStatus.PENDING, order.getStatus());
        Assertions.assertEquals(2, challengeCount(onlyAuthorization()));
    }

    @Test
    void preauthorizedOnlyRefusesAnUncoveredIdentifierAndWritesNothing() throws Exception {
        policy(AcmeIdentifierAuthorizationMode.PREAUTHORIZED_ONLY,
                entry("apps.example.com", AcmeIdentifierMatchType.SUBDOMAIN, false));

        AcmeProblemDocumentException e = Assertions
                .assertThrows(AcmeProblemDocumentException.class, () -> newOrder("other.example.com"));

        Assertions.assertEquals(403, e.getHttpStatusCode());
        Assertions.assertEquals("urn:ietf:params:acme:error:rejectedIdentifier", e.getProblemDocument().getType());
        Assertions.assertTrue(acmeOrderRepository.findAll().isEmpty(), "a refused order must leave no rows");
    }

    @Test
    void preauthorizedOnlyStillIssuesForACoveredIdentifier() throws Exception {
        policy(AcmeIdentifierAuthorizationMode.PREAUTHORIZED_ONLY,
                entry("apps.example.com", AcmeIdentifierMatchType.SUBDOMAIN, false));

        Assertions.assertEquals(OrderStatus.READY, newOrder("web.apps.example.com").getBody().getStatus());
    }

    @Test
    void preauthorizedOnlyRefusesAnOrderMixingCoveredAndUncovered() throws Exception {
        policy(AcmeIdentifierAuthorizationMode.PREAUTHORIZED_ONLY,
                entry("apps.example.com", AcmeIdentifierMatchType.SUBDOMAIN, false));

        AcmeProblemDocumentException e = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> newOrder("web.apps.example.com", "other.example.com"));

        Assertions.assertEquals(403, e.getHttpStatusCode());
        Assertions.assertTrue(acmeOrderRepository.findAll().isEmpty());
    }

    @Test
    void anOrderNamingNoIdentifierIsMalformedRatherThanAnInternalError() throws Exception {
        String jws = AcmeTestUtil
                .createJwsRequest(objectMapper, accountKeyPair, acmeNonceRepository, Map.of(), NEW_ORDER_PATH,
                        accountId, PROFILE_NAME);

        AcmeProblemDocumentException e = Assertions
                .assertThrows(AcmeProblemDocumentException.class,
                        () -> acmeService.newOrder(PROFILE_NAME, jws, URI.create(NEW_ORDER_PATH), false));

        Assertions.assertEquals(400, e.getHttpStatusCode());
        Assertions.assertEquals("urn:ietf:params:acme:error:malformed", e.getProblemDocument().getType());
    }

    private boolean isValidWithNoChallenge(AcmeAuthorization authorization) {
        return authorization.getStatus() == AuthorizationStatus.VALID && challengeCount(authorization) == 0;
    }

    /** Read as rows rather than through the order's lazy collection, which has no session outside the service. */
    private AcmeAuthorization onlyAuthorization() {
        List<AcmeAuthorization> authorizations = acmeAuthorizationRepository.findAll();
        Assertions.assertEquals(1, authorizations.size(), "exactly one authorization is expected");
        return authorizations.getFirst();
    }

    private long challengeCount(AcmeAuthorization authorization) {
        return acmeChallengeRepository
                .findAll()
                .stream()
                .filter(challenge -> authorization.getUuid().equals(challenge.getAuthorizationUuid()))
                .count();
    }

    private void policy(AcmePreauthorizedIdentifierDto... entries) {
        policy(AcmeIdentifierAuthorizationMode.PREAUTHORIZED_OR_CHALLENGE, entries);
    }

    private void policy(AcmeIdentifierAuthorizationMode mode, AcmePreauthorizedIdentifierDto... entries) {
        acmeProfile.setPreauthorizedIdentifiers(List.of(entries));
        acmeProfile.setIdentifierAuthorizationMode(mode);
        acmeProfileRepository.save(acmeProfile);
    }

    private static AcmePreauthorizedIdentifierDto entry(String value, AcmeIdentifierMatchType matchType,
            boolean allowWildcard) {
        AcmePreauthorizedIdentifierDto entry = new AcmePreauthorizedIdentifierDto();
        entry.setValue(value);
        entry.setMatchType(matchType);
        entry.setAllowWildcard(allowWildcard);
        return entry;
    }

    private AcmeOrder storedOrder() {
        List<AcmeOrder> orders = acmeOrderRepository.findAll();
        Assertions.assertEquals(1, orders.size(), "exactly one order is expected");
        return orders.getFirst();
    }

    private ResponseEntity<Order> newOrder(String... dnsValues) throws Exception {
        List<Map<String, String>> identifiers = List
                .of(dnsValues)
                .stream()
                .map(value -> Map.of("type", "dns", "value", value))
                .toList();
        Map<String, Object> payload = new HashMap<>();
        payload.put("identifiers", identifiers);

        String jws = AcmeTestUtil
                .createJwsRequest(objectMapper, accountKeyPair, acmeNonceRepository, payload, NEW_ORDER_PATH, accountId,
                        PROFILE_NAME);
        return acmeService.newOrder(PROFILE_NAME, jws, URI.create(NEW_ORDER_PATH), false);
    }

    private String registerAccount() throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("termsOfServiceAgreed", true);
        String jws = AcmeTestUtil
                .createJwsRequest(objectMapper, accountKeyPair, acmeNonceRepository, payload, NEW_ACCOUNT_PATH, null,
                        PROFILE_NAME);
        ResponseEntity<Account> response = acmeService
                .newAccount(PROFILE_NAME, jws, URI.create(NEW_ACCOUNT_PATH), false);
        String location = response.getHeaders().getLocation().toString();
        return location.substring(location.lastIndexOf('/') + 1);
    }
}
