package com.otilm.core.integration.service.acme;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.model.core.acme.Account;
import com.otilm.api.model.core.acme.AcmeIdentifierAuthorizationMode;
import com.otilm.api.model.core.acme.AcmeIdentifierMatchType;
import com.otilm.api.model.core.acme.AcmeIdentifierType;
import com.otilm.api.model.core.acme.AcmePreauthorizedIdentifierDto;
import com.otilm.api.model.core.acme.Order;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.api.model.core.certificate.CertificateRelationType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.CertificateRelation;
import com.otilm.core.dao.entity.CertificateRelationId;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.acme.AcmeAccountRepository;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.model.ActionMessage;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.acme.AcmeExternalService;
import com.otilm.core.service.acme.AcmeTestUtil;
import com.otilm.core.service.acme.AriCertId;
import com.otilm.core.service.renewal.RenewalWindowWriter;
import com.otilm.core.service.renewal.Window;
import com.otilm.core.service.renewal.WindowWrite;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.mockbeans.ProducerMocks;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

/**
 * The {@code replaces} member of a new order (RFC 9773): checked and kept on a profile that serves renewal information,
 * ignored on one that does not, and turned into a renewal or rekey of the replaced certificate on finalize. The action
 * producer is a mock, so the requested certificate stays queued until a test issues it.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class AcmeReplacesITest extends BaseSpringBootTest {

    private static final String PROFILE_NAME = "replacesProfile";
    private static final String NEW_ACCOUNT_PATH = "/acme/" + PROFILE_NAME + "/new-account";
    private static final String NEW_ORDER_PATH = "/acme/" + PROFILE_NAME + "/new-order";
    private static final String ISSUER_DN = "CN=Replaces Test CA";
    private static final String DOMAIN = "replaced.example.com";

    private static final AtomicLong SERIALS = new AtomicLong(0x5000);

    @Autowired
    private AcmeExternalService acmeService;
    @Autowired
    private CertificateInternalService certificateService;
    @Autowired
    private RenewalWindowWriter renewalWindowWriter;
    @Autowired
    private ActionProducer actionProducer;
    @Autowired
    private EventProducer eventProducer;
    @Autowired
    private AcmeProfileRepository acmeProfileRepository;
    @Autowired
    private AcmeAccountRepository acmeAccountRepository;
    @Autowired
    private AcmeOrderRepository acmeOrderRepository;
    @Autowired
    private AcmeNonceRepository acmeNonceRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateRelationRepository certificateRelationRepository;
    @Autowired
    private CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private EntityManagerFactory entityManagerFactory;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private WireMockServer connector;
    private RaProfile raProfile;
    private AcmeProfile acmeProfile;
    private KeyPair issuerKeys;
    private KeyPair ownerKeys;
    private KeyPair otherKeys;
    private String ownerAccountId;
    private String otherAccountId;
    private KeyPair predecessorKeys;
    private Certificate predecessor;

    @BeforeEach
    void seedProfileAccountsAndPredecessor() throws Exception {
        connector = startAuthorityConnector();
        raProfile = AuthorityFixtures
                .v2Authority(new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                        connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                        connectorInterfaceRepository), connector, "ApiKey")
                .raProfile();
        acmeProfile = seedAcmeProfile();
        issuerKeys = generateKeyPair("EC", 256);
        ownerKeys = generateKeyPair("RSA", 2048);
        otherKeys = generateKeyPair("RSA", 2048);
        ownerAccountId = registerAccount(ownerKeys);
        otherAccountId = registerAccount(otherKeys);
        predecessorKeys = generateKeyPair("RSA", 2048);
        predecessor = seedOrderedCertificate(ownerAccountId, predecessorKeys, DOMAIN);
    }

    @AfterEach
    void stopConnector() {
        connector.stop();
    }

    @Test
    void ignoresReplaces_whenTheProfileDoesNotServeRenewalInformation() throws Exception {
        // given
        acmeProfile.setRenewalInfoEnabled(false);
        acmeProfileRepository.save(acmeProfile);
        var notEvenWellFormed = "not a certificate identifier";

        // when
        Order order = newOrder(ownerKeys, ownerAccountId, notEvenWellFormed, DOMAIN).getBody();

        // then
        assertThat(order.getReplaces()).isNull();
        AcmeOrder stored = storedOrder(order);
        assertThat(stored.getReplacesCertId()).isNull();
        assertThat(stored.getReplacesCertificateUuid()).isNull();
    }

    @Test
    void reflectsReplaces_whenTheProfileServesRenewalInformation() throws Exception {
        // given
        String certId = idOf(predecessor);

        // when
        Order order = newOrder(ownerKeys, ownerAccountId, certId, DOMAIN).getBody();

        // then
        assertThat(order.getReplaces()).isEqualTo(certId);
        AcmeOrder stored = storedOrder(order);
        assertThat(stored.getReplacesCertId()).isEqualTo(certId);
        assertThat(stored.getReplacesCertificateUuid()).isEqualTo(predecessor.getUuid());
    }

    @Test
    void otherAccountAndUnknownAnswerIdentically() throws Exception {
        // given
        String ownersCertificate = idOf(predecessor);
        String unknownCertificate = AriCertId.of(certificate(predecessorKeys, DOMAIN));

        // when
        AcmeProblemDocumentException otherAccount = refusal(
                () -> newOrder(otherKeys, otherAccountId, ownersCertificate, DOMAIN));
        AcmeProblemDocumentException unknown = refusal(
                () -> newOrder(otherKeys, otherAccountId, unknownCertificate, DOMAIN));

        // then
        assertThat(otherAccount.getHttpStatusCode()).isEqualTo(400);
        assertThat(otherAccount.getProblemDocument().getType()).isEqualTo(Problem.MALFORMED.getType());
        assertThat(otherAccount.getHttpStatusCode()).isEqualTo(unknown.getHttpStatusCode());
        assertThat(objectMapper.writeValueAsString(otherAccount.getProblemDocument()))
                .isEqualTo(objectMapper.writeValueAsString(unknown.getProblemDocument()));
    }

    @Test
    void answersTheSameMalformed_whenTheIdentifierIsMalformedOrNoIdentifierIsShared() throws Exception {
        // given
        String ownersCertificate = idOf(predecessor);
        String unknownCertificate = AriCertId.of(certificate(predecessorKeys, DOMAIN));
        AcmeProblemDocumentException unknown = refusal(
                () -> newOrder(ownerKeys, ownerAccountId, unknownCertificate, DOMAIN));

        // when
        AcmeProblemDocumentException malformed = refusal(
                () -> newOrder(ownerKeys, ownerAccountId, "AQ+D.AQID", DOMAIN));
        AcmeProblemDocumentException noSharedIdentifier = refusal(
                () -> newOrder(ownerKeys, ownerAccountId, ownersCertificate, "elsewhere.example.com"));

        // then
        String expected = objectMapper.writeValueAsString(unknown.getProblemDocument());
        assertThat(objectMapper.writeValueAsString(malformed.getProblemDocument())).isEqualTo(expected);
        assertThat(objectMapper.writeValueAsString(noSharedIdentifier.getProblemDocument())).isEqualTo(expected);
        assertThat(noSharedIdentifier.getHttpStatusCode()).isEqualTo(400);
    }

    @Test
    void answersAlreadyReplaced_whenALiveOrderOfAnotherAccountReplacesTheCertificate() throws Exception {
        // given
        AcmeOrder othersOrder = new AcmeOrder();
        othersOrder.setOrderId("othersLiveOrder");
        othersOrder.setStatus(OrderStatus.PENDING);
        othersOrder.setAcmeAccount(account(otherAccountId));
        othersOrder.setReplacesCertificateUuid(predecessor.getUuid());
        acmeOrderRepository.save(othersOrder);
        String certId = idOf(predecessor);

        // when
        ThrowingCallable order = () -> newOrder(ownerKeys, ownerAccountId, certId, DOMAIN);

        // then
        assertAlreadyReplaced(order);
    }

    @Test
    void acceptsReplaces_whenTheOnlyOrderReplacingTheCertificateHasExpired() throws Exception {
        // given
        seedOrderReplacingPredecessor(OrderStatus.PENDING, new Date(System.currentTimeMillis() - 60_000));
        String certId = idOf(predecessor);

        // when
        Order order = newOrder(ownerKeys, ownerAccountId, certId, DOMAIN).getBody();

        // then
        assertThat(order.getReplaces()).isEqualTo(certId);
    }

    @Test
    void acceptsReplaces_whenTheOnlyOrderReplacingTheCertificateIsInvalid() throws Exception {
        // given
        seedOrderReplacingPredecessor(OrderStatus.INVALID, null);
        String certId = idOf(predecessor);

        // when
        Order order = newOrder(ownerKeys, ownerAccountId, certId, DOMAIN).getBody();

        // then
        assertThat(order.getReplaces()).isEqualTo(certId);
    }

    @Test
    void answersAlreadyReplaced_whenTheCertificateHasAnIssuedSuccessor() throws Exception {
        // given
        Certificate successor = seedOrderedCertificate(ownerAccountId, predecessorKeys, DOMAIN);
        seedRelation(predecessor, successor);
        String certId = idOf(predecessor);

        // when
        ThrowingCallable order = () -> newOrder(ownerKeys, ownerAccountId, certId, DOMAIN);

        // then
        assertAlreadyReplaced(order);
    }

    @Test
    void renewsThePredecessor_whenTheCsrKeepsItsKey() throws Exception {
        // given
        Order order = newOrder(ownerKeys, ownerAccountId, idOf(predecessor), DOMAIN).getBody();

        // when
        UUID successorUuid = finalizeAndIssue(order, predecessorKeys);

        // then
        assertThat(queuedAction()).isEqualTo(ResourceAction.RENEW);
        assertThat(relationType(successorUuid)).isEqualTo(CertificateRelationType.RENEWAL);
    }

    @Test
    void rekeysThePredecessor_whenTheCsrBringsANewKey() throws Exception {
        // given
        Order order = newOrder(ownerKeys, ownerAccountId, idOf(predecessor), DOMAIN).getBody();

        // when
        UUID successorUuid = finalizeAndIssue(order, generateKeyPair("RSA", 2048));

        // then
        assertThat(queuedAction()).isEqualTo(ResourceAction.REKEY);
        assertThat(relationType(successorUuid)).isEqualTo(CertificateRelationType.REKEY);
    }

    @Test
    void issuesAndRelatesTheSuccessor_whenThePredecessorCannotBeRenewed() throws Exception {
        // given
        Order order = newOrder(ownerKeys, ownerAccountId, idOf(predecessor), DOMAIN).getBody();
        Certificate archived = certificateRepository.findByUuid(predecessor.getUuid()).orElseThrow();
        archived.setArchived(true);
        certificateRepository.save(archived);

        // when
        UUID successorUuid = finalizeAndIssue(order, predecessorKeys);

        // then
        assertThat(queuedAction()).isEqualTo(ResourceAction.ISSUE);
        assertThat(relationType(successorUuid)).isEqualTo(CertificateRelationType.RENEWAL);
    }

    @Test
    void issuesAndRelatesTheSuccessor_whenANewKeyComesWithAnotherSubject() throws Exception {
        // given
        Certificate legacySubject = seedOrderedCertificate(ownerAccountId, predecessorKeys, "O=Legacy,CN=" + DOMAIN,
                DOMAIN);
        Order order = newOrder(ownerKeys, ownerAccountId, idOf(legacySubject), DOMAIN).getBody();

        // when
        UUID successorUuid = finalizeAndIssue(order, generateKeyPair("RSA", 2048));

        // then
        assertThat(queuedAction()).isEqualTo(ResourceAction.ISSUE);
        assertThat(relationType(legacySubject.getUuid(), successorUuid)).isEqualTo(CertificateRelationType.REPLACEMENT);
    }

    @Test
    void issuesAndRelatesTheSuccessor_whenThePredecessorRequiresItsRegistrationChallenge() throws Exception {
        // given
        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(predecessor.getUuid());
        authorization.setChallenge("not presented by ACME");
        authorization.setState(RegistrationState.ACTIVE);
        registrationAuthorizationRepository.save(authorization);
        Order order = newOrder(ownerKeys, ownerAccountId, idOf(predecessor), DOMAIN).getBody();

        // when
        UUID successorUuid = finalizeAndIssue(order, predecessorKeys);

        // then
        assertThat(queuedAction()).isEqualTo(ResourceAction.ISSUE);
        assertThat(relationType(successorUuid)).isEqualTo(CertificateRelationType.RENEWAL);
    }

    @Test
    void issuesWithoutRelation_whenThePredecessorIsNoLongerIssued() throws Exception {
        // given
        Order order = newOrder(ownerKeys, ownerAccountId, idOf(predecessor), DOMAIN).getBody();
        Certificate revoking = certificateRepository.findByUuid(predecessor.getUuid()).orElseThrow();
        revoking.setState(CertificateState.PENDING_REVOKE);
        certificateRepository.save(revoking);

        // when
        UUID successorUuid = finalize(order, predecessorKeys);

        // then
        assertThat(queuedAction()).isEqualTo(ResourceAction.ISSUE);
        assertThat(
                certificateRelationRepository.findById(new CertificateRelationId(successorUuid, predecessor.getUuid())))
                .isEmpty();
    }

    @Test
    void leavesThePredecessorIssuedAndQuiet_onceItsRenewalIsIssued() throws Exception {
        // given
        Certificate expiring = certificateRepository.findByUuid(predecessor.getUuid()).orElseThrow();
        expiring.setValidationStatus(CertificateValidationStatus.EXPIRING);
        certificateRepository.save(expiring);
        Instant windowStart = Instant.now().minus(Duration.ofDays(1));
        renewalWindowWriter
                .write(predecessor.getUuid(),
                        new WindowWrite.Forced(new Window(windowStart, windowStart.plus(Duration.ofDays(10))), null));
        Certificate notRenewed = seedOrderedCertificate(otherAccountId, generateKeyPair("RSA", 2048),
                "sibling.example.com");
        notRenewed.setValidationStatus(CertificateValidationStatus.EXPIRING);
        certificateRepository.save(notRenewed);
        renewalWindowWriter
                .write(notRenewed.getUuid(),
                        new WindowWrite.Forced(new Window(windowStart, windowStart.plus(Duration.ofDays(10))), null));
        Order order = newOrder(ownerKeys, ownerAccountId, idOf(predecessor), DOMAIN).getBody();
        finalizeAndIssue(order, predecessorKeys);
        reset(eventProducer);

        // when
        certificateService.handleExpiringCertificates();
        certificateService.handleRenewalDueCertificates();

        // then
        assertThat(certificateRepository.findByUuid(predecessor.getUuid()).orElseThrow().getState())
                .isEqualTo(CertificateState.ISSUED);
        List<EventMessage> events = producedEvents();
        assertThat(events).noneMatch(event -> predecessor.getUuid().equals(event.getObjectUuid()));
        assertThat(events)
                .filteredOn(event -> notRenewed.getUuid().equals(event.getObjectUuid()))
                .extracting(EventMessage::getEvent)
                .containsExactlyInAnyOrder(ResourceEvent.CERTIFICATE_EXPIRING, ResourceEvent.CERTIFICATE_RENEWAL_DUE);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static WireMockServer startAuthorityConnector() {
        WireMockServer server = LoopbackWireMock.start();
        server
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/.*/validate"))
                        .willReturn(WireMock.okJson("true")));
        server
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v2/authorityProvider/authorities/[^/]+/.*/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        return server;
    }

    private AcmeProfile seedAcmeProfile() {
        AcmePreauthorizedIdentifierDto examples = new AcmePreauthorizedIdentifierDto();
        examples.setType(AcmeIdentifierType.DNS);
        examples.setValue("example.com");
        examples.setMatchType(AcmeIdentifierMatchType.SUBDOMAIN);
        AcmeProfile profile = new AcmeProfile();
        profile.setName(PROFILE_NAME);
        profile.setEnabled(true);
        profile.setDisableNewOrders(false);
        profile.setRaProfile(raProfile);
        profile.setRetryInterval(30);
        profile.setValidity(3600);
        profile.setRenewalInfoEnabled(true);
        profile.setPreauthorizedIdentifiers(List.of(examples));
        profile.setIdentifierAuthorizationMode(AcmeIdentifierAuthorizationMode.PREAUTHORIZED_OR_CHALLENGE);
        profile = acmeProfileRepository.save(profile);
        raProfile.setAcmeProfile(profile);
        raProfileRepository.save(raProfile);
        return profile;
    }

    private String registerAccount(KeyPair accountKeys) throws Exception {
        Map<String, Object> payload = Map.of("termsOfServiceAgreed", true);
        String jws = AcmeTestUtil
                .createJwsRequest(objectMapper, accountKeys, acmeNonceRepository, payload, NEW_ACCOUNT_PATH, null,
                        PROFILE_NAME);
        ResponseEntity<Account> response = acmeService
                .newAccount(PROFILE_NAME, jws, URI.create(NEW_ACCOUNT_PATH), false);
        String location = response.getHeaders().getLocation().toString();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private AcmeAccount account(String accountId) {
        return acmeAccountRepository.findByAccountId(accountId).orElseThrow();
    }

    /** An issued certificate of the RA profile that the account ordered, as a completed order records it. */
    private Certificate seedOrderedCertificate(String accountId, KeyPair subjectKeys, String domain) throws Exception {
        return seedOrderedCertificate(accountId, subjectKeys, "CN=" + domain, domain);
    }

    private Certificate seedOrderedCertificate(String accountId, KeyPair subjectKeys, String subjectDn, String domain)
            throws Exception {
        String content = Base64.getEncoder().encodeToString(certificate(subjectKeys, subjectDn, domain).getEncoded());
        Certificate certificate = certificateService.createCertificate(content, CertificateType.X509);
        certificate.setRaProfile(raProfile);
        certificate.setRaProfileUuid(raProfile.getUuid());
        certificate.setState(CertificateState.ISSUED);
        certificate = certificateRepository.save(certificate);

        AcmeOrder order = new AcmeOrder();
        order.setOrderId("completed-" + certificate.getSerialNumber());
        order.setStatus(OrderStatus.VALID);
        order.setAcmeAccount(account(accountId));
        order.setCertificateReference(certificate);
        acmeOrderRepository.save(order);
        return certificate;
    }

    private X509Certificate certificate(KeyPair subjectKeys, String domain) throws Exception {
        return certificate(subjectKeys, "CN=" + domain, domain);
    }

    private X509Certificate certificate(KeyPair subjectKeys, String subjectDn, String domain) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + Duration.ofDays(30).toMillis());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(ISSUER_DN),
                BigInteger.valueOf(SERIALS.incrementAndGet()), notBefore, notAfter, new X500Name(subjectDn),
                subjectKeys.getPublic());
        builder
                .addExtension(Extension.authorityKeyIdentifier, false,
                        new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuerKeys.getPublic()));
        builder
                .addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, domain)));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate())));
    }

    private void seedOrderReplacingPredecessor(OrderStatus status, Date expires) {
        AcmeOrder othersOrder = new AcmeOrder();
        othersOrder.setOrderId("othersOrder-" + status.name());
        othersOrder.setStatus(status);
        othersOrder.setExpires(expires);
        othersOrder.setAcmeAccount(account(otherAccountId));
        othersOrder.setReplacesCertificateUuid(predecessor.getUuid());
        acmeOrderRepository.save(othersOrder);
    }

    private void seedRelation(Certificate predecessorCertificate, Certificate successor) {
        CertificateRelation relation = new CertificateRelation();
        relation.getId().setPredecessorCertificateUuid(predecessorCertificate.getUuid());
        relation.getId().setSuccessorCertificateUuid(successor.getUuid());
        relation.setPredecessorCertificate(predecessorCertificate);
        relation.setSuccessorCertificate(successor);
        relation.setRelationType(CertificateRelationType.RENEWAL);
        certificateRelationRepository.save(relation);
    }

    private ResponseEntity<Order> newOrder(KeyPair accountKeys, String accountId, String replaces, String domain)
            throws Exception {
        Map<String, Object> payload = new HashMap<>();
        payload.put("identifiers", List.of(Map.of("type", "dns", "value", domain)));
        payload.put("replaces", replaces);
        String jws = AcmeTestUtil
                .createJwsRequest(objectMapper, accountKeys, acmeNonceRepository, payload, NEW_ORDER_PATH, accountId,
                        PROFILE_NAME);
        return acmeService.newOrder(PROFILE_NAME, jws, URI.create(NEW_ORDER_PATH), false);
    }

    private AcmeOrder storedOrder(Order order) {
        String finalizeUrl = order.getFinalize();
        String withoutSuffix = finalizeUrl.substring(0, finalizeUrl.length() - "/finalize".length());
        String orderId = withoutSuffix.substring(withoutSuffix.lastIndexOf('/') + 1);
        return acmeOrderRepository.findByOrderId(orderId).orElseThrow();
    }

    /**
     * Sends the finalize request as one HTTP request does, with the servlet request in context and an EntityManager
     * bound to the thread, and returns the certificate the order requested.
     */
    private UUID finalize(Order order, KeyPair csrKeys) throws Exception {
        String orderId = storedOrder(order).getOrderId();
        String finalizePath = "/acme/" + PROFILE_NAME + "/order/" + orderId + "/finalize";
        PKCS10CertificationRequest csr = AcmeTestUtil.createCsr(csrKeys, DOMAIN);
        Map<String, Object> payload = Map
                .of("csr", Base64.getUrlEncoder().withoutPadding().encodeToString(csr.getEncoded()));
        String jws = AcmeTestUtil
                .createJwsRequest(objectMapper, ownerKeys, acmeNonceRepository, payload, finalizePath, ownerAccountId,
                        PROFILE_NAME);

        RequestContextHolder
                .setRequestAttributes(new ServletRequestAttributes(
                        new MockHttpServletRequest("POST", "/v1/protocols" + finalizePath)));
        EntityManager requestEntityManager = entityManagerFactory.createEntityManager();
        TransactionSynchronizationManager
                .bindResource(entityManagerFactory, new EntityManagerHolder(requestEntityManager));
        try {
            Order finalized = acmeService
                    .finalizeOrder(PROFILE_NAME, orderId, jws, new URI(finalizePath), false)
                    .getBody();
            assertThat(finalized.getStatus()).isEqualTo(OrderStatus.PROCESSING);
        } finally {
            TransactionSynchronizationManager.unbindResource(entityManagerFactory);
            requestEntityManager.close();
            RequestContextHolder.resetRequestAttributes();
        }
        return acmeOrderRepository.findByOrderId(orderId).orElseThrow().getCertificateReferenceUuid();
    }

    /** Finalizes the order and issues its certificate, as the queued action does once the authority answers. */
    private UUID finalizeAndIssue(Order order, KeyPair csrKeys) throws Exception {
        UUID successorUuid = finalize(order, csrKeys);
        Certificate successor = certificateRepository.findByUuid(successorUuid).orElseThrow();
        successor.setState(CertificateState.PENDING_ISSUE);
        certificateRepository.save(successor);
        String issued = Base64.getEncoder().encodeToString(certificate(csrKeys, DOMAIN).getEncoded());
        certificateService.issueRequestedCertificate(successorUuid, issued, List.of());
        return successorUuid;
    }

    private ResourceAction queuedAction() {
        ArgumentCaptor<ActionMessage> captor = ArgumentCaptor.forClass(ActionMessage.class);
        verify(actionProducer).produceMessage(captor.capture());
        return captor.getValue().getResourceAction();
    }

    private CertificateRelationType relationType(UUID successorUuid) {
        return relationType(predecessor.getUuid(), successorUuid);
    }

    private CertificateRelationType relationType(UUID predecessorUuid, UUID successorUuid) {
        return certificateRelationRepository
                .findById(new CertificateRelationId(successorUuid, predecessorUuid))
                .orElseThrow()
                .getRelationType();
    }

    private List<EventMessage> producedEvents() {
        ArgumentCaptor<EventMessage> captor = ArgumentCaptor.forClass(EventMessage.class);
        verify(eventProducer, atLeast(0)).produceMessage(captor.capture());
        return captor.getAllValues();
    }

    private String idOf(Certificate certificate) throws Exception {
        return AriCertId
                .of(com.otilm.core.util.CertificateUtil
                        .getX509Certificate(certificateRepository
                                .findByUuid(certificate.getUuid())
                                .orElseThrow()
                                .getContentData()));
    }

    private static AcmeProblemDocumentException refusal(ThrowingCallable newOrder) {
        try {
            newOrder.call();
        } catch (AcmeProblemDocumentException e) {
            return e;
        } catch (Throwable e) {
            throw new AssertionError("Expected an ACME problem", e);
        }
        throw new AssertionError("Expected the order to be refused");
    }

    private static void assertAlreadyReplaced(ThrowingCallable newOrder) {
        assertThatThrownBy(newOrder).isInstanceOfSatisfying(AcmeProblemDocumentException.class, e -> {
            assertThat(e.getHttpStatusCode()).isEqualTo(409);
            assertThat(e.getProblemDocument().getType()).isEqualTo(Problem.ALREADY_REPLACED.getType());
        });
    }

    private static KeyPair generateKeyPair(String algorithm, int size) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(size);
        return generator.generateKeyPair();
    }
}
