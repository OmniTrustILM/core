package com.otilm.core.integration.service.est;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRelationId;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateRelationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.messaging.jms.listeners.ActionsListener;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.service.est.EstExternalService;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.util.AuthServiceWireMockStubs;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.EstCsrFixtures;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import com.otilm.core.util.QueuedMessageDelivery;
import com.otilm.core.util.WireMockResponseGate;
import com.otilm.core.util.builders.V3ConnectorStubs;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.mocks.AuthorityV2ConnectorStubs;
import com.otilm.core.util.seeders.EstRouteSeeder;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What a {@code /simplereenroll} through the service needs: an EST Profile that gives every certificate requested
 * through it the owner of the profile, an RA Profile whose authority has a connector double on WireMock that validates
 * every request, the CA that issues the certificates of the device, the key pair of the device, and the Auth service,
 * which the platform asks for the users that it acts as. The client presents only the certificate that it renews, as
 * the proxy forwards it.
 * <p>
 * The mocked {@link ActionProducer} hands each queued message to the real {@link ActionsListener} through
 * {@link QueuedMessageDelivery}, as the broker consumer would: the renewal or rekey that a request queues is issued
 * before the request waits for it, a failure of the consumer stays with it, and the answers of an approval wait until
 * the test delivers them.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
abstract class AbstractEstReenrollmentITest extends BaseSpringBootTest {

    protected static final String EST_PROFILE_NAME = "devices-profile";
    protected static final String RA_PROFILE_NAME = "devices-ra";
    protected static final String SUBJECT = "CN=device-1,O=Acme";
    protected static final String DNS_NAME = "device-1.example";
    protected static final UUID PROFILE_OWNER_UUID = UUID.fromString("6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f");
    protected static final String PROFILE_OWNER_NAME = "device-owner";

    private static final Duration VALIDITY = Duration.ofDays(365);
    private static final Duration PAST_HALF_OF_THE_VALIDITY = Duration.ofDays(300);

    @Autowired
    protected EstRouteSeeder routes;

    @Autowired
    protected ActionProducer actionProducer;

    @Autowired
    protected CertificateRepository certificateRepository;

    @Autowired
    protected EstProfileRepository estProfileRepository;

    @Autowired
    protected QueuedMessageDelivery delivery;

    @Autowired
    private EstExternalService estService;

    @Autowired
    private CertificateRelationRepository relationRepository;

    /** Holds the connector's answers while a test holds it, inert otherwise. */
    protected final WireMockResponseGate responseGate = new WireMockResponseGate();
    protected WireMockServer connector;
    protected Ca issuer;
    protected KeyPair deviceKeys;
    protected RaProfile raProfile;
    protected EstProfile estProfile;

    private WireMockServer authService;

    @BeforeEach
    void startServersSeedRouteAndDeliverActionsToTheListener() {
        authService = AuthServiceWireMockStubs.startImpersonating(PROFILE_OWNER_UUID, PROFILE_OWNER_NAME);
        connector = LoopbackWireMock.start(responseGate);
        AuthorityV2ConnectorStubs.on(connector).stubIssueAttributeValidation();
        raProfile = routes.seedRaProfile(connector, RA_PROFILE_NAME);
        estProfile = routes.seedEstProfileAssociatingCertificates(EST_PROFILE_NAME, raProfile, PROFILE_OWNER_UUID);
        issuer = PkiFixtures.rootCa("EST Issuing CA");
        deviceKeys = PkiFixtures.keyPair();
        delivery.deliverQueuedActions();
    }

    @AfterEach
    void stopServers() {
        authService.stop();
        connector.stop();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    protected ResponseEntity<byte[]> reenroll(byte[] request, EstClientCredentials credentials) {
        return estService.simpleReenroll(EST_PROFILE_NAME, request, credentials);
    }

    /** Has the EST Profile authenticate its enrolments by the policy, which no re-enrolment applies. */
    protected void authenticateBy(EstAuthenticationPolicy policy) {
        estProfile.setAuthenticationPolicy(policy);
        estProfile = estProfileRepository.save(estProfile);
    }

    /**
     * Moves the route to an RA Profile on a v3 authority that has the server as its connector, as a connector serves
     * one authority, and returns the RA Profile.
     *
     * @param features the feature flags that the authority advertises
     */
    protected RaProfile routeThroughV3Authority(WireMockServer v3Connector, String raProfileName,
            FeatureFlag... features) {
        V3ConnectorStubs.stubAttributesAndValidate(v3Connector);
        RaProfile v3RaProfile = routes.seedRaProfileOnV3Authority(v3Connector, raProfileName, features);
        estProfile.setRaProfile(v3RaProfile);
        estProfile = estProfileRepository.save(estProfile);
        return v3RaProfile;
    }

    /** A certificate of the device past half of its validity, so that it is due when the profile sets no threshold. */
    protected X509Certificate issueDueCertificate(KeyPair keys) {
        return issueDueCertificate(keys, SUBJECT, new GeneralName(GeneralName.dNSName, DNS_NAME));
    }

    protected X509Certificate issueDueCertificate(KeyPair keys, String subject, GeneralName... alternativeNames) {
        Instant notBefore = Instant.now().minus(PAST_HALF_OF_THE_VALIDITY);
        return PkiFixtures
                .clientCertificateFor(issuer, keys, notBefore, notBefore.plus(VALIDITY), subject, alternativeNames);
    }

    /** A certificate of the device that was issued a minute ago, as the connector renews one. */
    protected X509Certificate issueFreshCertificate(KeyPair keys) {
        Instant notBefore = Instant.now().minus(Duration.ofMinutes(1));
        return PkiFixtures
                .clientCertificateFor(issuer, keys, notBefore, notBefore.plus(VALIDITY), SUBJECT,
                        new GeneralName(GeneralName.dNSName, DNS_NAME));
    }

    /** A request for the identity of the device that carries the public key of the key pair. */
    protected static byte[] signRequest(KeyPair keys) throws Exception {
        return EstCsrFixtures.signedRequestBody(keys, SUBJECT, DNS_NAME);
    }

    protected Certificate findInInventory(X509Certificate certificate) throws Exception {
        return certificateRepository.findByFingerprint(CertificateUtil.getThumbprint(certificate)).orElseThrow();
    }

    /**
     * Every other certificate in the inventory: in a re-enrolment test, those that the source was renewed or rekeyed
     * into, whatever state they reached.
     */
    protected List<Certificate> findCertificatesBesides(Certificate source) {
        return certificateRepository
                .findAll()
                .stream()
                .filter(certificate -> !certificate.getUuid().equals(source.getUuid()))
                .toList();
    }

    protected Certificate findTheOnlyCertificateBesides(Certificate source) {
        List<Certificate> others = findCertificatesBesides(source);
        assertThat(others).hasSize(1);
        return others.getFirst();
    }

    protected void assertSuccessorOf(Certificate predecessor, Certificate successor) {
        var relation = new CertificateRelationId(successor.getUuid(), predecessor.getUuid());
        assertThat(relationRepository.existsById(relation))
                .as("certificate %s is the successor of %s", successor.getUuid(), predecessor.getUuid())
                .isTrue();
    }

    /** Reads the only certificate of the certificates-only CMS that answers an enrolment. */
    protected static X509Certificate readCertificate(ResponseEntity<byte[]> response) throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(response.getBody());
        Collection<X509CertificateHolder> held = new CMSSignedData(der).getCertificates().getMatches(null);
        assertThat(held).hasSize(1);
        return new JcaX509CertificateConverter().getCertificate(held.iterator().next());
    }
}
