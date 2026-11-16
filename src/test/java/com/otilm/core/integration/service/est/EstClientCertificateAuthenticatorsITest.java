package com.otilm.core.integration.service.est;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClient;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.authentication.RaMtlsAuthenticator;
import com.otilm.core.service.est.authentication.VendorMtlsAuthenticator;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.PkiFixtures.Ca;
import com.otilm.core.util.seeders.EstRouteSeeder;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.EstClientCredentialsFixtures.certificateCredentials;
import static com.otilm.core.util.EstCsrFixtures.decodedRequest;
import static com.otilm.core.util.EstCsrFixtures.decodedRequestWithNames;
import static com.otilm.core.util.PkiFixtures.CLIENT_SUBJECT;
import static com.otilm.core.util.PkiFixtures.clientCertificate;
import static com.otilm.core.util.PkiFixtures.clientCertificateFor;
import static com.otilm.core.util.PkiFixtures.intermediateCa;
import static com.otilm.core.util.PkiFixtures.raCertificate;
import static com.otilm.core.util.PkiFixtures.rootCa;
import static com.otilm.core.util.PkiFixtures.selfSignedClientCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;

/**
 * The authentication policies that rest on a client certificate, beside the trust check they share. Every certificate
 * here is issued under a root that the EST Profile trusts and names no revocation source.
 */
class EstClientCertificateAuthenticatorsITest extends BaseSpringBootTest {

    private static final String LABEL = "devices";
    private static final String PROFILE_NAME = "devices-profile";
    private static final String SUBJECT = "CN=device-1,O=Acme";
    private static final String DNS_NAME = "device-1.example";
    private static final String OTHER_DNS_NAME = "device-2.example";
    private static final String IP_ADDRESS = "192.168.1.1";
    private static final String OTHER_IP_ADDRESS = "192.168.1.2";
    private static final String EMAIL_ADDRESS = "device@example.com";
    private static final String OTHER_EMAIL_ADDRESS = "other@example.com";

    @Autowired
    private VendorMtlsAuthenticator vendorAuthenticator;

    @Autowired
    private RaMtlsAuthenticator raAuthenticator;

    @Autowired
    private EstRouteSeeder routes;

    private Ca issuingCa;
    private Certificate trustedRoot;

    @BeforeEach
    void trustTheRootOfThePki() {
        Ca root = rootCa("EST Root CA");
        issuingCa = intermediateCa(root, "EST Issuing CA");
        trustedRoot = routes.seedCertificate(root.certificate());
    }

    // ── VendorMtls ────────────────────────────────────────────────────────────

    @Nested
    class VendorMtls {

        @Test
        void authenticatesAsCertificate_whenRequestAsksForItsIdentity() throws Exception {
            // given
            X509Certificate leaf = clientCertificateFor(issuingCa, SUBJECT, dnsName(DNS_NAME));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            CertificateRequest csr = decodedRequest(SUBJECT, DNS_NAME);
            EstRoute route = routeOf(EstAuthenticationPolicy.VENDOR_MTLS);

            // when
            EstClient client = vendorAuthenticator.authenticate(route, credentials, csr);

            // then
            String thumbprint = CertificateUtil.getThumbprint(leaf);
            assertThat(client)
                    .isEqualTo(new EstClient(EstAuthenticationPolicy.VENDOR_MTLS, "certificate:" + thumbprint, null));
        }

        @Test
        void authenticates_whenCertificateHasNoRaUsage() throws Exception {
            // given
            X509Certificate leafWithoutRaUsage = clientCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(leafWithoutRaUsage, issuingCa.certificate());
            CertificateRequest csr = decodedRequest(CLIENT_SUBJECT);
            EstRoute route = routeOf(EstAuthenticationPolicy.VENDOR_MTLS);

            // when
            EstClient client = vendorAuthenticator.authenticate(route, credentials, csr);

            // then
            assertThat(client.policy()).isEqualTo(EstAuthenticationPolicy.VENDOR_MTLS);
        }

        @ParameterizedTest
        @MethodSource("identitiesThatAreTheSame")
        void authenticates_whenRequestAsksForTheSameIdentity(Identity ofTheCertificate, Identity ofTheRequest)
                throws Exception {
            // given
            X509Certificate leaf = certificateOf(ofTheCertificate);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            CertificateRequest csr = requestOf(ofTheRequest);
            EstRoute route = routeOf(EstAuthenticationPolicy.VENDOR_MTLS);

            // when
            EstClient client = vendorAuthenticator.authenticate(route, credentials, csr);

            // then
            assertThat(client.policy()).isEqualTo(EstAuthenticationPolicy.VENDOR_MTLS);
        }

        @ParameterizedTest
        @MethodSource("identitiesThatDiffer")
        void throwsIdentityMismatchWithTheRealm_whenRequestAsksForAnotherIdentity(Identity ofTheCertificate,
                Identity ofTheRequest) throws Exception {
            // given
            X509Certificate leaf = certificateOf(ofTheCertificate);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            CertificateRequest csr = requestOf(ofTheRequest);
            EstRoute route = routeOf(EstAuthenticationPolicy.VENDOR_MTLS);

            // when
            ThrowingCallable authenticate = () -> vendorAuthenticator.authenticate(route, credentials, csr);

            // then
            assertThatThrownBy(authenticate)
                    .satisfies(thrown -> assertRefusedWithTheRealm(thrown, EstError.IDENTITY_MISMATCH));
        }

        @Test
        void throwsCertificateRejectedWithTheRealm_whenCertificateIsNotTrusted() throws Exception {
            // given
            X509Certificate certificateOfNoTrustedCa = selfSignedClientCertificate();
            EstClientCredentials credentials = certificateCredentials(certificateOfNoTrustedCa);
            CertificateRequest csr = decodedRequest(CLIENT_SUBJECT);
            EstRoute route = routeOf(EstAuthenticationPolicy.VENDOR_MTLS);

            // when
            ThrowingCallable authenticate = () -> vendorAuthenticator.authenticate(route, credentials, csr);

            // then
            assertThatThrownBy(authenticate)
                    .satisfies(thrown -> assertRefusedWithTheRealm(thrown, EstError.CERTIFICATE_REJECTED));
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> identitiesThatAreTheSame() {
            Identity commaInAValue = identity("CN=device-1,O=Acme\\, Inc.");
            Identity plusInAValue = identity("CN=a\\+b");
            Identity quoteInAValue = identity("CN=say \\\"hi\\\"");
            Identity backslashInAValue = identity("CN=a\\\\b");
            Identity leadingSpaceInAValue = identity("CN=\\ device");
            Identity trailingSpaceInAValue = identity("CN=device\\ ");
            Identity leadingHashInAValue = identity("CN=\\#device");
            Identity ipv4Identity = identity(SUBJECT, ipAddress(IP_ADDRESS));
            Identity emailIdentity = identity(SUBJECT, emailAddress(EMAIL_ADDRESS));
            return Stream
                    .of(argumentSet("subject names in another order", identity("CN=device-1,O=Acme"),
                            identity("O=Acme,CN=device-1")),
                            argumentSet("DNS names in another letter case",
                                    identity(CLIENT_SUBJECT, dnsName("Device-1.Example")),
                                    identity(CLIENT_SUBJECT, dnsName("device-1.example"))),
                            argumentSet("DNS names in another order",
                                    identity(CLIENT_SUBJECT, dnsName(DNS_NAME), dnsName(OTHER_DNS_NAME)),
                                    identity(CLIENT_SUBJECT, dnsName(OTHER_DNS_NAME), dnsName(DNS_NAME))),
                            argumentSet("the same IPv4 address", ipv4Identity, ipv4Identity),
                            argumentSet("the same e-mail address", emailIdentity, emailIdentity),
                            argumentSet("a comma in a subject value", commaInAValue, commaInAValue),
                            argumentSet("a plus sign in a subject value", plusInAValue, plusInAValue),
                            argumentSet("a quote in a subject value", quoteInAValue, quoteInAValue),
                            argumentSet("a backslash in a subject value", backslashInAValue, backslashInAValue),
                            argumentSet("a leading space in a subject value", leadingSpaceInAValue,
                                    leadingSpaceInAValue),
                            argumentSet("a trailing space in a subject value", trailingSpaceInAValue,
                                    trailingSpaceInAValue),
                            argumentSet("a leading hash in a subject value", leadingHashInAValue, leadingHashInAValue));
        }

        static Stream<Arguments> identitiesThatDiffer() {
            return Stream
                    .of(argumentSet("another subject", identity("CN=device-1"), identity("CN=device-2")),
                            argumentSet("a subject value in another letter case", identity("CN=Device-1"),
                                    identity("CN=device-1")),
                            argumentSet("a subject with one more name", identity("CN=device-1"),
                                    identity("CN=device-1,O=Acme")),
                            argumentSet("a subject value with a comma against its first part", identity("CN=a\\,b"),
                                    identity("CN=a")),
                            argumentSet("one name that holds a second name against the two names",
                                    identity("CN=x\\,O\\=y"), identity("CN=x,O=y")),
                            argumentSet("two names against one name that holds a second name", identity("CN=x,O=y"),
                                    identity("CN=x\\,O\\=y")),
                            argumentSet("a DNS name that only the certificate has",
                                    identity(SUBJECT, dnsName(DNS_NAME)), identity(SUBJECT)),
                            argumentSet("a DNS name that only the request asks for", identity(SUBJECT),
                                    identity(SUBJECT, dnsName(DNS_NAME))),
                            argumentSet("another DNS name", identity(SUBJECT, dnsName(DNS_NAME)),
                                    identity(SUBJECT, dnsName(OTHER_DNS_NAME))),
                            argumentSet("one more DNS name in the request", identity(SUBJECT, dnsName(DNS_NAME)),
                                    identity(SUBJECT, dnsName(DNS_NAME), dnsName(OTHER_DNS_NAME))),
                            argumentSet("another IPv4 address", identity(SUBJECT, ipAddress(IP_ADDRESS)),
                                    identity(SUBJECT, ipAddress(OTHER_IP_ADDRESS))),
                            argumentSet("another e-mail address", identity(SUBJECT, emailAddress(EMAIL_ADDRESS)),
                                    identity(SUBJECT, emailAddress(OTHER_EMAIL_ADDRESS))));
        }
    }

    // ── RaMtls ────────────────────────────────────────────────────────────────

    @Nested
    class RaMtls {

        @Test
        void authenticatesAsCertificate_whenCertificateCarriesTheRaUsage() throws Exception {
            // given
            X509Certificate raLeaf = raCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(raLeaf, issuingCa.certificate());
            CertificateRequest csr = decodedRequest(SUBJECT);
            EstRoute route = routeOf(EstAuthenticationPolicy.RA_MTLS);

            // when
            EstClient client = raAuthenticator.authenticate(route, credentials, csr);

            // then
            String thumbprint = CertificateUtil.getThumbprint(raLeaf);
            assertThat(client)
                    .isEqualTo(new EstClient(EstAuthenticationPolicy.RA_MTLS, "certificate:" + thumbprint, null));
        }

        @Test
        void authenticates_whenRequestAsksForAnotherIdentityThanTheCertificate() throws Exception {
            // given
            X509Certificate raLeaf = raCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(raLeaf, issuingCa.certificate());
            CertificateRequest csrOfAnotherIdentity = decodedRequest(SUBJECT, DNS_NAME);
            EstRoute route = routeOf(EstAuthenticationPolicy.RA_MTLS);

            // when
            EstClient client = raAuthenticator.authenticate(route, credentials, csrOfAnotherIdentity);

            // then
            assertThat(client.policy()).isEqualTo(EstAuthenticationPolicy.RA_MTLS);
        }

        @Test
        void throwsCertificateRejectedWithTheRealm_whenCertificateLacksTheRaUsage() throws Exception {
            // given
            X509Certificate leafWithoutRaUsage = clientCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(leafWithoutRaUsage, issuingCa.certificate());
            CertificateRequest csr = decodedRequest(CLIENT_SUBJECT);
            EstRoute route = routeOf(EstAuthenticationPolicy.RA_MTLS);

            // when
            ThrowingCallable authenticate = () -> raAuthenticator.authenticate(route, credentials, csr);

            // then
            assertThatThrownBy(authenticate)
                    .satisfies(thrown -> assertRefusedWithTheRealm(thrown, EstError.CERTIFICATE_REJECTED));
        }
    }

    // ── Logging ───────────────────────────────────────────────────────────────

    @Nested
    class Logging {

        private final ListAppender<ILoggingEvent> logged = new ListAppender<>();

        /** The logger is a process-wide singleton, so what is set on it here is taken off again after each test. */
        @BeforeEach
        void captureTheVendorAuthenticatorLog() {
            logged.start();
            Logger logger = (Logger) LoggerFactory.getLogger(VendorMtlsAuthenticator.class);
            logger.setLevel(Level.DEBUG);
            logger.addAppender(logged);
        }

        @AfterEach
        void releaseTheVendorAuthenticatorLog() {
            Logger logger = (Logger) LoggerFactory.getLogger(VendorMtlsAuthenticator.class);
            logger.detachAppender(logged);
            logger.setLevel(null);
            logged.stop();
        }

        @Test
        void logsTheRefusalOnlyAtDebug_whenRequestAsksForAnotherIdentity() throws Exception {
            // given
            X509Certificate leaf = clientCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            CertificateRequest csrOfAnotherSubject = decodedRequest("CN=another device");
            EstRoute route = routeOf(EstAuthenticationPolicy.VENDOR_MTLS);

            // when
            ThrowingCallable authenticate = () -> vendorAuthenticator
                    .authenticate(route, credentials, csrOfAnotherSubject);

            // then
            assertThatThrownBy(authenticate).isInstanceOf(EstException.class);
            assertThat(logged.list)
                    .isNotEmpty()
                    .allSatisfy(event -> assertThat(event.getLevel()).isEqualTo(Level.DEBUG));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * What a certificate or a certification request names: its subject, written as {@code X500Name} reads it, and its
     * subject alternative names.
     */
    private record Identity(String subject, List<GeneralName> names) {
    }

    private static Identity identity(String subject, GeneralName... names) {
        return new Identity(subject, List.of(names));
    }

    private static GeneralName dnsName(String name) {
        return new GeneralName(GeneralName.dNSName, name);
    }

    private static GeneralName ipAddress(String address) {
        return new GeneralName(GeneralName.iPAddress, address);
    }

    private static GeneralName emailAddress(String address) {
        return new GeneralName(GeneralName.rfc822Name, address);
    }

    private X509Certificate certificateOf(Identity identity) {
        return clientCertificateFor(issuingCa, identity.subject(), identity.names().toArray(GeneralName[]::new));
    }

    private static CertificateRequest requestOf(Identity identity) throws Exception {
        return decodedRequestWithNames(identity.subject(), identity.names().toArray(GeneralName[]::new));
    }

    private EstRoute routeOf(EstAuthenticationPolicy policy) {
        EstProfile estProfile = routes.seedEstProfile(PROFILE_NAME, policy, null, List.of(), List.of(trustedRoot));
        return new EstRoute(estProfile, null, false, LABEL);
    }

    private static void assertRefusedWithTheRealm(Throwable thrown, EstError expected) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(expected);
            assertThat(refusal.realm()).contains(LABEL);
        });
    }
}
