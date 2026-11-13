package com.otilm.core.integration.service.est;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.CrlService;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.authentication.EstClientCertificateTrust;
import com.otilm.core.service.est.authentication.EstClientCredentials;
import com.otilm.core.service.est.authentication.EstRevocationCheck;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures.Ca;
import com.otilm.core.util.PkiFixtures.RevocationSources;
import com.otilm.core.util.SecretLeakProbe;
import com.otilm.core.util.seeders.EstRouteSeeder;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.util.ReflectionTestUtils;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.otilm.core.util.EstClientCredentialsFixtures.certificateCredentials;
import static com.otilm.core.util.EstClientCredentialsFixtures.malformedCertificateCredentials;
import static com.otilm.core.util.EstClientCredentialsFixtures.noCredentials;
import static com.otilm.core.util.PkiFixtures.CRL_NUMBER;
import static com.otilm.core.util.PkiFixtures.certificateWithoutExtendedKeyUsage;
import static com.otilm.core.util.PkiFixtures.clientCertificate;
import static com.otilm.core.util.PkiFixtures.clientCertificateWithAuthorityInfoAccess;
import static com.otilm.core.util.PkiFixtures.crl;
import static com.otilm.core.util.PkiFixtures.crlExpiredFor;
import static com.otilm.core.util.PkiFixtures.deltaCrl;
import static com.otilm.core.util.PkiFixtures.deltaCrlExpiredFor;
import static com.otilm.core.util.PkiFixtures.endEntityIssuer;
import static com.otilm.core.util.PkiFixtures.expiredClientCertificate;
import static com.otilm.core.util.PkiFixtures.expiredCrl;
import static com.otilm.core.util.PkiFixtures.expiredDeltaCrl;
import static com.otilm.core.util.PkiFixtures.expiredIntermediateCa;
import static com.otilm.core.util.PkiFixtures.intermediateCa;
import static com.otilm.core.util.PkiFixtures.keyPair;
import static com.otilm.core.util.PkiFixtures.ocspRequest;
import static com.otilm.core.util.PkiFixtures.raCertificate;
import static com.otilm.core.util.PkiFixtures.rootCa;
import static com.otilm.core.util.PkiFixtures.selfSignedClientCertificate;
import static com.otilm.core.util.PkiFixtures.serverCertificate;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static com.otilm.core.util.builders.OcspResponseBuilder.anOcspResponse;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class EstClientCertificateTrustITest extends BaseSpringBootTest {

    private static final String LABEL = "devices";
    private static final String PROFILE_NAME = "vendor-devices";
    private static final String ROOT_CA_NAME = "EST Root CA";
    private static final String ISSUING_CA_NAME = "EST Issuing CA";
    private static final String OCSP_PATH = "/issuing-ca/ocsp";
    private static final String CRL_PATH = "/issuing-ca.crl";
    private static final String ROOT_CRL_PATH = "/root-ca.crl";
    private static final String DELTA_CRL_PATH = "/issuing-ca-delta.crl";
    private static final String CA_ISSUERS_PATH = "/issuing-ca.crt";
    private static final String UNREADABLE_CONTENT = Base64
            .getEncoder()
            .encodeToString("not a certificate".getBytes(StandardCharsets.US_ASCII));

    @RegisterExtension
    static WireMockExtension revocationSources = WireMockExtension
            .newInstance()
            .options(LoopbackWireMock.options())
            .build();

    @Autowired
    private EstClientCertificateTrust trust;

    @Autowired
    private EstRouteSeeder routes;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private EstRevocationCheck revocationCheck;

    private Ca root;
    private Ca issuingCa;
    private Certificate storedRoot;

    @BeforeEach
    void createPkiAndStoreItsRoot() {
        root = rootCa(ROOT_CA_NAME);
        issuingCa = intermediateCa(root, ISSUING_CA_NAME);
        storedRoot = routes.seedCertificate(root.certificate());
    }

    // ── PathToATrustedCa ──────────────────────────────────────────────────────

    @Nested
    class PathToATrustedCa {

        @Test
        void returnsLeaf_whenChainLeadsToTrustedRoot() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa);
            EstClientCredentials leafWithItsChain = certificateCredentials(leaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), leafWithItsChain, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void returnsLeaf_whenProfileTrustsTheIntermediate() {
            // given
            Certificate storedIssuingCa = routes.seedCertificate(issuingCa.certificate());
            X509Certificate leaf = clientCertificate(issuingCa);
            EstClientCredentials onlyTheLeaf = certificateCredentials(leaf);

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedIssuingCa), onlyTheLeaf, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void throwsCertificateRejected_whenIntermediateIsNeitherSentNorTrusted() {
            // given
            // the inventory knows the issuing CA, yet the path may only be completed from what the client sent
            routes.seedCertificate(issuingCa.certificate());
            EstClientCredentials onlyTheLeaf = certificateCredentials(clientCertificate(issuingCa));
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, onlyTheLeaf, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsCertificateRejected_whenChainLeadsToAnUntrustedRootOfTheSameName() {
            // given
            Ca rogueRoot = rootCa(ROOT_CA_NAME);
            Ca rogueIssuingCa = intermediateCa(rogueRoot, ISSUING_CA_NAME);
            EstClientCredentials leafWithRogueChain = certificateCredentials(clientCertificate(rogueIssuingCa),
                    rogueIssuingCa.certificate(), rogueRoot.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, leafWithRogueChain, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsCertificateRejected_whenLeafIsExpired() {
            // given
            X509Certificate expiredLeaf = expiredClientCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(expiredLeaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsCertificateRejected_whenIntermediateIsExpired() {
            // given
            Ca expiredIssuingCa = expiredIntermediateCa(root, ISSUING_CA_NAME);
            EstClientCredentials credentials = certificateCredentials(clientCertificate(expiredIssuingCa),
                    expiredIssuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsCertificateRejected_whenAnEndEntityIssuedTheLeaf() {
            // given
            Ca endEntityIssuer = endEntityIssuer(root, ISSUING_CA_NAME);
            EstClientCredentials credentials = certificateCredentials(clientCertificate(endEntityIssuer),
                    endEntityIssuer.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsCertificateRejected_whenEkuLacksClientAuth() {
            // given
            X509Certificate serverLeaf = serverCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(serverLeaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void returnsLeaf_whenLeafHasNoEkuExtension() {
            // given
            X509Certificate leafForEveryPurpose = certificateWithoutExtendedKeyUsage(issuingCa);
            EstClientCredentials credentials = certificateCredentials(leafForEveryPurpose, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leafForEveryPurpose);
        }

        @Test
        void throwsCertificateRejected_whenRaUsageIsRequiredAndMissing() {
            // given
            X509Certificate clientLeaf = clientCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(clientLeaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, true);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsCertificateRejected_whenRaUsageIsRequiredAndLeafHasNoEkuExtension() {
            // given
            X509Certificate leafForEveryPurpose = certificateWithoutExtendedKeyUsage(issuingCa);
            EstClientCredentials credentials = certificateCredentials(leafForEveryPurpose, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, true);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void returnsLeaf_whenRaUsageIsRequiredAndPresent() {
            // given
            X509Certificate raLeaf = raCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(raLeaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, true);

            // then
            assertThat(verified).isEqualTo(raLeaf);
        }

        @Test
        void throwsCertificateRejected_whenProfileTrustsOnlyEndEntityCertificates() {
            // given
            X509Certificate pinnedClientCertificate = selfSignedClientCertificate();
            EstRoute route = buildRouteTrusting(routes.seedCertificate(pinnedClientCertificate));
            EstClientCredentials credentials = certificateCredentials(pinnedClientCertificate);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsCertificateRejected_whenProfileTrustsNoCertificate() {
            // given
            // deleting a certificate from the inventory takes it off every trust list, which can leave one empty
            EstRoute routeTrustingNothing = buildRouteTrusting();
            EstClientCredentials credentials = certificateCredentials(clientCertificate(issuingCa),
                    issuingCa.certificate());

            // when
            ThrowingCallable verify = () -> trust.verify(routeTrustingNothing, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void returnsLeaf_whenAnotherTrustedCertificateCannotBeRead() {
            // given
            Certificate unreadable = corruptContentOf(
                    routes.seedCertificate(rootCa("EST Retired Root CA").certificate()));
            X509Certificate leaf = clientCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(unreadable, storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void throwsCertificateRejected_whenTheOnlyTrustedCertificateCannotBeRead() {
            // given
            EstRoute route = buildRouteTrusting(corruptContentOf(storedRoot));
            EstClientCredentials credentials = certificateCredentials(clientCertificate(issuingCa),
                    issuingCa.certificate());

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @ParameterizedTest
        @MethodSource("revocationMarks")
        void throwsCertificateRejected_whenTheInventoryMarksTheOnlyTrustedCertificateRevoked(
                Consumer<Certificate> revocationMark) {
            // given
            EstRoute route = buildRouteTrusting(markedInTheInventory(storedRoot, revocationMark));
            EstClientCredentials credentials = certificateCredentials(clientCertificate(issuingCa),
                    issuingCa.certificate());

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsCertificateRejected_whenNoCertificateIsPresented() {
            // given
            EstClientCredentials withoutCertificate = noCredentials();
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, withoutCertificate, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsCertificateRejected_whenCertificateHeaderIsMalformed() {
            // given
            EstClientCredentials malformed = malformedCertificateCredentials();
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, malformed, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void returnsLeaf_whenChainCarriesTwoCertificatesOfOneSubject() {
            // given
            Ca renewedIssuingCa = intermediateCa(root, ISSUING_CA_NAME);
            X509Certificate leaf = clientCertificate(renewedIssuingCa);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate(),
                    renewedIssuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void throwsCertificateRejected_whenChainCarriesThreeCertificatesOfOneSubject() {
            // given
            Ca renewedIssuingCa = intermediateCa(root, ISSUING_CA_NAME);
            Ca renewedAgainIssuingCa = intermediateCa(root, ISSUING_CA_NAME);
            X509Certificate leaf = clientCertificate(issuingCa);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate(),
                    renewedIssuingCa.certificate(), renewedAgainIssuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> revocationMarks() {
            Consumer<Certificate> revoked = certificate -> certificate.setState(CertificateState.REVOKED);
            Consumer<Certificate> validatedAsRevoked = certificate -> certificate
                    .setValidationStatus(CertificateValidationStatus.REVOKED);
            return Stream
                    .of(arguments(named("in the revoked state", revoked)),
                            arguments(named("validated as revoked", validatedAsRevoked)));
        }
    }

    // ── Revocation ────────────────────────────────────────────────────────────

    @Nested
    class Revocation {

        @Test
        void throwsCertificateRejected_whenOcspReportsRevoked() throws Exception {
            // given
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.ocsp(resolveUrl(OCSP_PATH)));
            serveOcspStatus(leaf, new RevokedStatus(new Date(), CRLReason.keyCompromise));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void returnsLeaf_whenOcspReportsGood() throws Exception {
            // given
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.ocsp(resolveUrl(OCSP_PATH)));
            serveOcspStatus(leaf, CertificateStatus.GOOD);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void throwsCertificateRejected_whenCrlListsTheLeaf() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.crl(resolveUrl(CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa, leaf));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsCertificateRejected_whenCrlListsTheIntermediate() {
            // given
            Ca revokedIssuingCa = intermediateCa(root, ISSUING_CA_NAME,
                    RevocationSources.crl(resolveUrl(ROOT_CRL_PATH)));
            serveCrl(ROOT_CRL_PATH, crl(root, revokedIssuingCa.certificate()));
            X509Certificate leaf = clientCertificate(revokedIssuingCa);
            EstClientCredentials credentials = certificateCredentials(leaf, revokedIssuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void returnsLeaf_whenOcspCannotBeReachedAndCrlDoesNotListTheLeaf() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.ocspAndCrl(resolveUrl(OCSP_PATH), resolveUrl(CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void throwsServiceUnavailable_whenNamedOcspCannotBeReachedAndNoCrlIsNamed() {
            // given
            // nothing answers at the OCSP path
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.ocsp(resolveUrl(OCSP_PATH)));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void throwsServiceUnavailable_whenNamedOcspAndCrlCannotBeReached() {
            // given
            // nothing answers at the OCSP path or at the CRL path
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.ocspAndCrl(resolveUrl(OCSP_PATH), resolveUrl(CRL_PATH)));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void throwsCertificateRejected_whenOcspAnswerIsForgedAndCrlListsTheLeaf() throws Exception {
            // given
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.ocspAndCrl(resolveUrl(OCSP_PATH), resolveUrl(CRL_PATH)));
            KeyPair forgerKeyPair = keyPair();
            serveOcspResponse(anOcspResponse(ocspRequest(leaf, issuingCa.certificate()), forgerKeyPair).build());
            serveCrl(CRL_PATH, crl(issuingCa, leaf));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsServiceUnavailable_whenNamedCrlCannotBeReached() {
            // given
            // nothing answers at the CRL path
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.crl(resolveUrl(CRL_PATH)));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void throwsServiceUnavailable_whenCrlDistributionPointNamesNoUri() {
            // given
            var directoryOnly = RevocationSources.crlInDirectory("CN=EST Issuing CA CRL,O=EST Directory");
            X509Certificate leaf = clientCertificate(issuingCa, directoryOnly);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void throwsServiceUnavailable_whenDeltaCrlNeedsNewerBaseCrl() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.crlAndDeltaCrl(resolveUrl(CRL_PATH), resolveUrl(DELTA_CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa));
            BigInteger unpublishedBaseCrlNumber = CRL_NUMBER.add(BigInteger.ONE);
            serveCrl(DELTA_CRL_PATH, deltaCrl(issuingCa, unpublishedBaseCrlNumber));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void throwsCertificateRejected_whenOcspReportsUnknownAndCrlListsTheLeaf() throws Exception {
            // given
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.ocspAndCrl(resolveUrl(OCSP_PATH), resolveUrl(CRL_PATH)));
            serveOcspStatus(leaf, new UnknownStatus());
            serveCrl(CRL_PATH, crl(issuingCa, leaf));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void returnsLeaf_whenCertificatesCarryNoRevocationInformation() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.NONE);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void returnsLeaf_whenAuthorityInformationNamesOnlyTheIssuersCertificate() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.onlyCaIssuers(resolveUrl(CA_ISSUERS_PATH)));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void returnsLeaf_whenCrlAndDeltaCrlAreCurrentAndListNeitherCertificate() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.crlAndDeltaCrl(resolveUrl(CRL_PATH), resolveUrl(DELTA_CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa));
            serveCrl(DELTA_CRL_PATH, deltaCrl(issuingCa, CRL_NUMBER));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void throwsServiceUnavailable_whenCrlIsNoLongerCurrent() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.crl(resolveUrl(CRL_PATH)));
            serveCrl(CRL_PATH, expiredCrl(issuingCa));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void returnsLeaf_whenCrlWentStaleWithinTheClockSkew() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.crl(resolveUrl(CRL_PATH)));
            serveCrl(CRL_PATH, crlExpiredFor(issuingCa, Duration.ofMinutes(1)));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void throwsServiceUnavailable_whenCrlWentStaleBeyondTheClockSkew() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.crl(resolveUrl(CRL_PATH)));
            serveCrl(CRL_PATH, crlExpiredFor(issuingCa, Duration.ofMinutes(6)));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void returnsLeaf_whenDeltaCrlWentStaleWithinTheClockSkew() {
            // given — the base CRL is current
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.crlAndDeltaCrl(resolveUrl(CRL_PATH), resolveUrl(DELTA_CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa));
            serveCrl(DELTA_CRL_PATH, deltaCrlExpiredFor(issuingCa, CRL_NUMBER, Duration.ofMinutes(1)));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @Test
        void throwsServiceUnavailable_whenDeltaCrlWentStaleBeyondTheClockSkew() {
            // given — the base CRL is current
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.crlAndDeltaCrl(resolveUrl(CRL_PATH), resolveUrl(DELTA_CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa));
            serveCrl(DELTA_CRL_PATH, deltaCrlExpiredFor(issuingCa, CRL_NUMBER, Duration.ofMinutes(6)));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void throwsCertificateRejected_whenCrlListsTheLeafAndTheNamedDeltaCrlIsMissing() {
            // given — nothing answers at the delta CRL path
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.crlAndDeltaCrl(resolveUrl(CRL_PATH), resolveUrl(DELTA_CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa, leaf));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @Test
        void throwsServiceUnavailable_whenTheCrlIsGoneByTheTimeItsStateIsRead() throws Exception {
            // given — the CRL service names a CRL that is no longer stored
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.crlInDirectory("CN=EST CRL,O=EST Directory"));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);
            CrlService realCrlService = (CrlService) ReflectionTestUtils.getField(revocationCheck, "crlService");
            CrlService namingAGoneCrl = mock(CrlService.class);
            doReturn(UUID.randomUUID()).when(namingAGoneCrl).getCurrentCrl(any(), any());
            ReflectionTestUtils.setField(revocationCheck, "crlService", namingAGoneCrl);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            try {
                assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
            } finally {
                ReflectionTestUtils.setField(revocationCheck, "crlService", realCrlService);
            }
        }

        @Test
        void throwsServiceUnavailable_whenNamedDeltaCrlCannotBeReached() {
            // given — the CRL is current, and nothing answers at the delta CRL path
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.crlAndDeltaCrl(resolveUrl(CRL_PATH), resolveUrl(DELTA_CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void throwsServiceUnavailable_whenDeltaCrlIsNoLongerCurrent() {
            // given
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.crlAndDeltaCrl(resolveUrl(CRL_PATH), resolveUrl(DELTA_CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa));
            serveCrl(DELTA_CRL_PATH, expiredDeltaCrl(issuingCa, CRL_NUMBER));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void throwsServiceUnavailable_whenOnlyADeltaCrlIsNamed() {
            // given — a delta CRL answers, but the certificate names no CRL that it updates
            X509Certificate leaf = clientCertificate(issuingCa,
                    RevocationSources.onlyDeltaCrl(resolveUrl(DELTA_CRL_PATH)));
            serveCrl(DELTA_CRL_PATH, deltaCrl(issuingCa, CRL_NUMBER));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @Test
        void throwsServiceUnavailable_whenOcspResponderIsNamedWithoutAUri() {
            // given
            var directoryOnly = RevocationSources.ocspInDirectory("CN=EST Issuing CA OCSP,O=EST Directory");
            X509Certificate leaf = clientCertificate(issuingCa, directoryOnly);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @ParameterizedTest
        @MethodSource("unreadableAuthorityInfoAccessValues")
        void throwsServiceUnavailable_whenAuthorityInformationAccessCannotBeRead(ASN1Encodable unreadableValue) {
            // given — the certificate names no CRL distribution point
            X509Certificate leaf = clientCertificateWithAuthorityInfoAccess(issuingCa, unreadableValue);
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        @ParameterizedTest
        @MethodSource("unreadableAuthorityInfoAccessValues")
        void returnsLeaf_whenAuthorityInformationAccessCannotBeReadAndCrlDoesNotListTheLeaf(
                ASN1Encodable unreadableValue) {
            // given
            X509Certificate leaf = clientCertificateWithAuthorityInfoAccess(issuingCa, unreadableValue,
                    RevocationSources.crl(resolveUrl(CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());

            // when
            X509Certificate verified = trust.verify(buildRouteTrusting(storedRoot), credentials, false);

            // then
            assertThat(verified).isEqualTo(leaf);
        }

        @ParameterizedTest
        @MethodSource("unreadableAuthorityInfoAccessValues")
        void throwsCertificateRejected_whenAuthorityInformationAccessCannotBeReadAndCrlListsTheLeaf(
                ASN1Encodable unreadableValue) {
            // given
            X509Certificate leaf = clientCertificateWithAuthorityInfoAccess(issuingCa, unreadableValue,
                    RevocationSources.crl(resolveUrl(CRL_PATH)));
            serveCrl(CRL_PATH, crl(issuingCa, leaf));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertCertificateRejected);
        }

        @ParameterizedTest
        @MethodSource("unreadableAuthorityInfoAccessValues")
        void throwsServiceUnavailable_whenAuthorityInformationAccessCannotBeReadAndNamedCrlCannotBeReached(
                ASN1Encodable unreadableValue) {
            // given
            // nothing answers at the CRL path
            X509Certificate leaf = clientCertificateWithAuthorityInfoAccess(issuingCa, unreadableValue,
                    RevocationSources.crl(resolveUrl(CRL_PATH)));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).satisfies(EstClientCertificateTrustITest::assertServiceUnavailable);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> unreadableAuthorityInfoAccessValues() {
            var explicitlyTaggedLocation = new DERTaggedObject(true, GeneralName.uniformResourceIdentifier,
                    new DERIA5String("http://ocsp.example"));
            var ocspAtAnExplicitlyTaggedLocation = new DERSequence(
                    new DERSequence(new ASN1Encodable[]{AccessDescription.id_ad_ocsp, explicitlyTaggedLocation}));
            return Stream
                    .of(arguments(
                            named("an OCTET STRING where a SEQUENCE belongs", new DEROctetString(new byte[]{1, 2, 3}))),
                            arguments(named("an empty SEQUENCE", new DERSequence())),
                            arguments(named("a SEQUENCE of a number, which is no access description",
                                    new DERSequence(new ASN1Integer(1)))),
                            arguments(named("an OCSP location that is tagged explicitly, where the tag is implicit",
                                    ocspAtAnExplicitlyTaggedLocation)));
        }
    }

    // ── Logging ───────────────────────────────────────────────────────────────

    @Nested
    class Logging {

        private static final List<Class<?>> TRUST_CLASSES = List
                .of(EstClientCertificateTrust.class, EstRevocationCheck.class);

        private final ListAppender<ILoggingEvent> logged = new ListAppender<>();

        /** The loggers are process-wide singletons, so what is set on them here is taken off again after each test. */
        @BeforeEach
        void captureTheTrustLogs() {
            logged.start();
            for (Class<?> source : TRUST_CLASSES) {
                Logger logger = (Logger) LoggerFactory.getLogger(source);
                logger.setLevel(Level.DEBUG);
                logger.addAppender(logged);
            }
        }

        @AfterEach
        void releaseTheTrustLogs() {
            for (Class<?> source : TRUST_CLASSES) {
                Logger logger = (Logger) LoggerFactory.getLogger(source);
                logger.detachAppender(logged);
                logger.setLevel(null);
            }
            logged.stop();
        }

        @Test
        void logsTheRefusalOnlyAtDebug_whenOcspReportsRevoked() throws Exception {
            // given
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.ocsp(resolveUrl(OCSP_PATH)));
            serveOcspStatus(leaf, new RevokedStatus(new Date(), CRLReason.keyCompromise));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).isInstanceOf(EstException.class);
            assertThat(logged.list)
                    .isNotEmpty()
                    .allSatisfy(event -> assertThat(event.getLevel()).isEqualTo(Level.DEBUG));
        }

        @Test
        void logsNoCertificateContent_whenOcspReportsRevoked() throws Exception {
            // given
            X509Certificate leaf = clientCertificate(issuingCa, RevocationSources.ocsp(resolveUrl(OCSP_PATH)));
            serveOcspStatus(leaf, new RevokedStatus(new Date(), CRLReason.keyCompromise));
            EstClientCredentials credentials = certificateCredentials(leaf, issuingCa.certificate());
            EstRoute route = buildRouteTrusting(storedRoot);

            try (SecretLeakProbe probe = SecretLeakProbe.capture()) {
                // when
                ThrowingCallable verify = () -> trust.verify(route, credentials, false);

                // then
                assertThatThrownBy(verify).isInstanceOf(EstException.class);
                SecretLeakProbe
                        .assertNoneReveals(probe.logged(), encodeBase64(leaf), encodeBase64(issuingCa.certificate()));
            }
        }

        @Test
        void logsAWarningNamingTheProfile_whenProfileTrustsNoUsableCaCertificate() {
            // given
            EstRoute route = buildRouteTrusting(routes.seedCertificate(selfSignedClientCertificate()));
            EstClientCredentials credentials = certificateCredentials(clientCertificate(issuingCa),
                    issuingCa.certificate());

            // when
            ThrowingCallable verify = () -> trust.verify(route, credentials, false);

            // then
            assertThatThrownBy(verify).isInstanceOf(EstException.class);
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.WARN)
                    .singleElement()
                    .satisfies(warning -> assertThat(warning.getFormattedMessage()).contains(PROFILE_NAME));
        }

        @Test
        void logsAWarningNamingProfileAndCertificate_whenTrustedCertificateCannotBeRead() {
            // given
            Certificate unreadable = corruptContentOf(
                    routes.seedCertificate(rootCa("EST Retired Root CA").certificate()));
            EstRoute route = buildRouteTrusting(unreadable, storedRoot);
            EstClientCredentials credentials = certificateCredentials(clientCertificate(issuingCa),
                    issuingCa.certificate());

            // when
            trust.verify(route, credentials, false);

            // then
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.WARN)
                    .singleElement()
                    .satisfies(warning -> assertThat(warning.getFormattedMessage())
                            .contains(PROFILE_NAME, unreadable.getUuid().toString()));
        }

        @Test
        void logsAWarningNamingProfileAndCertificate_whenTheInventoryMarksATrustedCertificateRevoked() {
            // given
            Certificate revoked = markedInTheInventory(
                    routes.seedCertificate(rootCa("EST Retired Root CA").certificate()),
                    certificate -> certificate.setState(CertificateState.REVOKED));
            EstRoute route = buildRouteTrusting(revoked, storedRoot);
            EstClientCredentials credentials = certificateCredentials(clientCertificate(issuingCa),
                    issuingCa.certificate());

            // when
            trust.verify(route, credentials, false);

            // then
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.WARN)
                    .singleElement()
                    .satisfies(warning -> assertThat(warning.getFormattedMessage())
                            .contains(PROFILE_NAME, revoked.getUuid().toString()));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Stores the certificate again with the mark that the inventory records for a revocation. */
    private Certificate markedInTheInventory(Certificate stored, Consumer<Certificate> revocationMark) {
        revocationMark.accept(stored);
        return certificateRepository.save(stored);
    }

    /** Replaces the stored content of the certificate with bytes that are no certificate. */
    private Certificate corruptContentOf(Certificate stored) {
        CertificateContent content = certificateContentRepository.findByFingerprint(stored.getFingerprint());
        content.setContent(UNREADABLE_CONTENT);
        certificateContentRepository.save(content);
        return stored;
    }

    private static EstRoute buildRouteTrusting(Certificate... trustedCas) {
        UUID[] certificateUuids = Arrays.stream(trustedCas).map(Certificate::getUuid).toArray(UUID[]::new);
        EstProfile estProfile = anEstProfile()
                .withName(PROFILE_NAME)
                .withAuthenticationPolicy(EstAuthenticationPolicy.VENDOR_MTLS)
                .withTrustedCaCertificates(certificateUuids)
                .build();
        return new EstRoute(estProfile, null, false, LABEL);
    }

    private static String resolveUrl(String path) {
        return LoopbackWireMock.url(revocationSources.getPort()) + path;
    }

    /** Serves the status of the certificate as the issuing CA signs it. */
    private void serveOcspStatus(X509Certificate certificate, CertificateStatus status) throws IOException {
        serveOcspResponse(anOcspResponse(ocspRequest(certificate, issuingCa.certificate()), issuingCa.keyPair())
                .withStatus(status)
                .build());
    }

    private static void serveOcspResponse(OCSPResp response) throws IOException {
        revocationSources
                .stubFor(post(urlPathEqualTo(OCSP_PATH))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/ocsp-response")
                                .withBody(response.getEncoded())));
    }

    private static void serveCrl(String path, byte[] crl) {
        revocationSources
                .stubFor(get(urlPathEqualTo(path))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withHeader("Content-Type", "application/pkix-crl")
                                .withBody(crl)));
    }

    private static String encodeBase64(X509Certificate certificate) throws CertificateEncodingException {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    private static void assertCertificateRejected(Throwable thrown) {
        assertRefusedWith(thrown, EstError.CERTIFICATE_REJECTED);
    }

    private static void assertServiceUnavailable(Throwable thrown) {
        assertRefusedWith(thrown, EstError.SERVICE_UNAVAILABLE);
    }

    private static void assertRefusedWith(Throwable thrown, EstError expected) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(expected);
            assertThat(refusal.realm()).contains(LABEL);
        });
    }
}
