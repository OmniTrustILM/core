package com.otilm.core.service.impl;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.writer.CertificateChainWriter;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import com.otilm.core.util.PkiFixtures.RevocationSources;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateContentBuilder.aCertificateContent;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@Timeout(20)
class CertificateChainTraversalTest {

    private static Ca rootCa;

    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private X509CertificateRepository x509CertificateRepository;
    @Mock
    private CertificateChainWriter chainWriter;
    @Mock
    private CertificateInternalService certificateService;

    private WireMockServer server;
    private CertificateChainServiceImpl service;
    private final List<X509CertificateEntity> imported = new ArrayList<>();

    @BeforeAll
    static void generateRootCertificate() {
        rootCa = PkiFixtures.rootCa("Traversal Root");
    }

    @BeforeEach
    void wireChainServiceAndStartServer() {
        server = LoopbackWireMock.start();
        service = new CertificateChainServiceImpl(certificateRepository, x509CertificateRepository, chainWriter,
                certificateService);
        ReflectionTestUtils.setField(service, "certificateChainMaxDepth", 20);
    }

    @AfterEach
    void stopServer() {
        server.stop();
    }

    @Test
    void stopsAtConfiguredDepth_whenPublishedChainHasMoreIssuers() throws Exception {
        // given
        int maximumDepth = 3;
        ReflectionTestUtils.setField(service, "certificateChainMaxDepth", maximumDepth);
        List<Ca> issuers = createPublishedIssuers(8);
        X509CertificateEntity leaf = createLeafCertificate(issuers.getFirst(), buildUrl(issuerPath(0)));
        stubCertificateImports();

        // when
        service.updateCertificateChain(leaf);

        // then
        assertImportedIssuers(issuers.subList(0, maximumDepth));
        assertLinkedChain(leaf, imported);
        assertRequestedIssuerRange(0, maximumDepth);
        assertThat(server.getAllServeEvents()).hasSize(maximumDepth);
        server.verify(0, getRequestedFor(urlPathEqualTo(issuerPath(maximumDepth))));
    }

    @Test
    void countsInventoryLinksTowardDepth_whenAiaContinuesAnInventoryPrefix() throws Exception {
        // given
        int maximumDepth = 3;
        int inventoryPrefixLength = 2;
        ReflectionTestUtils.setField(service, "certificateChainMaxDepth", maximumDepth);
        List<Ca> issuers = createPublishedIssuers(8);
        X509CertificateEntity leaf = createLeafCertificate(issuers.getFirst(), buildUrl(issuerPath(0)));
        X509CertificateEntity firstInventoryIssuer = createEntity(issuers.get(0).certificate());
        X509CertificateEntity secondInventoryIssuer = createEntity(issuers.get(1).certificate());
        stubInventory(firstInventoryIssuer, secondInventoryIssuer);
        stubCertificateImports();

        // when
        service.updateCertificateChain(leaf);

        // then
        assertImportedIssuers(issuers.subList(inventoryPrefixLength, maximumDepth));
        assertLinkedChain(leaf, List.of(firstInventoryIssuer, secondInventoryIssuer, imported.getFirst()));
        assertRequestedIssuerRange(inventoryPrefixLength, maximumDepth);
        assertThat(server.getAllServeEvents()).hasSize(maximumDepth - inventoryPrefixLength);
        server.verify(0, getRequestedFor(urlPathEqualTo(issuerPath(maximumDepth))));
    }

    @Test
    void retainsCachedAncestors_whenDownloadLimitPreventsFurtherRequests() throws Exception {
        // given
        int maximumDownloads = 20;
        int cachedAncestors = 2;
        int maximumDepth = 30;
        ReflectionTestUtils.setField(service, "certificateChainMaxDepth", maximumDepth);
        List<Ca> issuers = createPublishedIssuers(25);
        int expectedIssuerCount = maximumDownloads + cachedAncestors;
        stubBundle(issuerPath(maximumDownloads - 1), issuers.subList(maximumDownloads - 1, expectedIssuerCount));
        X509CertificateEntity leaf = createLeafCertificate(issuers.getFirst(), buildUrl(issuerPath(0)));
        stubCertificateImports();

        // when
        service.updateCertificateChain(leaf);

        // then
        assertImportedIssuers(issuers.subList(0, expectedIssuerCount));
        assertLinkedChain(leaf, imported);
        assertRequestedIssuerRange(0, maximumDownloads);
        assertThat(server.getAllServeEvents()).hasSize(maximumDownloads);
        server.verify(0, getRequestedFor(urlPathEqualTo(issuerPath(maximumDownloads))));
        server.verify(0, getRequestedFor(urlPathEqualTo(issuerPath(expectedIssuerCount))));
    }

    @Test
    void usesFifthUniqueLocation_whenEarlierLocationsIncludeDuplicates() throws Exception {
        // given
        int maximumLocations = 5;
        List<String> locations = new ArrayList<>();
        for (int index = 0; index < maximumLocations - 1; index++) {
            String path = "/failed-" + index;
            stubFailure(path);
            locations.add(buildUrl(path));
            locations.add(buildUrl(path));
        }
        locations.add(buildUrl("/root"));
        stubCertificate("/root", rootCa.certificate());
        X509CertificateEntity leaf = createLeafCertificate(rootCa, locations.toArray(String[]::new));
        stubCertificateImports();

        // when
        service.updateCertificateChain(leaf);

        // then
        assertImportedIssuers(List.of(rootCa));
        assertLinkedChain(leaf, imported);
        assertThat(server.getAllServeEvents()).hasSize(maximumLocations);
        for (int index = 0; index < maximumLocations - 1; index++) {
            server.verify(1, getRequestedFor(urlPathEqualTo("/failed-" + index)));
        }
        server.verify(1, getRequestedFor(urlPathEqualTo("/root")));
    }

    @Test
    void skipsSixthUniqueLocation_whenFiveLocationsHaveFailed() throws Exception {
        // given
        int maximumLocations = 5;
        List<String> locations = new ArrayList<>();
        for (int index = 0; index < maximumLocations; index++) {
            String path = "/failed-" + index;
            stubFailure(path);
            locations.add(buildUrl(path));
        }
        String locationBeyondLimit = "/root";
        locations.add(buildUrl(locationBeyondLimit));
        stubCertificate(locationBeyondLimit, rootCa.certificate());
        X509CertificateEntity leaf = createLeafCertificate(rootCa, locations.toArray(String[]::new));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertThat(imported).isEmpty();
        assertThat(leaf.getIssuerCertificateUuid()).isNull();
        assertThat(leaf.getIssuerSerialNumber()).isNull();
        verifyNoInteractions(certificateService, chainWriter);
        assertThat(server.getAllServeEvents()).hasSize(maximumLocations);
        for (int index = 0; index < maximumLocations; index++) {
            server.verify(1, getRequestedFor(urlPathEqualTo("/failed-" + index)));
        }
        server.verify(0, getRequestedFor(urlPathEqualTo(locationBeyondLimit)));
    }

    @Test
    void leavesPartialChainLinked_whenTheNextSourceInitiallyReturnsNoCertificates() throws Exception {
        // given
        int maximumDepth = 3;
        ReflectionTestUtils.setField(service, "certificateChainMaxDepth", maximumDepth);
        List<Ca> issuers = createPublishedIssuers(8);
        X509CertificateEntity leaf = createLeafCertificate(issuers.getFirst(), buildUrl(issuerPath(0)));
        String intermittentPath = issuerPath(1);
        String scenario = "issuer availability";
        String available = "available";
        server
                .stubFor(get(urlPathEqualTo(intermittentPath))
                        .inScenario(scenario)
                        .whenScenarioStateIs(Scenario.STARTED)
                        .willReturn(aResponse().withStatus(200).withBody(new byte[0]))
                        .willSetStateTo(available));
        server
                .stubFor(get(urlPathEqualTo(intermittentPath))
                        .inScenario(scenario)
                        .whenScenarioStateIs(available)
                        .willReturn(aResponse().withBody(issuers.get(1).certificate().getEncoded())));
        stubCertificateImports();

        // when
        service.updateCertificateChain(leaf);

        // then
        assertImportedIssuers(issuers.subList(0, 1));
        assertLinkedChain(leaf, imported);
        server.verify(1, getRequestedFor(urlPathEqualTo(issuerPath(0))));
        server.verify(1, getRequestedFor(urlPathEqualTo(intermittentPath)));
        server.verify(0, getRequestedFor(urlPathEqualTo(issuerPath(2))));
        assertThat(server.getAllServeEvents()).hasSize(2);
    }

    @Test
    void retainsBundleCandidates_whenAnInventoryIssuerConnectsDownloadedCertificates() throws Exception {
        // given
        Ca inventoryCa = PkiFixtures.intermediateCa(rootCa, "Inventory Intermediate");
        Ca downloadedCa = PkiFixtures.intermediateCa(inventoryCa, "Downloaded Intermediate");
        X509CertificateEntity inventoryIssuer = createEntity(inventoryCa.certificate());
        X509CertificateEntity leaf = createLeafCertificate(downloadedCa, buildUrl("/bundle"));
        stubBundle("/bundle", List.of(rootCa, downloadedCa));
        stubInventory(inventoryIssuer);
        stubCertificateImports();

        // when
        service.updateCertificateChain(leaf);

        // then
        assertImportedIssuers(List.of(downloadedCa, rootCa));
        assertLinkedChain(leaf, List.of(imported.get(0), inventoryIssuer, imported.get(1)));
        server.verify(1, getRequestedFor(urlPathEqualTo("/bundle")));
        assertThat(server.getAllServeEvents()).hasSize(1);
    }

    @Test
    void verifiesEachCandidateOnce_whenSuccessiveLocationsReturnDifferentKeysForTheIssuer() throws Exception {
        // given
        X509Certificate firstWrongIssuer = PkiFixtures.rootCa("Traversal Root").certificate();
        X509Certificate secondWrongIssuer = PkiFixtures.rootCa("Traversal Root").certificate();
        stubCertificate("/first-key", firstWrongIssuer);
        stubCertificate("/second-key", secondWrongIssuer);
        stubCertificate("/root", rootCa.certificate());
        X509Certificate leafCertificate = spy(PkiFixtures
                .clientCertificate(rootCa,
                        caIssuerSources(List.of(buildUrl("/first-key"), buildUrl("/second-key"), buildUrl("/root")))));
        X509CertificateEntity leaf = createEntity(leafCertificate);
        stubCertificateImports();

        // when
        service.updateCertificateChain(leaf, leafCertificate);

        // then
        assertImportedIssuers(List.of(rootCa));
        assertLinkedChain(leaf, imported);
        verify(leafCertificate).verify(firstWrongIssuer.getPublicKey());
        verify(leafCertificate).verify(secondWrongIssuer.getPublicKey());
        verify(leafCertificate).verify(rootCa.certificate().getPublicKey());
        assertThat(server.getAllServeEvents()).hasSize(3);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private List<Ca> createPublishedIssuers(int count) throws Exception {
        List<Ca> issuers = new ArrayList<>();
        Ca issuer = rootCa;
        issuers.add(issuer);
        for (int index = count - 2; index >= 0; index--) {
            issuer = PkiFixtures
                    .intermediateCa(issuer, "Traversal CA " + index,
                            RevocationSources.onlyCaIssuers(buildUrl(issuerPath(index + 1))));
            issuers.add(0, issuer);
        }
        for (int index = 0; index < issuers.size(); index++) {
            stubCertificate(issuerPath(index), issuers.get(index).certificate());
        }
        return issuers;
    }

    private void stubInventory(X509CertificateEntity... certificates) {
        when(x509CertificateRepository.findBySubjectDnNormalized(anyString())).thenAnswer(invocation -> {
            String subject = invocation.getArgument(0);
            return List
                    .of(certificates)
                    .stream()
                    .filter(certificate -> certificate.getSubjectDnNormalized().equals(subject))
                    .toList();
        });
    }

    private void stubCertificateImports() throws Exception {
        when(certificateService.createCertificateAtomic(anyString(), eq(false))).thenAnswer(invocation -> {
            X509CertificateEntity certificate = createEntity(
                    CertificateUtil.parseCertificate(invocation.getArgument(0)));
            imported.add(certificate);
            return certificate;
        });
    }

    private static X509CertificateEntity createLeafCertificate(Ca issuer, String... locations) throws Exception {
        return createEntity(PkiFixtures.clientCertificate(issuer, caIssuerSources(List.of(locations))));
    }

    private static RevocationSources caIssuerSources(List<String> locations) {
        return new RevocationSources(List.of(), List.of(), locations, List.of(), List.of(), List.of());
    }

    private static X509CertificateEntity createEntity(X509Certificate certificate) throws Exception {
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        CertificateContent content = aCertificateContent().withContent(pem).build();
        return aCertificate()
                .withUuid(UUID.randomUUID())
                .withSerialNumber(certificate.getSerialNumber().toString(16))
                .withSubjectDnNormalized(certificate.getSubjectX500Principal().getName())
                .withIssuerDnNormalized(certificate.getIssuerX500Principal().getName())
                .withCertificateContent(content)
                .build();
    }

    private void stubCertificate(String path, X509Certificate certificate) throws Exception {
        server
                .stubFor(get(urlPathEqualTo(path))
                        .willReturn(aResponse()
                                .withHeader("Content-Type", "application/pkix-cert")
                                .withBody(certificate.getEncoded())));
    }

    private void stubBundle(String path, List<Ca> issuers) throws Exception {
        var bundle = new CMSSignedDataGenerator();
        for (Ca issuer : issuers) {
            bundle.addCertificate(new JcaX509CertificateHolder(issuer.certificate()));
        }
        server
                .stubFor(get(urlPathEqualTo(path))
                        .willReturn(aResponse()
                                .withHeader("Content-Type", "application/pkcs7-mime")
                                .withBody(bundle.generate(new CMSAbsentContent()).getEncoded())));
    }

    private void stubFailure(String path) {
        server.stubFor(get(urlPathEqualTo(path)).willReturn(aResponse().withStatus(503)));
    }

    private String buildUrl(String path) {
        return LoopbackWireMock.url(server) + path;
    }

    private static String issuerPath(int index) {
        return "/issuer-" + index;
    }

    private void assertImportedIssuers(List<Ca> expectedIssuers) {
        assertThat(imported)
                .extracting(X509CertificateEntity::getSerialNumber)
                .containsExactlyElementsOf(expectedIssuers
                        .stream()
                        .map(issuer -> issuer.certificate().getSerialNumber().toString(16))
                        .toList());
    }

    private void assertLinkedChain(X509CertificateEntity leaf, List<X509CertificateEntity> issuers) {
        X509CertificateEntity child = leaf;
        for (X509CertificateEntity issuer : issuers) {
            assertThat(child.getIssuerCertificateUuid()).isEqualTo(issuer.getUuid());
            assertThat(child.getIssuerSerialNumber()).isEqualTo(issuer.getSerialNumber());
            verify(chainWriter).applyIssuerReference(child.getUuid(), issuer.getSerialNumber(), issuer.getUuid());
            child = issuer;
        }
        assertThat(child.getIssuerCertificateUuid()).isNull();
        assertThat(child.getIssuerSerialNumber()).isNull();
        verifyNoMoreInteractions(chainWriter);
    }

    private void assertRequestedIssuerRange(int startInclusive, int endExclusive) {
        IntStream
                .range(startInclusive, endExclusive)
                .forEach(index -> server.verify(1, getRequestedFor(urlPathEqualTo(issuerPath(index)))));
    }
}
