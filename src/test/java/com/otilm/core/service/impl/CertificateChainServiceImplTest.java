package com.otilm.core.service.impl;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.writer.CertificateChainWriter;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.LdapFixtures.SearchResults;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.PkiFixtures;
import com.otilm.core.util.PkiFixtures.Ca;
import com.otilm.core.util.PkiFixtures.RevocationSources;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Hashtable;
import java.util.List;
import java.util.UUID;
import javax.naming.Name;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.otilm.core.util.LdapFixtures.searchResults;
import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateContentBuilder.aCertificateContent;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@Timeout(20)
class CertificateChainServiceImplTest {

    private static Ca rootCa;
    private static Ca intermediateCa;
    private static X509Certificate root;
    private static X509Certificate intermediate;
    private static X509Certificate unrelated;

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
    static void generateCertificates() {
        rootCa = PkiFixtures.rootCa("AIA Root");
        intermediateCa = PkiFixtures.intermediateCa(rootCa, "AIA Intermediate");
        root = rootCa.certificate();
        intermediate = intermediateCa.certificate();
        unrelated = PkiFixtures.rootCa("AIA Root").certificate();
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
    void linksIssuerChain_whenPkcs7BundleContainsUnorderedCertificates() throws Exception {
        // given
        stubCertificateImports();
        CMSSignedDataGenerator bundle = new CMSSignedDataGenerator();
        bundle.addCertificate(new JcaX509CertificateHolder(root));
        bundle.addCertificate(new JcaX509CertificateHolder(intermediate));
        stubResponse("/bundle", bundle.generate(new CMSAbsentContent()).getEncoded(), "application/pkcs7-mime");
        X509CertificateEntity leaf = createLeafCertificate(intermediateCa, buildUrl("/bundle"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertThat(imported)
                .extracting(X509CertificateEntity::getSerialNumber)
                .containsExactly(intermediate.getSerialNumber().toString(16), root.getSerialNumber().toString(16));
        assertLink(leaf, imported.get(0));
        assertLink(imported.get(0), imported.get(1));
        assertThat(imported.get(1).getIssuerCertificateUuid()).isNull();
        InOrder links = inOrder(chainWriter);
        links
                .verify(chainWriter)
                .applyIssuerReference(leaf.getUuid(), imported.get(0).getSerialNumber(), imported.get(0).getUuid());
        links
                .verify(chainWriter)
                .applyIssuerReference(imported.get(0).getUuid(), imported.get(1).getSerialNumber(),
                        imported.get(1).getUuid());
        verifyNoMoreInteractions(chainWriter);
        assertRequested("/bundle");
    }

    @ParameterizedTest
    @ValueSource(strings = {"DER", "PEM"})
    void linksIssuer_whenResponseContainsASingleCertificate(String encoding) throws Exception {
        // given
        stubCertificateImports();
        byte[] response = "DER".equals(encoding)
                ? root.getEncoded()
                : encodePem(root).getBytes(StandardCharsets.US_ASCII);
        stubResponse("/issuer", response, "application/pkix-cert");
        X509CertificateEntity leaf = createLeafCertificate(rootCa, buildUrl("/issuer"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertRootLink(leaf);
    }

    @Test
    void preservesExistingIssuerLink_whenImportedCertificateAlreadyHasAChain() throws Exception {
        // given
        X509CertificateEntity existingIntermediate = createEntity(intermediate);
        UUID existingIssuerUuid = UUID.randomUUID();
        existingIntermediate.setIssuerCertificateUuid(existingIssuerUuid);
        existingIntermediate.setIssuerSerialNumber("existing-issuer");
        when(certificateService.createCertificateAtomic(anyString(), eq(false))).thenReturn(existingIntermediate);
        CMSSignedDataGenerator bundle = new CMSSignedDataGenerator();
        bundle.addCertificate(new JcaX509CertificateHolder(root));
        bundle.addCertificate(new JcaX509CertificateHolder(intermediate));
        stubResponse("/bundle", bundle.generate(new CMSAbsentContent()).getEncoded(), "application/pkcs7-mime");
        X509CertificateEntity leaf = createLeafCertificate(intermediateCa, buildUrl("/bundle"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertLink(leaf, existingIntermediate);
        assertThat(existingIntermediate.getIssuerCertificateUuid()).isEqualTo(existingIssuerUuid);
        assertThat(existingIntermediate.getIssuerSerialNumber()).isEqualTo("existing-issuer");
        verify(certificateService).createCertificateAtomic(anyString(), eq(false));
        verify(chainWriter)
                .applyIssuerReference(leaf.getUuid(), existingIntermediate.getSerialNumber(),
                        existingIntermediate.getUuid());
        verifyNoMoreInteractions(chainWriter);
        assertRequested("/bundle");
    }

    @Test
    void retainsLinkedPrefix_whenNextIssuerCannotBeImported() throws Exception {
        // given
        X509CertificateEntity importedIntermediate = createEntity(intermediate);
        when(certificateService.createCertificateAtomic(anyString(), eq(false)))
                .thenReturn(importedIntermediate)
                .thenThrow(new CertificateException("Unable to import issuer"));
        CMSSignedDataGenerator bundle = new CMSSignedDataGenerator();
        bundle.addCertificate(new JcaX509CertificateHolder(root));
        bundle.addCertificate(new JcaX509CertificateHolder(intermediate));
        stubResponse("/bundle", bundle.generate(new CMSAbsentContent()).getEncoded(), "application/pkcs7-mime");
        X509CertificateEntity leaf = createLeafCertificate(intermediateCa, buildUrl("/bundle"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertLink(leaf, importedIntermediate);
        assertThat(importedIntermediate.getIssuerCertificateUuid()).isNull();
        verify(chainWriter)
                .applyIssuerReference(leaf.getUuid(), importedIntermediate.getSerialNumber(),
                        importedIntermediate.getUuid());
        verifyNoMoreInteractions(chainWriter);
        assertRequested("/bundle");
    }

    @Test
    void linksIssuer_whenFirstAiaLocationReturnsAnHttpFailure() throws Exception {
        // given
        stubCertificateImports();
        server.stubFor(get(urlPathEqualTo("/failed")).willReturn(aResponse().withStatus(503)));
        stubResponse("/issuer", root.getEncoded(), "application/pkix-cert");
        X509CertificateEntity leaf = createLeafCertificate(rootCa, buildUrl("/failed"), buildUrl("/issuer"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertRootLink(leaf);
        assertRequested("/failed", "/issuer");
    }

    @Test
    void requestsFailedLocationOnce_whenAiaRepeatsItsUri() throws Exception {
        // given
        stubCertificateImports();
        server.stubFor(get(urlPathEqualTo("/failed")).willReturn(aResponse().withStatus(503)));
        stubResponse("/issuer", root.getEncoded(), "application/pkix-cert");
        String repeatedFailure = buildUrl("/failed");
        X509CertificateEntity leaf = createLeafCertificate(rootCa, repeatedFailure, repeatedFailure,
                buildUrl("/issuer"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertRootLink(leaf);
        assertRequested("/failed", "/issuer");
    }

    @Test
    void linksIssuer_whenFirstAiaLocationReturnsMalformedContent() throws Exception {
        // given
        stubCertificateImports();
        stubResponse("/malformed", "not a certificate".getBytes(StandardCharsets.US_ASCII), "text/plain");
        stubResponse("/issuer", root.getEncoded(), "application/pkix-cert");
        X509CertificateEntity leaf = createLeafCertificate(rootCa, buildUrl("/malformed"), buildUrl("/issuer"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertRootLink(leaf);
        assertRequested("/malformed", "/issuer");
    }

    @Test
    void linksIssuerFromFallback_whenFirstResponseExceedsOneMebibyte() throws Exception {
        // given
        stubCertificateImports();
        int maximumResponseBytes = 1024 * 1024;
        byte[] issuerDer = root.getEncoded();
        var oversizedResponse = new ByteArrayOutputStream();
        while (oversizedResponse.size() <= maximumResponseBytes) {
            oversizedResponse.writeBytes(issuerDer);
        }
        stubResponse("/oversized", oversizedResponse.toByteArray(), "application/pkix-cert");
        stubResponse("/issuer", issuerDer, "application/pkix-cert");
        X509CertificateEntity leaf = createLeafCertificate(rootCa, buildUrl("/oversized"), buildUrl("/issuer"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertThat(oversizedResponse.size()).isGreaterThan(maximumResponseBytes);
        assertRootLink(leaf);
        assertRequested("/oversized", "/issuer");
    }

    @Test
    void linksIssuer_whenHttpFollowsAHostlessLdapLocation() throws Exception {
        // given
        stubCertificateImports();
        stubResponse("/issuer", root.getEncoded(), "application/pkix-cert");
        String hostlessLdapUrl = "ldap:///CN=AIA%20Root?cACertificate;binary";
        X509CertificateEntity leaf = createLeafCertificate(rootCa, hostlessLdapUrl, buildUrl("/issuer"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertRootLink(leaf);
        assertRequested("/issuer");
    }

    @Test
    void linksIssuer_whenLdapAiaLocationServesBinaryCertificate() throws Exception {
        // given
        stubCertificateImports();
        SearchResults results = searchResults(new BasicAttributes("cACertificate;binary", root.getEncoded(), true));
        String ldapIssuerUrl = "ldap://ldap.example.com/CN=AIA%20Root?cACertificate;binary?base";
        X509CertificateEntity leaf = createLeafCertificate(rootCa, ldapIssuerUrl);
        List<Hashtable<?, ?>> environments = new ArrayList<>();
        try (MockedConstruction<InitialLdapContext> contexts = mockConstruction(InitialLdapContext.class,
                (context, construction) -> {
                    environments.add((Hashtable<?, ?>) construction.arguments().getFirst());
                    when(context.search(any(Name.class), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            // when
            service.updateCertificateChain(leaf);

            // then
            assertRootLink(leaf);
            assertThat(environments).hasSize(1);
            assertThat(environments.getFirst().get("com.sun.jndi.ldap.connect.timeout")).isEqualTo("1000");
            assertThat(environments.getFirst().get("com.sun.jndi.ldap.read.timeout")).isEqualTo("1000");
            assertThat(results.isClosed()).isTrue();
            verify(contexts.constructed().getFirst()).close();
        }
    }

    @Test
    void leavesCertificateUnlinked_whenSignedLeafHasMalformedAia() throws Exception {
        // given
        X509Certificate leafWithMalformedAia = reissueWithMalformedAia(PkiFixtures.clientCertificate(rootCa), rootCa);
        X509CertificateEntity leaf = createEntity(leafWithMalformedAia);

        // when
        service.updateCertificateChain(leaf);

        // then
        assertThat(imported).isEmpty();
        assertThat(leaf.getIssuerCertificateUuid()).isNull();
        assertThat(leaf.getIssuerSerialNumber()).isNull();
        verifyNoInteractions(certificateService, chainWriter);
    }

    @Test
    void retainsVerifiedIssuer_whenIntermediateHasMalformedAia() throws Exception {
        // given
        stubCertificateImports();
        X509Certificate malformedIntermediate = reissueWithMalformedAia(intermediate, rootCa);
        var malformedIntermediateCa = new Ca(intermediateCa.keyPair(), malformedIntermediate);
        stubResponse("/intermediate", malformedIntermediate.getEncoded(), "application/pkix-cert");
        X509CertificateEntity leaf = createLeafCertificate(malformedIntermediateCa, buildUrl("/intermediate"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertThat(imported).hasSize(1);
        assertThat(imported.getFirst().getSerialNumber())
                .isEqualTo(malformedIntermediate.getSerialNumber().toString(16));
        assertLink(leaf, imported.getFirst());
        assertThat(imported.getFirst().getIssuerCertificateUuid()).isNull();
        verify(chainWriter)
                .applyIssuerReference(leaf.getUuid(), imported.getFirst().getSerialNumber(),
                        imported.getFirst().getUuid());
        verifyNoMoreInteractions(chainWriter);
        assertRequested("/intermediate");
    }

    @Test
    void linksIssuer_whenFirstCertificateHasAnUnrelatedKey() throws Exception {
        // given
        stubCertificateImports();
        stubResponse("/unrelated", unrelated.getEncoded(), "application/pkix-cert");
        stubResponse("/issuer", root.getEncoded(), "application/pkix-cert");
        X509CertificateEntity leaf = createLeafCertificate(rootCa, buildUrl("/unrelated"), buildUrl("/issuer"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertRootLink(leaf);
        assertRequested("/unrelated", "/issuer");
    }

    @Test
    void linksIssuer_whenFirstCertificateHasADifferentSubject() throws Exception {
        // given
        stubCertificateImports();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(root, BigInteger.valueOf(3),
                root.getNotBefore(), root.getNotAfter(), new X500Name("CN=Different CA"), root.getPublicKey());
        X509Certificate differentSubject = new JcaX509CertificateConverter()
                .getCertificate(builder
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(rootCa.keyPair().getPrivate())));
        stubResponse("/different-subject", differentSubject.getEncoded(), "application/pkix-cert");
        stubResponse("/issuer", root.getEncoded(), "application/pkix-cert");
        X509CertificateEntity leaf = createLeafCertificate(rootCa, buildUrl("/different-subject"), buildUrl("/issuer"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertRootLink(leaf);
        assertRequested("/different-subject", "/issuer");
    }

    @Test
    void leavesCertificateUnlinked_whenEveryAiaLocationFails() throws Exception {
        // given
        server.stubFor(get(urlPathEqualTo("/failed")).willReturn(aResponse().withStatus(503)));
        stubResponse("/malformed", new byte[]{1, 2, 3}, "application/pkix-cert");
        stubResponse("/unrelated", unrelated.getEncoded(), "application/pkix-cert");
        X509CertificateEntity leaf = createLeafCertificate(rootCa, buildUrl("/failed"), buildUrl("/malformed"),
                buildUrl("/unrelated"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertThat(imported).isEmpty();
        assertThat(leaf.getIssuerCertificateUuid()).isNull();
        assertThat(leaf.getIssuerSerialNumber()).isNull();
        verifyNoInteractions(certificateService, chainWriter);
        assertRequested("/failed", "/malformed", "/unrelated");
    }

    @Test
    void stopsRequestingAlternatives_whenIssuerIsFound() throws Exception {
        // given
        stubCertificateImports();
        stubResponse("/issuer", root.getEncoded(), "application/pkix-cert");
        stubResponse("/unused", unrelated.getEncoded(), "application/pkix-cert");
        X509CertificateEntity leaf = createLeafCertificate(rootCa, buildUrl("/issuer"), buildUrl("/unused"));

        // when
        service.updateCertificateChain(leaf);

        // then
        assertRootLink(leaf);
        assertRequested("/issuer");
        server.verify(0, getRequestedFor(urlPathEqualTo("/unused")));
    }

    @Test
    void linksEachIssuerOnce_whenDownloadedCertificatesFormACycle() throws Exception {
        // given
        stubCertificateImports();
        String firstIssuerUrl = buildUrl("/first-issuer");
        String secondIssuerUrl = buildUrl("/second-issuer");
        Ca secondCa = PkiFixtures
                .intermediateCa(rootCa, "Cyclic Intermediate", RevocationSources.onlyCaIssuers(firstIssuerUrl));
        Ca firstCa = crossSignCa(rootCa, secondCa, secondIssuerUrl);
        X509Certificate leafCertificate = PkiFixtures
                .clientCertificate(firstCa, RevocationSources.onlyCaIssuers(firstIssuerUrl));
        X509CertificateEntity leaf = createEntity(leafCertificate);
        stubResponse("/first-issuer", firstCa.certificate().getEncoded(), "application/pkix-cert");
        stubResponse("/second-issuer", secondCa.certificate().getEncoded(), "application/pkix-cert");

        // when
        service.updateCertificateChain(leaf);

        // then
        assertThat(imported).hasSize(2);
        assertThat(CertificateUtil.parseCertificate(imported.get(0).getCertificateContent().getContent()))
                .isEqualTo(firstCa.certificate());
        assertThat(CertificateUtil.parseCertificate(imported.get(1).getCertificateContent().getContent()))
                .isEqualTo(secondCa.certificate());
        assertLink(leaf, imported.get(0));
        assertLink(imported.get(0), imported.get(1));
        assertThat(imported.get(1).getIssuerCertificateUuid()).isNull();
        assertRequested("/first-issuer", "/second-issuer");
    }

    @Test
    void linksLimitedChain_whenBundleExceedsConfiguredDepth() throws Exception {
        // given
        stubCertificateImports();
        int maximumDownloadDepth = 1;
        ReflectionTestUtils.setField(service, "certificateChainMaxDepth", maximumDownloadDepth);
        CMSSignedDataGenerator bundle = new CMSSignedDataGenerator();
        bundle.addCertificate(new JcaX509CertificateHolder(root));
        bundle.addCertificate(new JcaX509CertificateHolder(intermediate));
        stubResponse("/bundle", bundle.generate(new CMSAbsentContent()).getEncoded(), "application/pkcs7-mime");
        X509Certificate leafCertificate = PkiFixtures
                .clientCertificate(intermediateCa, RevocationSources.onlyCaIssuers(buildUrl("/bundle")));
        X509CertificateEntity leaf = createEntity(leafCertificate);

        // when
        service.updateCertificateChain(leaf);

        // then
        assertThat(imported).hasSize(maximumDownloadDepth);
        assertThat(CertificateUtil.parseCertificate(imported.getFirst().getCertificateContent().getContent()))
                .isEqualTo(intermediate);
        assertLink(leaf, imported.getFirst());
        assertThat(imported.getFirst().getIssuerCertificateUuid()).isNull();
        assertRequested("/bundle");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Ca crossSignCa(Ca subject, Ca issuer, String issuerUrl) throws Exception {
        X509Certificate certificate = subject.certificate();
        var builder = new JcaX509v3CertificateBuilder(issuer.certificate(), certificate.getSerialNumber(),
                certificate.getNotBefore(), certificate.getNotAfter(),
                new X500Name(certificate.getSubjectX500Principal().getName()), certificate.getPublicKey());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder
                .addExtension(Extension.authorityInfoAccess, false,
                        new AuthorityInformationAccess(AccessDescription.id_ad_caIssuers,
                                new GeneralName(GeneralName.uniformResourceIdentifier, issuerUrl)));
        X509Certificate crossSignedCertificate = new JcaX509CertificateConverter()
                .getCertificate(builder
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuer.keyPair().getPrivate())));
        return new Ca(subject.keyPair(), crossSignedCertificate);
    }

    private static X509Certificate reissueWithMalformedAia(X509Certificate certificate, Ca issuer) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(issuer.certificate(), certificate.getSerialNumber(),
                certificate.getNotBefore(), certificate.getNotAfter(),
                new X500Name(certificate.getSubjectX500Principal().getName()), certificate.getPublicKey());
        builder
                .addExtension(Extension.basicConstraints, true,
                        new BasicConstraints(certificate.getBasicConstraints() >= 0));
        builder.addExtension(Extension.authorityInfoAccess, false, new byte[]{0x30, 0x01, 0x00});
        return new JcaX509CertificateConverter()
                .getCertificate(builder
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuer.keyPair().getPrivate())));
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
        RevocationSources sources = new RevocationSources(List.of(), List.of(), List.of(locations), List.of(),
                List.of(), List.of());
        return createEntity(PkiFixtures.clientCertificate(issuer, sources));
    }

    private static X509CertificateEntity createEntity(X509Certificate x509) throws Exception {
        CertificateContent content = aCertificateContent().withContent(encodePem(x509)).build();
        return aCertificate()
                .withUuid(UUID.randomUUID())
                .withSerialNumber(x509.getSerialNumber().toString(16))
                .withSubjectDnNormalized(x509.getSubjectX500Principal().getName())
                .withIssuerDnNormalized(x509.getIssuerX500Principal().getName())
                .withCertificateContent(content)
                .build();
    }

    private static String encodePem(X509Certificate x509) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(x509.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private void stubResponse(String path, byte[] body, String contentType) {
        server
                .stubFor(get(urlPathEqualTo(path))
                        .willReturn(aResponse().withHeader("Content-Type", contentType).withBody(body)));
    }

    private String buildUrl(String path) {
        return LoopbackWireMock.url(server) + path;
    }

    private void assertRequested(String... paths) {
        for (String path : paths) {
            server.verify(1, getRequestedFor(urlPathEqualTo(path)));
        }
    }

    private void assertRootLink(X509CertificateEntity leaf) {
        assertThat(imported)
                .extracting(X509CertificateEntity::getSerialNumber)
                .containsExactly(root.getSerialNumber().toString(16));
        assertLink(leaf, imported.getFirst());
        InOrder links = inOrder(chainWriter);
        links
                .verify(chainWriter)
                .applyIssuerReference(leaf.getUuid(), imported.getFirst().getSerialNumber(),
                        imported.getFirst().getUuid());
        verifyNoMoreInteractions(chainWriter);
    }

    private static void assertLink(X509CertificateEntity child, X509CertificateEntity issuer) {
        assertThat(child.getIssuerCertificateUuid()).isEqualTo(issuer.getUuid());
        assertThat(child.getIssuerSerialNumber()).isEqualTo(issuer.getSerialNumber());
    }
}
