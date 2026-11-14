package com.otilm.core.security.ai;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLSession;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RuntimeProxyTrustManagerTest {
    private static final Instant NOW = Instant.parse("2026-10-29T12:00:00Z");
    private static final String URI = "ilm-runtime-proxy://lab/ns/runtime/sa/runner/pod/run-a/uid/"
            + "27b7adad-1f27-490a-971d-633e8abbdfbd";
    private static final String REJECTED = "Runtime proxy certificate rejected";
    private static Identity root;
    private static Identity intermediate;
    private static Identity proxy;

    @BeforeAll
    static void certificates() throws Exception {
        root = issue(null, true, KeyUsage.keyCertSign | KeyUsage.cRLSign, null, null, NOW.minusSeconds(300),
                NOW.plusSeconds(300));
        intermediate = issue(root, true, KeyUsage.keyCertSign, null, null, NOW.minusSeconds(100), NOW.plusSeconds(200));
        proxy = client(intermediate, new GeneralName(GeneralName.uniformResourceIdentifier, URI));
    }

    @Test
    void validatesPresentedChainWithOrWithoutItsTrustedRoot() throws Exception {
        var manager = manager(policy(Set.of()));
        assertThat(manager.verifyPeer(session(chain(proxy, intermediate))).uri()).isEqualTo(URI);
        assertThat(manager.verifyPeer(session(chain(proxy, intermediate, root))).uri()).isEqualTo(URI);
        assertThat(manager.getAcceptedIssuers()).isEmpty();
    }

    @Test
    void rejectsUntrustedSignerAndMissingIntermediate() throws Exception {
        var other = issue(null, true, KeyUsage.keyCertSign, null, null, NOW.minusSeconds(10), NOW.plusSeconds(100));
        denied(manager(policy(Set.of())), chain(client(other, uri()), other));
        denied(manager(policy(Set.of())), chain(proxy));
    }

    @Test
    void rejectsExpiredOrFutureLeafAndExpiredAnchor() throws Exception {
        for (var interval : List
                .of(new Instant[]{NOW.minusSeconds(20), NOW.minusSeconds(1)},
                        new Instant[]{NOW.plusSeconds(1), NOW.plusSeconds(20)})) {
            var leaf = issue(intermediate, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                    new GeneralNames(uri()), interval[0], interval[1]);
            denied(manager(policy(Set.of())), chain(leaf, intermediate));
        }
        var expiredRoot = issue(null, true, KeyUsage.keyCertSign, null, null, NOW.minusSeconds(100),
                NOW.minusSeconds(1));
        var leaf = client(expiredRoot, uri());
        var policy = new RuntimeProxyTrustManager.Policy(authorities(expiredRoot.certificate()), Set.of(), NOW,
                NOW.plusSeconds(30));
        denied(manager(policy), chain(leaf));
    }

    @Test
    void rejectsCaLeafWrongOrAbsentPurposeAndSigningKeyUsage() throws Exception {
        for (var profile : List
                .of(new Profile(true, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth),
                        new Profile(false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth),
                        new Profile(false, KeyUsage.digitalSignature, null),
                        new Profile(false, KeyUsage.keyEncipherment, KeyPurposeId.id_kp_clientAuth),
                        new Profile(false, KeyUsage.digitalSignature | KeyUsage.keyCertSign,
                                KeyPurposeId.id_kp_clientAuth),
                        new Profile(false, KeyUsage.digitalSignature | KeyUsage.cRLSign,
                                KeyPurposeId.id_kp_clientAuth))) {
            var leaf = issue(intermediate, profile.ca(), profile.usage(), profile.purpose(), new GeneralNames(uri()),
                    NOW.minusSeconds(10), NOW.plusSeconds(100));
            denied(manager(policy(Set.of())), chain(leaf, intermediate));
        }
        var withoutUsage = issue(intermediate, false, null, KeyPurposeId.id_kp_clientAuth, new GeneralNames(uri()),
                NOW.minusSeconds(10), NOW.plusSeconds(100));
        denied(manager(policy(Set.of())), chain(withoutUsage, intermediate));
    }

    @Test
    void rejectsAbsentAmbiguousGeneralAndLegacySubjectAlternativeNames() throws Exception {
        for (var names : List
                .of(new GeneralNames(new GeneralName(GeneralName.dNSName, "runtime.invalid")),
                        new GeneralNames(
                                new GeneralName(GeneralName.uniformResourceIdentifier, URI.replace("proxy", "other"))),
                        new GeneralNames(
                                new GeneralName[]{uri(), new GeneralName(GeneralName.dNSName, "runtime.invalid")}),
                        new GeneralNames(new GeneralName[]{uri(), uri()}))) {
            var leaf = issue(intermediate, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth, names,
                    NOW.minusSeconds(10), NOW.plusSeconds(100));
            denied(manager(policy(Set.of())), chain(leaf, intermediate));
        }
        var leaf = issue(intermediate, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth, null,
                NOW.minusSeconds(10), NOW.plusSeconds(100));
        denied(manager(policy(Set.of())), chain(leaf, intermediate));
    }

    @Test
    void rejectsEveryDeniedPresentedCertificateAndOmittedAnchor() throws Exception {
        for (var certificate : List.of(proxy.certificate(), intermediate.certificate(), root.certificate())) {
            var digest = HexFormat
                    .of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getTBSCertificate()));
            denied(manager(policy(Set.of(digest))), chain(proxy, intermediate));
        }
    }

    @Test
    void rejectsUnavailableFutureAndExpiredPolicyWithoutRetainingItsCause() throws Exception {
        var current = new AtomicReference<>(policy(Set.of()));
        var manager = new RuntimeProxyTrustManager(current::get, Clock.fixed(NOW, ZoneOffset.UTC));
        assertThat(manager.verifyPeer(session(chain(proxy, intermediate))).uri()).isEqualTo(URI);
        current.set(null);
        denied(manager, chain(proxy, intermediate));
        current
                .set(new RuntimeProxyTrustManager.Policy(authorities(root.certificate()), Set.of(), NOW.plusSeconds(1),
                        NOW.plusSeconds(30)));
        denied(manager, chain(proxy, intermediate));
        current
                .set(new RuntimeProxyTrustManager.Policy(authorities(root.certificate()), Set.of(),
                        NOW.minusSeconds(30), NOW));
        denied(manager, chain(proxy, intermediate));
        var unavailable = new RuntimeProxyTrustManager(() -> {
            throw new IllegalStateException("private-policy-source-detail");
        }, Clock.fixed(NOW, ZoneOffset.UTC));
        denied(unavailable, chain(proxy, intermediate));
    }

    @Test
    void rejectsNullEmptyOversizedAndOverdeepChains() throws Exception {
        var manager = manager(policy(Set.of()));
        denied(manager, null);
        denied(manager, new X509Certificate[0]);
        denied(manager, new X509Certificate[]{null});
        denied(manager, chain(proxy, intermediate, root, root, root));
        var builder = builder(intermediate, keys(), false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                new GeneralNames(uri()), NOW.minusSeconds(10), NOW.plusSeconds(100));
        builder.addExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4"), false, new byte[16384]);
        var oversized = new JcaX509CertificateConverter()
                .getCertificate(builder
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(intermediate.keys().getPrivate())));
        denied(manager, new X509Certificate[]{oversized, intermediate.certificate()});
    }

    @Test
    void rejectsPolicyExpiryOrClockRollbackDuringCertificateValidation() throws Exception {
        for (Instant completed : List.of(NOW.plusSeconds(30), NOW.minusNanos(1))) {
            var clock = mock(Clock.class);
            when(clock.instant()).thenReturn(NOW, completed);
            var manager = new RuntimeProxyTrustManager(() -> policy(Set.of()), clock);
            denied(manager, chain(proxy, intermediate));
        }
    }

    @Test
    void rejectsTrustPolicyReplacementDuringCertificateValidation() throws Exception {
        var denied = HexFormat
                .of()
                .formatHex(MessageDigest.getInstance("SHA-256").digest(proxy.certificate().getTBSCertificate()));
        @SuppressWarnings("unchecked")
        var source = (java.util.function.Supplier<RuntimeProxyTrustManager.Policy>) mock(
                java.util.function.Supplier.class);
        when(source.get()).thenReturn(policy(Set.of()), policy(Set.of(denied)));
        denied(new RuntimeProxyTrustManager(source, Clock.fixed(NOW, ZoneOffset.UTC)), chain(proxy, intermediate));
    }

    @Test
    void anEquivalentReplacementSnapshotCannotHideInterveningInvalidation() throws Exception {
        var original = policy(Set.of());
        var replacement = new RuntimeProxyTrustManager.Policy(original.authorities(), original.deniedTbsFingerprints(),
                original.observedAt(), original.expiresAt());
        assertThat(replacement).isEqualTo(original).isNotSameAs(original);
        var reads = new java.util.concurrent.atomic.AtomicInteger();
        var manager = new RuntimeProxyTrustManager(() -> reads.getAndIncrement() == 0 ? original : replacement,
                Clock.fixed(NOW, ZoneOffset.UTC));
        denied(manager, chain(proxy, intermediate));
    }

    @Test
    void rejectsAnEngineWithoutAHandshakeSession() throws Exception {
        var engine = javax.net.ssl.SSLContext.getDefault().createSSLEngine();
        var manager = manager(policy(Set.of()));
        assertThatThrownBy(() -> manager.checkClientTrusted(chain(proxy, intermediate), "EC", engine))
                .isInstanceOf(CertificateException.class)
                .hasMessage(REJECTED)
                .hasNoCause();
    }

    @Test
    void rejectsClientChecksWithoutATlsHandshakeContext() {
        var manager = manager(policy(Set.of()));
        var chain = chain(proxy, intermediate);
        assertThatThrownBy(() -> manager.checkClientTrusted(chain, "EC"))
                .isInstanceOf(CertificateException.class)
                .hasMessage(REJECTED)
                .hasNoCause();
        assertThatThrownBy(() -> manager.checkClientTrusted(chain, "EC", (java.net.Socket) null))
                .isInstanceOf(CertificateException.class)
                .hasMessage(REJECTED)
                .hasNoCause();
        assertThatThrownBy(() -> manager.checkClientTrusted(chain, "EC", (javax.net.ssl.SSLEngine) null))
                .isInstanceOf(CertificateException.class)
                .hasMessage(REJECTED)
                .hasNoCause();
    }

    @Test
    void acceptsEachAuthorityOnlyForItsExplicitCluster() throws Exception {
        var permitted = new RuntimeProxyTrustManager.Authority("lab", root.certificate());
        var foreign = new RuntimeProxyTrustManager.Authority("other", root.certificate());
        var policy = new RuntimeProxyTrustManager.Policy(List.of(foreign), Set.of(), NOW, NOW.plusSeconds(30));
        denied(manager(policy), chain(proxy, intermediate));
        assertThat(manager(new RuntimeProxyTrustManager.Policy(List.of(permitted), Set.of(), NOW, NOW.plusSeconds(30)))
                .verifyPeer(session(chain(proxy, intermediate)))
                .uri()).isEqualTo(URI);
    }

    @Test
    void deniesSignatureMalleationOfALeafAndIntermediate() throws Exception {
        var changedLeaf = malleated(proxy, intermediate);
        var changedIntermediate = malleated(intermediate, root);
        assertThat(manager(policy(Set.of()))
                .verifyPeer(session(new X509Certificate[]{changedLeaf, intermediate.certificate()}))
                .uri()).isEqualTo(URI);
        assertThat(manager(policy(Set.of()))
                .verifyPeer(session(new X509Certificate[]{proxy.certificate(), changedIntermediate}))
                .uri()).isEqualTo(URI);
        var leafPolicy = policy(
                Set.of(hash(proxy.certificate().getEncoded()), hash(proxy.certificate().getTBSCertificate())));
        var issuerPolicy = policy(Set
                .of(hash(intermediate.certificate().getEncoded()),
                        hash(intermediate.certificate().getTBSCertificate())));
        denied(manager(leafPolicy), chain(proxy, intermediate));
        denied(manager(leafPolicy), new X509Certificate[]{changedLeaf, intermediate.certificate()});
        denied(manager(issuerPolicy), new X509Certificate[]{proxy.certificate(), changedIntermediate});
    }

    @Test
    void rejectsConstrainedTrustAnchorsInsteadOfIgnoringTheirRestrictions() throws Exception {
        for (boolean pathLength : List.of(true, false)) {
            var pair = keys();
            var builder = builder(null, pair, true, KeyUsage.keyCertSign, null, null, NOW.minusSeconds(60),
                    NOW.plusSeconds(300));
            if (pathLength) {
                builder.replaceExtension(Extension.basicConstraints, true, new BasicConstraints(0));
            } else {
                var subtree = new org.bouncycastle.asn1.x509.GeneralSubtree(
                        new GeneralName(GeneralName.uniformResourceIdentifier, ".foreign.invalid"));
                builder
                        .addExtension(Extension.nameConstraints, true, new org.bouncycastle.asn1.x509.NameConstraints(
                                new org.bouncycastle.asn1.x509.GeneralSubtree[]{subtree}, null));
            }
            var certificate = new JcaX509CertificateConverter()
                    .getCertificate(
                            builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
            var authority = new Identity(pair, certificate);
            var issuer = issue(authority, true, KeyUsage.keyCertSign, null, null, NOW.minusSeconds(10),
                    NOW.plusSeconds(200));
            var leaf = client(issuer, uri());
            var policy = new RuntimeProxyTrustManager.Policy(authorities(certificate), Set.of(), NOW,
                    NOW.plusSeconds(30));
            denied(manager(policy), chain(leaf, issuer));
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "2.5.29.36,true",
            "2.5.29.36,false",
            "2.5.29.54,true",
            "2.5.29.54,false",
            "1.2.3.4,true",
            "1.2.3.4,false"})
    void rejectsOtherIgnoredTrustAnchorRestrictions(String oid, boolean critical) throws Exception {
        var pair = keys();
        var builder = builder(null, pair, true, KeyUsage.keyCertSign, null, null, NOW.minusSeconds(60),
                NOW.plusSeconds(300));
        org.bouncycastle.asn1.ASN1Encodable value = switch (oid) {
            case "2.5.29.36" -> new org.bouncycastle.asn1.x509.PolicyConstraints(BigInteger.ZERO, null);
            case "2.5.29.54" -> new org.bouncycastle.asn1.ASN1Integer(0);
            default -> org.bouncycastle.asn1.DERNull.INSTANCE;
        };
        builder.addExtension(new org.bouncycastle.asn1.ASN1ObjectIdentifier(oid), critical, value);
        var certificate = new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
        var authority = new Identity(pair, certificate);
        var leaf = client(authority, uri());
        var policy = new RuntimeProxyTrustManager.Policy(authorities(certificate), Set.of(), NOW, NOW.plusSeconds(30));
        denied(manager(policy), chain(leaf));
    }

    @Test
    void acceptsRuntimeCaKeyIdentifiers() throws Exception {
        var pair = keys();
        var builder = builder(null, pair, true, KeyUsage.keyCertSign, null, null, NOW.minusSeconds(60),
                NOW.plusSeconds(300));
        var identifiers = new org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils();
        builder
                .addExtension(Extension.subjectKeyIdentifier, false,
                        identifiers.createSubjectKeyIdentifier(pair.getPublic()));
        builder
                .addExtension(Extension.authorityKeyIdentifier, false,
                        identifiers.createAuthorityKeyIdentifier(pair.getPublic()));
        var certificate = new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
        var authority = new Identity(pair, certificate);
        var leaf = client(authority, uri());
        var policy = new RuntimeProxyTrustManager.Policy(authorities(certificate), Set.of(), NOW, NOW.plusSeconds(30));
        assertThat(manager(policy).verifyPeer(session(chain(leaf))).uri()).isEqualTo(URI);
    }

    @Test
    void rejectsAForeignClusterCaWhenBothClustersAreConfigured() throws Exception {
        var foreign = issue(null, true, KeyUsage.keyCertSign, null, null, NOW.minusSeconds(60), NOW.plusSeconds(300));
        var forged = client(foreign, uri());
        var authorities = List
                .of(new RuntimeProxyTrustManager.Authority("lab", root.certificate()),
                        new RuntimeProxyTrustManager.Authority("other", foreign.certificate()));
        var policy = new RuntimeProxyTrustManager.Policy(authorities, Set.of(), NOW, NOW.plusSeconds(30));
        assertThat(manager(policy).verifyPeer(session(chain(proxy, intermediate))).uri()).isEqualTo(URI);
        denied(manager(policy), chain(forged));
        assertThat(manager(policy).verifyPeer(session(chain(proxy, intermediate))).uri()).isEqualTo(URI);
    }

    static X509Certificate malleated(Identity identity, Identity issuer) throws Exception {
        var encoded = org.bouncycastle.asn1.x509.Certificate.getInstance(identity.certificate().getEncoded());
        var signature = org.bouncycastle.asn1.ASN1Sequence.getInstance(encoded.getSignature().getBytes());
        var r = org.bouncycastle.asn1.ASN1Integer.getInstance(signature.getObjectAt(0)).getPositiveValue();
        var s = org.bouncycastle.asn1.ASN1Integer.getInstance(signature.getObjectAt(1)).getPositiveValue();
        var order = ((java.security.interfaces.ECKey) issuer.keys().getPublic()).getParams().getOrder();
        var changed = new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{
                new org.bouncycastle.asn1.ASN1Integer(r),
                new org.bouncycastle.asn1.ASN1Integer(order.subtract(s))});
        var certificate = new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[]{
                encoded.getTBSCertificate(),
                encoded.getSignatureAlgorithm(),
                new org.bouncycastle.asn1.DERBitString(changed.getEncoded())});
        var result = new JcaX509CertificateConverter()
                .getCertificate(new org.bouncycastle.cert.X509CertificateHolder(certificate.getEncoded()));
        result.verify(issuer.keys().getPublic());
        assertThat(result.getEncoded()).isNotEqualTo(identity.certificate().getEncoded());
        assertThat(result.getTBSCertificate()).isEqualTo(identity.certificate().getTBSCertificate());
        return result;
    }

    static String hash(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    @Test
    void neverAuthenticatesServersOrAnUnverifiedSession() throws Exception {
        var manager = manager(policy(Set.of()));
        assertThatThrownBy(() -> manager.checkServerTrusted(chain(proxy, intermediate), "EC"))
                .isInstanceOf(CertificateException.class)
                .hasMessage(REJECTED)
                .hasNoCause();
        assertThatThrownBy(() -> manager.checkServerTrusted(chain(proxy, intermediate), "EC", (java.net.Socket) null))
                .isInstanceOf(CertificateException.class)
                .hasMessage(REJECTED)
                .hasNoCause();
        assertThatThrownBy(
                () -> manager.checkServerTrusted(chain(proxy, intermediate), "EC", (javax.net.ssl.SSLEngine) null))
                .isInstanceOf(CertificateException.class)
                .hasMessage(REJECTED)
                .hasNoCause();
        assertThatThrownBy(() -> manager.verifyPeer(null))
                .isInstanceOf(CertificateException.class)
                .hasMessage(REJECTED)
                .hasNoCause();
        SSLSession unverified = javax.net.ssl.SSLContext.getDefault().createSSLEngine().getSession();
        assertThatThrownBy(() -> manager.verifyPeer(unverified))
                .isInstanceOf(CertificateException.class)
                .hasMessage(REJECTED)
                .hasNoCause();
    }

    @Test
    void boundsAndCopiesTrustedPolicyInputs() {
        var anchors = new java.util.ArrayList<>(authorities(root.certificate()));
        var denied = new java.util.HashSet<String>();
        var policy = new RuntimeProxyTrustManager.Policy(anchors, denied, NOW, NOW.plusSeconds(30));
        anchors.clear();
        denied.add("a".repeat(64));
        assertThat(policy.authorities())
                .containsExactly(new RuntimeProxyTrustManager.Authority("lab", root.certificate()));
        assertThat(policy.deniedTbsFingerprints()).isEmpty();
        List<RuntimeProxyTrustManager.Authority> empty = List.of();
        var authorities = authorities(root.certificate());
        Set<String> noDenials = Set.of();
        Set<String> malformedDenial = Set.of("BAD");
        Instant shortExpiry = NOW.plusSeconds(1);
        Instant longExpiry = NOW.plusSeconds(31);
        assertThatThrownBy(() -> new RuntimeProxyTrustManager.Policy(empty, noDenials, NOW, shortExpiry))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RuntimeProxyTrustManager.Policy(authorities, malformedDenial, NOW, shortExpiry))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RuntimeProxyTrustManager.Policy(authorities, noDenials, NOW, longExpiry))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RuntimeProxyTrustManager.Policy(authorities, noDenials, NOW, NOW))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void revalidatesAnEstablishedMutualTlsSessionAfterTrustAndValidityChanges() throws Exception {
        Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        var authority = issue(null, true, KeyUsage.keyCertSign, null, null, now.minusSeconds(60), now.plusSeconds(900));
        var runner = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                new GeneralNames(uri()), now.minusSeconds(10), now.plusSeconds(300));
        var server = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")), now.minusSeconds(10),
                now.plusSeconds(300));
        var time = mock(Clock.class);
        when(time.instant()).thenReturn(now);
        var acceptedPolicy = new RuntimeProxyTrustManager.Policy(authorities(authority.certificate()), Set.of(), now,
                now.plusSeconds(30));
        var current = new AtomicReference<>(acceptedPolicy);
        var manager = new RuntimeProxyTrustManager(current::get, time);
        var engines = engines(authority, runner, server, manager, chain(runner, authority));
        var client = engines.client();
        var peer = engines.peer();
        try {
            handshake(client, peer);
            var session = peer.getSession();
            assertThat(session.getProtocol()).isEqualTo("TLSv1.3");
            assertThat(session.getPeerCertificates()[0]).isEqualTo(runner.certificate());
            assertThat(manager.verifyPeer(session).uri()).isEqualTo(URI);
            var fingerprint = HexFormat
                    .of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(runner.certificate().getTBSCertificate()));
            current
                    .set(new RuntimeProxyTrustManager.Policy(authorities(authority.certificate()), Set.of(fingerprint),
                            now, now.plusSeconds(30)));
            deniedSession(manager, session);
            current.set(acceptedPolicy);
            assertThat(manager.verifyPeer(session).uri()).isEqualTo(URI);
            var other = issue(null, true, KeyUsage.keyCertSign, null, null, now.minusSeconds(60), now.plusSeconds(900));
            current
                    .set(new RuntimeProxyTrustManager.Policy(authorities(other.certificate()), Set.of(), now,
                            now.plusSeconds(30)));
            deniedSession(manager, session);
            current.set(acceptedPolicy);
            assertThat(manager.verifyPeer(session).uri()).isEqualTo(URI);
            current
                    .set(new RuntimeProxyTrustManager.Policy(authorities(authority.certificate()), Set.of(),
                            now.minusSeconds(30), now));
            deniedSession(manager, session);
            current.set(acceptedPolicy);
            assertThat(manager.verifyPeer(session).uri()).isEqualTo(URI);
            Instant later = now.plusSeconds(301);
            when(time.instant()).thenReturn(later);
            current
                    .set(new RuntimeProxyTrustManager.Policy(authorities(authority.certificate()), Set.of(), later,
                            later.plusSeconds(30)));
            deniedSession(manager, session);
            assertThat(peer.isOutboundDone()).isFalse();
        } finally {
            engines.close();
        }
    }

    @Test
    void appliesTlsAlgorithmConstraintsToTheIssuingCaKey() throws Exception {
        Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        var authority = issue(null, true, KeyUsage.keyCertSign, null, null, now.minusSeconds(60), now.plusSeconds(900));
        var issuer = issue(authority, true, KeyUsage.keyCertSign, null, null, now.minusSeconds(30),
                now.plusSeconds(600));
        var runner = issue(issuer, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                new GeneralNames(uri()), now.minusSeconds(10), now.plusSeconds(300));
        var server = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")), now.minusSeconds(10),
                now.plusSeconds(300));
        var policy = new RuntimeProxyTrustManager.Policy(authorities(authority.certificate()), Set.of(), now,
                now.plusSeconds(30));
        var manager = new RuntimeProxyTrustManager(() -> policy, Clock.fixed(now, ZoneOffset.UTC));
        var chain = chain(runner, issuer, authority);
        for (boolean restricted : List.of(false, true, false)) {
            try (var connection = engines(authority, runner, server, manager, chain)) {
                if (restricted) {
                    var parameters = connection.peer().getSSLParameters();
                    parameters.setAlgorithmConstraints(new BlockedKey(issuer.certificate().getPublicKey()));
                    connection.peer().setSSLParameters(parameters);
                    assertThatThrownBy(() -> handshake(connection.client(), connection.peer()))
                            .isInstanceOf(javax.net.ssl.SSLHandshakeException.class);
                } else {
                    handshake(connection.client(), connection.peer());
                    assertThat(manager.verifyPeer(connection.peer().getSession()).uri()).isEqualTo(URI);
                }
            }
        }
    }

    @Test
    void rejectsMissingOrAmbiguousAuthorityClusters() {
        var certificate = root.certificate();
        for (String invalid : List.of("", "Lab", "lab.example", "-lab", "lab-", "a".repeat(64))) {
            assertThatThrownBy(() -> new RuntimeProxyTrustManager.Authority(invalid, certificate))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Invalid runtime certificate authority");
        }
        assertThatThrownBy(() -> new RuntimeProxyTrustManager.Authority(null, certificate))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RuntimeProxyTrustManager.Authority("lab", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    record BlockedKey(java.security.PublicKey key) implements java.security.AlgorithmConstraints {
        @Override
        public boolean permits(Set<java.security.CryptoPrimitive> primitives, String algorithm,
                java.security.AlgorithmParameters parameters) {
            return true;
        }

        @Override
        public boolean permits(Set<java.security.CryptoPrimitive> primitives, java.security.Key candidate) {
            return !key.equals(candidate);
        }

        @Override
        public boolean permits(Set<java.security.CryptoPrimitive> primitives, String algorithm,
                java.security.Key candidate, java.security.AlgorithmParameters parameters) {
            return !key.equals(candidate);
        }
    }

    static EnginePair engines(Identity authority, Identity runner, Identity server, RuntimeProxyTrustManager manager,
            X509Certificate[] clientChain) throws Exception {
        var serverContext = tlsContext(server, chain(server, authority), new javax.net.ssl.TrustManager[]{manager});
        var trusted = java.security.KeyStore.getInstance("PKCS12");
        trusted.load(null, null);
        trusted.setCertificateEntry("authority", authority.certificate());
        var factory = javax.net.ssl.TrustManagerFactory.getInstance("PKIX");
        factory.init(trusted);
        var clientContext = tlsContext(runner, clientChain, factory.getTrustManagers());
        var client = clientContext.createSSLEngine("localhost", 443);
        var peer = serverContext.createSSLEngine();
        client.setUseClientMode(true);
        peer.setUseClientMode(false);
        peer.setNeedClientAuth(true);
        var parameters = client.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        client.setSSLParameters(parameters);
        client.setEnabledProtocols(new String[]{"TLSv1.3"});
        peer.setEnabledProtocols(new String[]{"TLSv1.3"});
        return new EnginePair(client, peer);
    }

    record EnginePair(javax.net.ssl.SSLEngine client, javax.net.ssl.SSLEngine peer) implements AutoCloseable {
        @Override
        public void close() {
            client.closeOutbound();
            peer.closeOutbound();
            client.getSession().invalidate();
            peer.getSession().invalidate();
        }
    }

    static void handshake(javax.net.ssl.SSLEngine client, javax.net.ssl.SSLEngine server) throws Exception {
        var clientToServer = java.nio.ByteBuffer.allocate(65536);
        var serverToClient = java.nio.ByteBuffer.allocate(65536);
        var application = java.nio.ByteBuffer.allocate(65536);
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
        client.beginHandshake();
        server.beginHandshake();
        for (int step = 0; step < 128 && System.nanoTime() < deadline; step++) {
            transfer(client, server, clientToServer, application);
            transfer(server, client, serverToClient, application);
            if (client.getHandshakeStatus() == javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                    && server.getHandshakeStatus() == javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                return;
            }
        }
        throw new IllegalStateException("TLS handshake did not complete within its test budget");
    }

    static void transfer(javax.net.ssl.SSLEngine source, javax.net.ssl.SSLEngine destination, java.nio.ByteBuffer wire,
            java.nio.ByteBuffer application) throws Exception {
        runTasks(source);
        if (source.getHandshakeStatus() == javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            var result = source.wrap(java.nio.ByteBuffer.allocate(0), wire);
            assertThat(result.getStatus()).isEqualTo(javax.net.ssl.SSLEngineResult.Status.OK);
        }
        runTasks(destination);
        if (wire.position() > 0 || destination
                .getHandshakeStatus() == javax.net.ssl.SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
            wire.flip();
            application.clear();
            var result = destination.unwrap(wire, application);
            assertThat(result.getStatus())
                    .isIn(javax.net.ssl.SSLEngineResult.Status.OK,
                            javax.net.ssl.SSLEngineResult.Status.BUFFER_UNDERFLOW);
            wire.compact();
            runTasks(destination);
        }
    }

    static void runTasks(javax.net.ssl.SSLEngine engine) {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }

    static void deniedSession(RuntimeProxyTrustManager manager, SSLSession session) {
        assertThatThrownBy(() -> manager.verifyPeer(session))
                .isInstanceOf(CertificateException.class)
                .hasMessage(REJECTED)
                .hasNoCause();
    }

    static javax.net.ssl.SSLContext tlsContext(Identity identity, X509Certificate[] chain,
            javax.net.ssl.TrustManager[] trust) throws Exception {
        var store = java.security.KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("identity", identity.keys().getPrivate(), new char[0], chain);
        var factory = javax.net.ssl.KeyManagerFactory
                .getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        factory.init(store, new char[0]);
        var context = javax.net.ssl.SSLContext.getInstance("TLSv1.3");
        context.init(factory.getKeyManagers(), trust, null);
        return context;
    }

    static List<RuntimeProxyTrustManager.Authority> authorities(X509Certificate certificate) {
        return List.of(new RuntimeProxyTrustManager.Authority("lab", certificate));
    }

    static RuntimeProxyTrustManager manager(RuntimeProxyTrustManager.Policy policy) {
        return new RuntimeProxyTrustManager(() -> policy, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    static RuntimeProxyTrustManager.Policy policy(Set<String> denied) {
        return new RuntimeProxyTrustManager.Policy(authorities(root.certificate()), denied, NOW, NOW.plusSeconds(30));
    }

    static void denied(RuntimeProxyTrustManager manager, X509Certificate[] chain)
            throws javax.net.ssl.SSLPeerUnverifiedException {
        var session = session(chain);
        deniedSession(manager, session);
    }

    static SSLSession session(X509Certificate[] chain) throws javax.net.ssl.SSLPeerUnverifiedException {
        var session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(chain);
        return session;
    }

    static X509Certificate[] chain(Identity... identities) {
        return java.util.Arrays.stream(identities).map(Identity::certificate).toArray(X509Certificate[]::new);
    }

    static GeneralName uri() {
        return new GeneralName(GeneralName.uniformResourceIdentifier, URI);
    }

    static Identity client(Identity issuer, GeneralName name) throws Exception {
        return issue(issuer, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth, new GeneralNames(name),
                NOW.minusSeconds(10), NOW.plusSeconds(100));
    }

    static Identity issue(Identity issuer, boolean ca, Integer usage, KeyPurposeId purpose, GeneralNames names,
            Instant before, Instant after) throws Exception {
        var pair = keys();
        var builder = builder(issuer, pair, ca, usage, purpose, names, before, after);
        var signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .build(issuer == null ? pair.getPrivate() : issuer.keys().getPrivate());
        return new Identity(pair, new JcaX509CertificateConverter().getCertificate(builder.build(signer)));
    }

    static KeyPair keys() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    static JcaX509v3CertificateBuilder builder(Identity issuer, KeyPair keys, boolean ca, Integer usage,
            KeyPurposeId purpose, GeneralNames names, Instant before, Instant after) throws Exception {
        var name = new X500Name("CN=" + UUID.randomUUID());
        var issuerName = issuer == null ? name : new X500Name(issuer.certificate().getSubjectX500Principal().getName());
        var builder = new JcaX509v3CertificateBuilder(issuerName,
                new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16), Date.from(before), Date.from(after),
                name, keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (usage != null) {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        }
        if (purpose != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purpose));
        }
        if (names != null) {
            builder.addExtension(Extension.subjectAlternativeName, false, names);
        }
        return builder;
    }

    record Identity(KeyPair keys, X509Certificate certificate) {
    }

    record Profile(boolean ca, Integer usage, KeyPurposeId purpose) {
    }
}
