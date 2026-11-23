package com.otilm.core.security.ai;

import java.io.ByteArrayInputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/** Dedicated runtime client trust; certificate claims still require workload and operation authorization. */
public final class RuntimeProxyTrustManager extends X509ExtendedTrustManager {
    private static final String REJECTED = "Runtime proxy certificate rejected";
    private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    private static final Set<String> CRITICAL_CA_EXTENSIONS = Set.of("2.5.29.19", "2.5.29.15");
    private static final Set<String> SUPPORTED_CA_EXTENSIONS = Set
            .of("2.5.29.19", "2.5.29.15", "2.5.29.14", "2.5.29.35");
    private final Supplier<Policy> policies;
    private final Clock clock;
    private final RuntimePeerRole expectedRole;

    public RuntimeProxyTrustManager(Supplier<Policy> policies, Clock clock) {
        this(policies, clock, RuntimePeerRole.RUNNER_PROXY);
    }

    public RuntimeProxyTrustManager(Supplier<Policy> policies, Clock clock, RuntimePeerRole expectedRole) {
        this.policies = Objects.requireNonNull(policies);
        this.clock = Objects.requireNonNull(clock);
        this.expectedRole = Objects.requireNonNull(expectedRole);
    }

    RuntimePeerRole expectedRole() {
        return expectedRole;
    }

    /** Revalidates the actual TLS peer against the current policy, including established sessions. */
    public RuntimeProxyCertificateClaims verifyPeer(SSLSession session) throws CertificateException {
        requireRunnerRole();
        return verifyWorkloadPeer(session).subject();
    }

    public RuntimePeer verifyWorkloadPeer(SSLSession session) throws CertificateException {
        try {
            Verification verified = verify(session.getPeerCertificates());
            finish(verified);
            return verified.peer();
        } catch (GeneralSecurityException | SSLPeerUnverifiedException | RuntimeException rejected) {
            throw rejected();
        }
    }

    /** Called only by the connector Valve with the native Coyote TLS certificate attribute. */
    RuntimeProxyCertificateClaims verifyNativeChain(X509Certificate[] certificates) throws CertificateException {
        requireRunnerRole();
        return verifyWorkloadNativeChain(certificates).subject();
    }

    RuntimePeer verifyWorkloadNativeChain(X509Certificate[] certificates) throws CertificateException {
        try {
            Verification verified = verify(certificates);
            finish(verified);
            return verified.peer();
        } catch (GeneralSecurityException | RuntimeException rejected) {
            throw rejected();
        }
    }

    private void requireRunnerRole() throws CertificateException {
        if (expectedRole != RuntimePeerRole.RUNNER_PROXY) {
            throw rejected();
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw rejected();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        if (!(socket instanceof SSLSocket tls) || !tls.isConnected() || tls.getHandshakeSession() == null) {
            throw rejected();
        }
        checkClient(chain, authType, tls, null);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        if (engine == null || engine.getHandshakeSession() == null) {
            throw rejected();
        }
        checkClient(chain, authType, null, engine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw rejected();
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        throw rejected();
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        throw rejected();
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    private void checkClient(X509Certificate[] chain, String authType, Socket socket, SSLEngine engine)
            throws CertificateException {
        try {
            if (authType == null || authType.isBlank() || authType.length() > 64) {
                throw rejected();
            }
            Verification verified = verify(chain);
            X509ExtendedTrustManager delegate = delegate(verified);
            X509Certificate[] certificates = verified.chain().toArray(X509Certificate[]::new);
            if (socket != null) {
                delegate.checkClientTrusted(certificates, authType, socket);
            } else {
                delegate.checkClientTrusted(certificates, authType, engine);
            }
            finish(verified);
        } catch (GeneralSecurityException | RuntimeException rejected) {
            throw rejected();
        }
    }

    private Verification verify(Certificate[] presented) throws CertificateException {
        try {
            Instant now = clock.instant();
            Policy policy = policies.get();
            if (policy == null || now.isBefore(policy.observedAt()) || !now.isBefore(policy.expiresAt())
                    || presented == null || presented.length == 0 || presented.length > 4) {
                throw rejected();
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509", "SUN");
            List<X509Certificate> chain = new ArrayList<>(presented.length);
            for (Certificate certificate : presented) {
                X509Certificate parsed = detached(certificate, factory);
                if (policy.deniedTbsFingerprints().contains(fingerprint(parsed))) {
                    throw rejected();
                }
                chain.add(parsed);
            }
            RuntimePeer peer = claims(chain.getFirst(), expectedRole);
            Set<TrustAnchor> anchors = anchors(policy, peer.subject().cluster(), now, factory);
            X509Certificate last = chain.getLast();
            if (anchors.stream().anyMatch(anchor -> anchor.getTrustedCert().equals(last))) {
                chain.removeLast();
            }
            PKIXParameters parameters = new PKIXParameters(anchors);
            parameters.setDate(java.util.Date.from(now));
            parameters.setRevocationEnabled(false);
            var validated = (PKIXCertPathValidatorResult) CertPathValidator
                    .getInstance("PKIX", "SUN")
                    .validate(factory.generateCertPath(chain), parameters);
            return new Verification(peer, List.copyOf(chain), Set.copyOf(anchors),
                    validated.getTrustAnchor().getTrustedCert(), policy, now);
        } catch (GeneralSecurityException | RuntimeException rejected) {
            throw rejected();
        }
    }

    private void finish(Verification verified) throws CertificateException {
        Instant completed = clock.instant();
        if (completed.isBefore(verified.started()) || completed.isBefore(verified.policy().observedAt())
                || !completed.isBefore(verified.policy().expiresAt()) || verified.policy() != policies.get()) {
            throw rejected();
        }
        var date = java.util.Date.from(completed);
        for (X509Certificate certificate : verified.chain()) {
            certificate.checkValidity(date);
        }
        verified.anchor().checkValidity(date);
    }

    private static X509ExtendedTrustManager delegate(Verification verified) throws GeneralSecurityException {
        PKIXBuilderParameters parameters = new PKIXBuilderParameters(verified.anchors(), new X509CertSelector());
        parameters.setDate(java.util.Date.from(verified.started()));
        parameters.setRevocationEnabled(false);
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
        factory.init(new CertPathTrustManagerParameters(parameters));
        for (var manager : factory.getTrustManagers()) {
            if (manager instanceof X509ExtendedTrustManager extended) {
                return extended;
            }
        }
        throw rejected();
    }

    private static Set<TrustAnchor> anchors(Policy policy, String cluster, Instant now, CertificateFactory factory)
            throws GeneralSecurityException {
        Set<TrustAnchor> anchors = new HashSet<>();
        for (Authority configured : policy.authorities()) {
            if (!cluster.equals(configured.cluster())) {
                continue;
            }
            X509Certificate certificate = detached(configured.certificate(), factory);
            boolean[] usage = certificate.getKeyUsage();
            if (!unconstrainedAnchor(certificate) || usage == null || usage.length <= 5 || !usage[5]) {
                throw rejected();
            }
            if (!now.isBefore(certificate.getNotBefore().toInstant())
                    && now.isBefore(certificate.getNotAfter().toInstant())
                    && !policy.deniedTbsFingerprints().contains(fingerprint(certificate))) {
                anchors.add(new TrustAnchor(certificate, null));
            }
        }
        return anchors;
    }

    static boolean unconstrainedAnchor(X509Certificate certificate) {
        Set<String> critical = certificate.getCriticalExtensionOIDs();
        Set<String> noncritical = certificate.getNonCriticalExtensionOIDs();
        return certificate.getBasicConstraints() == Integer.MAX_VALUE
                && (critical == null || CRITICAL_CA_EXTENSIONS.containsAll(critical))
                && (noncritical == null || SUPPORTED_CA_EXTENSIONS.containsAll(noncritical));
    }

    private static X509Certificate detached(Certificate certificate, CertificateFactory factory)
            throws CertificateException {
        if (!(certificate instanceof X509Certificate)) {
            throw rejected();
        }
        byte[] encoded = certificate.getEncoded();
        if (encoded.length == 0 || encoded.length > 16384) {
            throw rejected();
        }
        ByteArrayInputStream input = new ByteArrayInputStream(encoded);
        X509Certificate parsed = (X509Certificate) factory.generateCertificate(input);
        if (input.available() != 0) {
            throw rejected();
        }
        return parsed;
    }

    private static RuntimePeer claims(X509Certificate leaf, RuntimePeerRole expectedRole) throws CertificateException {
        boolean[] usage = leaf.getKeyUsage();
        if (leaf.getBasicConstraints() >= 0 || usage == null || usage.length == 0 || !usage[0]
                || (usage.length > 5 && usage[5]) || (usage.length > 6 && usage[6])
                || !List.of(CLIENT_AUTH).equals(leaf.getExtendedKeyUsage())) {
            throw rejected();
        }
        var alternatives = leaf.getSubjectAlternativeNames();
        if (alternatives == null || alternatives.size() != 1) {
            throw rejected();
        }
        List<?> name = alternatives.iterator().next();
        if (name.size() != 2 || !Integer.valueOf(6).equals(name.getFirst()) || !(name.get(1) instanceof String uri)) {
            throw rejected();
        }
        return expectedRole.parseCertificateUri(uri).orElseThrow(RuntimeProxyTrustManager::rejected);
    }

    private static String fingerprint(X509Certificate certificate) throws GeneralSecurityException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getTBSCertificate()));
    }

    private static CertificateException rejected() {
        return new CertificateException(REJECTED);
    }

    private record Verification(RuntimePeer peer, List<X509Certificate> chain, Set<TrustAnchor> anchors,
            X509Certificate anchor, Policy policy, Instant started) {
    }

    public record Authority(String cluster, X509Certificate certificate) {
        public Authority {
            if (cluster == null || cluster.length() > 63 || !cluster.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
                    || certificate == null) {
                throw new IllegalArgumentException("Invalid runtime certificate authority");
            }
        }
    }

    public record Policy(List<Authority> authorities, Set<String> deniedTbsFingerprints, Instant observedAt,
            Instant expiresAt) {
        public Policy {
            if (authorities == null || authorities.isEmpty() || authorities.size() > 8
                    || authorities.stream().anyMatch(Objects::isNull) || deniedTbsFingerprints == null
                    || deniedTbsFingerprints.size() > 4096
                    || deniedTbsFingerprints.stream().anyMatch(value -> value == null || !value.matches("[0-9a-f]{64}"))
                    || observedAt == null || expiresAt == null || !observedAt.isBefore(expiresAt)
                    || Duration.between(observedAt, expiresAt).compareTo(Duration.ofSeconds(30)) > 0) {
                throw new IllegalArgumentException("Invalid runtime trust policy");
            }
            authorities = List.copyOf(authorities);
            deniedTbsFingerprints = Set.copyOf(deniedTbsFingerprints);
        }
    }
}
