package com.otilm.ai.controller;

import com.otilm.ai.proxy.CoreEndpoint;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HashSet;
import java.util.Objects;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Administrator-only API endpoint and file references; construction is not native identity or readiness. */
public record KubernetesConfiguration(CoreEndpoint endpoint, Path serverCaFile, Path tokenFile) {
    public KubernetesConfiguration {
        if (endpoint == null || !endpoint.origin().getRawPath().isEmpty() || !absoluteFile(serverCaFile)
                || !absoluteFile(tokenFile)) {
            throw new ObservationFailure();
        }
    }

    public KubernetesApi open(Duration budget) {
        long started = System.nanoTime();
        if (budget == null || budget.isZero() || budget.isNegative() || budget.compareTo(Duration.ofSeconds(5)) > 0) {
            throw new ObservationFailure();
        }
        try {
            Path resolved = serverCaFile.toRealPath();
            var before = attributes(resolved);
            byte[] bytes;
            try (var input = Files.newInputStream(resolved)) {
                bytes = input.readNBytes(65537);
            }
            if (bytes.length == 0 || bytes.length > 65536 || bytes.length != before.size()) {
                throw new ObservationFailure();
            }
            var certificates = CertificateFactory
                    .getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(bytes));
            if (certificates.isEmpty() || certificates.size() > 16) {
                throw new ObservationFailure();
            }
            var roots = new HashSet<TrustAnchor>();
            for (var encoded : certificates) {
                var certificate = (X509Certificate) encoded;
                certificate.checkValidity();
                boolean[] usage = certificate.getKeyUsage();
                if (certificate.getBasicConstraints() < 0 || usage != null && (usage.length < 6 || !usage[5])) {
                    throw new ObservationFailure();
                }
                roots.add(new TrustAnchor(certificate, null));
            }
            var parameters = new PKIXBuilderParameters(roots, new X509CertSelector());
            parameters.setRevocationEnabled(false);
            var managers = TrustManagerFactory.getInstance("PKIX");
            managers.init(new CertPathTrustManagerParameters(parameters));
            var trust = SSLContext.getInstance("TLS");
            trust.init(new KeyManager[0], managers.getTrustManagers(), null);
            var after = attributes(resolved);
            if (!resolved.equals(serverCaFile.toRealPath()) || !Objects.equals(before.fileKey(), after.fileKey())
                    || before.size() != after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime())) {
                throw new ObservationFailure();
            }
            var api = new KubernetesApi(endpoint, trust, tokenFile, budget, started);
            api.remaining();
            return api;
        } catch (Throwable unavailable) {
            throw new ObservationFailure();
        }
    }

    private static BasicFileAttributes attributes(Path path) throws Exception {
        var state = Files.readAttributes(path, BasicFileAttributes.class);
        var mode = Files.getPosixFilePermissions(path);
        if (!state.isRegularFile() || state.fileKey() == null || state.size() <= 0 || state.size() > 65536
                || mode.contains(PosixFilePermission.OTHERS_WRITE) || mode.contains(PosixFilePermission.GROUP_WRITE)) {
            throw new ObservationFailure();
        }
        return state;
    }

    private static boolean absoluteFile(Path path) {
        return path != null && path.isAbsolute() && path.getParent() != null && path.equals(path.normalize());
    }
}
