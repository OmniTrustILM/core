package com.otilm.core.signing.tsa;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * A certificate chain where the first element is the end-entity (signing) certificate,
 * followed by any CA certificates in the chain.
 *
 * @param signingCertificate the end-entity certificate used for signing
 * @param chain              the full chain including the signing certificate as the first element
 */
public record CertificateChain(X509Certificate signingCertificate, List<X509Certificate> chain) {

    public CertificateChain {
        if (signingCertificate == null) {
            throw new IllegalArgumentException("signingCertificate must not be null");
        }
        if (chain == null) {
            throw new IllegalArgumentException("chain must not be null");
        }

        chain = List.copyOf(chain);
        if (chain.isEmpty() || !chain.getFirst().equals(signingCertificate)) {
            throw new IllegalArgumentException("chain must start with the signing certificate");
        }
        if (signingCertificate.getBasicConstraints() != -1) {
            throw new IllegalArgumentException("signingCertificate must be an end-entity certificate, not a CA");
        }
        for (int i = 1; i < chain.size(); i++) {
            if (chain.get(i).getBasicConstraints() == -1) {
                throw new IllegalArgumentException("certificate at index " + i + " in the chain must be a CA certificate");
            }
        }
    }

    public static CertificateChain of(X509Certificate signingCertificate) {
        return new CertificateChain(signingCertificate, List.of(signingCertificate));
    }

    public static CertificateChain of(List<X509Certificate> chain) {
        if (chain == null || chain.isEmpty()) {
            throw new IllegalArgumentException("chain must not be null or empty");
        }
        return new CertificateChain(chain.getFirst(), chain);
    }
}
