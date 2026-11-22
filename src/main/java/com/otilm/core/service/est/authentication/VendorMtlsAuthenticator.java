package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.registration.RegistrationIdentityMatcher;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.Candidate;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.MatchResult;
import com.otilm.core.service.registration.RegistrationIdentityMatcher.Outcome;
import com.otilm.core.util.CertificateUtil;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Component;

/**
 * Authenticates a client by the certificate that the TLS proxy forwarded, issued under a CA certificate that the EST
 * Profile trusts. The request must ask for the identity that the certificate holds: the same subject and the same
 * subject alternative names, compared as the identity of a pre-registered certificate is. The client is identified by
 * its certificate. Basic credentials are not read, as a policy never falls back to another one.
 */
@Slf4j
@Component
public class VendorMtlsAuthenticator implements EstAuthenticator {

    /**
     * The matcher names a candidate by the UUID of its inventory row, which a forwarded certificate has none of. The
     * UUID of the result is not used.
     */
    private static final UUID NOT_AN_INVENTORY_ROW = new UUID(0L, 0L);

    private final EstClientCertificateTrust trust;

    public VendorMtlsAuthenticator(EstClientCertificateTrust trust) {
        this.trust = trust;
    }

    @Override
    public EstAuthenticationPolicy policy() {
        return EstAuthenticationPolicy.VENDOR_MTLS;
    }

    /**
     * @return the client, identified as {@code certificate:<SHA-256 thumbprint>} by its certificate
     * @throws EstException carrying the realm of the route: what the trust check refuses the certificate with, or
     * {@link EstError#IDENTITY_MISMATCH} when the request asks for another subject or other subject alternative names
     * than the certificate holds. The RA usage of the certificate is not required.
     */
    @Override
    public EstClient authenticate(EstRoute route, @Sensitive EstClientCredentials credentials, CertificateRequest csr) {
        X509Certificate leaf = trust.verify(route, credentials, false);
        String thumbprint = credentials.certificate().orElseThrow().thumbprint();
        MatchResult match = RegistrationIdentityMatcher
                .match(csr.getSubject(), CertificateUtil.getSAN(csr), List.of(identityOf(leaf)));
        if (match.outcome() != Outcome.MATCHED) {
            throw refused(route, thumbprint, match.outcome());
        }
        return EstClient.ofCertificate(EstAuthenticationPolicy.VENDOR_MTLS, thumbprint);
    }

    /**
     * The subject and the subject alternative names of the certificate, in the form in which the matcher reads the
     * identity of a registration. The matcher parses the subject text again, so the subject is rendered with escapes:
     * the style that the inventory stores a subject in writes a value as it is, and a value that holds a separator
     * would be read as several names, or not at all. The subject alternative names are serialized as
     * {@link CertificateUtil} stores them.
     */
    private static Candidate identityOf(X509Certificate leaf) {
        X500Name subject = X500Name.getInstance(BCStyle.INSTANCE, leaf.getSubjectX500Principal().getEncoded());
        String subjectAlternativeNames = CertificateUtil.serializeSans(CertificateUtil.getSAN(leaf));
        return new Candidate(NOT_AN_INVENTORY_ROW, subject.toString(), subjectAlternativeNames);
    }

    private static EstException refused(EstRoute route, String thumbprint, Outcome outcome) {
        log
                .debug("EST client certificate {} refused under the vendorMtls policy for realm {}: {}", thumbprint,
                        route.realm(), outcome);
        return new EstException(EstError.IDENTITY_MISMATCH, route.realm());
    }
}
