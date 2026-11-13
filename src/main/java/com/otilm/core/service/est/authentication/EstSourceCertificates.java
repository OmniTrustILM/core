package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.dao.repository.EstReenrollmentSource;
import com.otilm.core.dao.repository.X509CertificateRepository;
import com.otilm.core.security.authn.ForwardedClientCertificateParser.ParsedCertificate;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.CryptographyUtil;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Finds the certificate that an EST client renews: the client certificate that the proxy forwarded, under every
 * authentication policy. The inventory is the trust, so the certificate is neither chained to a trusted CA nor checked
 * for revocation online: the platform issued it through the EST Profile of the route and records its revocation.
 * <p>
 * The certificate is accepted when it is issued, not archived and inside its validity, has a validation status that
 * does not forbid renewal, belongs to the RA Profile of the route, was issued through the EST Profile of the route and
 * has no alternative key. Every other case is the same {@link EstError#CERTIFICATE_REJECTED}, so that a client learns
 * nothing about which certificates the inventory holds; the reason goes only to the debug log.
 * <p>
 * It reads the inventory without a transaction, so that a request that waits afterwards holds no pooled connection.
 */
@Slf4j
@Component
public class EstSourceCertificates {

    private static final Set<CertificateValidationStatus> FORBIDDEN_STATUSES = EnumSet
            .of(CertificateValidationStatus.REVOKED, CertificateValidationStatus.EXPIRED,
                    CertificateValidationStatus.INVALID);

    private final X509CertificateRepository certificateRepository;

    public EstSourceCertificates(X509CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    /**
     * @return the certificate in the inventory that the client presented
     * @throws EstException {@link EstError#CERTIFICATE_REJECTED} carrying the realm of the route, when the client
     * forwarded no certificate or one that cannot be read, or the inventory holds none that may be renewed through the
     * route
     */
    public EstSourceCertificate authenticate(EstRoute route, @Sensitive EstClientCredentials credentials) {
        ParsedCertificate presented = credentials
                .certificate()
                .orElseThrow(() -> refused(route,
                        credentials.certificateMalformed()
                                ? "the client certificate cannot be read"
                                : "no client certificate was forwarded"));
        String fingerprint = presented.thumbprint();
        EstReenrollmentSource stored = certificateRepository
                .findEstReenrollmentSource(fingerprint)
                .orElseThrow(() -> refused(route, "the certificate " + fingerprint + " is not in the inventory"));
        Optional<String> reason = reasonToRefuse(route, stored, new Date());
        if (reason.isPresent()) {
            throw refused(route, "the certificate " + fingerprint + " " + reason.get());
        }
        PublicKey publicKey = publicKeyOf(route, presented);
        return new EstSourceCertificate(stored.getUuid(), fingerprint, publicKey, stored.getSubjectDn(),
                stored.getSubjectAlternativeNames(), stored.getNotBefore(), stored.getNotAfter());
    }

    private static PublicKey publicKeyOf(EstRoute route, ParsedCertificate presented) {
        try {
            X509Certificate certificate = CertificateUtil.parseCertificate(presented.content());
            return CryptographyUtil.decodePublicKey(certificate.getPublicKey().getEncoded());
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            log.debug("The public key of the certificate {} cannot be read", presented.thumbprint(), e);
            throw refused(route, "the public key of the certificate " + presented.thumbprint() + " cannot be read");
        }
    }

    private static Optional<String> reasonToRefuse(EstRoute route, EstReenrollmentSource stored, Date now) {
        if (stored.getState() != CertificateState.ISSUED) {
            return Optional.of("is in state " + stored.getState());
        }
        if (Boolean.TRUE.equals(stored.getArchived())) {
            return Optional.of("is archived");
        }
        if (stored.getNotBefore() == null || stored.getNotAfter() == null) {
            return Optional.of("has no validity period");
        }
        if (now.before(stored.getNotBefore())) {
            return Optional.of("is not yet valid");
        }
        if (now.after(stored.getNotAfter())) {
            return Optional.of("has expired");
        }
        if (FORBIDDEN_STATUSES.contains(stored.getValidationStatus())) {
            return Optional.of("has validation status " + stored.getValidationStatus());
        }
        if (!route.raProfile().getUuid().equals(stored.getRaProfileUuid())) {
            return Optional.of("belongs to another RA Profile");
        }
        if (stored.getProtocol() != CertificateProtocol.EST
                || !route.estProfile().getUuid().equals(stored.getProtocolProfileUuid())) {
            return Optional.of("was not issued through this EST Profile");
        }
        if (stored.getAltKeyFingerprint() != null) {
            return Optional.of("has an alternative key");
        }
        return Optional.empty();
    }

    private static EstException refused(EstRoute route, String reason) {
        log.debug("EST re-enrolment refused for realm {}: {}", route.realm(), reason);
        return new EstException(EstError.CERTIFICATE_REJECTED, route.realm());
    }
}
