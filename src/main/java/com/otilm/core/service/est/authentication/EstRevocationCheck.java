package com.otilm.core.service.est.authentication;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.core.dao.repository.CrlRepository;
import com.otilm.core.dao.repository.CrlRepository.CrlStateView;
import com.otilm.core.service.CrlService;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.util.CrlUtil;
import com.otilm.core.util.OcspUtil;
import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.springframework.stereotype.Component;

/**
 * Checks that no certificate of a validated client certificate path is revoked, from the client certificate up to the
 * last one below the trust anchor. The anchor itself is not checked: the EST Profile trusts it as it is.
 * <p>
 * The OCSP responders that a certificate names are asked in turn, and the first trusted answer of good or revoked
 * decides. An answer of unknown, one that cannot be trusted, or none at all passes the question on to the next
 * responder and then to the CRL of the certificate's distribution points, which decides while it is current, together
 * with the delta CRL when the certificate names one. Only a certificate that names no OCSP responder, no CRL
 * distribution point and no delta CRL is accepted without an answer, and an authority information access extension that
 * cannot be read counts as naming a responder. When the sources it names give none, the client is told to try again
 * later: no responder answers or none has a URL, the CRL cannot be fetched, does not verify or is no longer current,
 * its delta CRL does not fit it, cannot be fetched or is no longer current, or the certificate names no CRL location
 * that can be fetched.
 * <p>
 * The CRL is read through {@link CrlService}, which stores it in transactions of its own, so no transaction is open
 * around this check.
 */
@Slf4j
@Component
public class EstRevocationCheck {

    private final CrlService crlService;
    private final CrlRepository crlRepository;

    public EstRevocationCheck(CrlService crlService, CrlRepository crlRepository) {
        this.crlService = crlService;
        this.crlRepository = crlRepository;
    }

    /**
     * @param route the route of the request, whose realm a refusal names
     * @param path the validated path, starting with the client certificate
     * @param anchor the trust anchor of the path, whose certificate issued the last certificate of the path
     * @throws EstException carrying the realm of the route: {@link EstError#CERTIFICATE_REJECTED} when a certificate of
     * the path is revoked, {@link EstError#SERVICE_UNAVAILABLE} when the revocation sources it names cannot answer
     */
    public void verify(EstRoute route, CertPath path, TrustAnchor anchor) {
        List<X509Certificate> certificates = path.getCertificates().stream().map(X509Certificate.class::cast).toList();
        for (int index = 0; index < certificates.size(); index++) {
            X509Certificate issuer = index + 1 < certificates.size()
                    ? certificates.get(index + 1)
                    : anchor.getTrustedCert();
            verify(route, certificates.get(index), issuer);
        }
    }

    private void verify(EstRoute route, X509Certificate certificate, X509Certificate issuer) {
        String serialNumber = certificate.getSerialNumber().toString(16);
        try {
            List<String> ocspUrls = ocspUrlsOf(certificate);
            for (String ocspUrl : ocspUrls) {
                CertificateValidationStatus status = askOcspResponder(certificate, issuer, ocspUrl, serialNumber);
                if (status == CertificateValidationStatus.REVOKED) {
                    throw refused(route, EstError.CERTIFICATE_REJECTED,
                            "the OCSP responder " + ocspUrl + " reports serial number " + serialNumber + " revoked");
                }
                if (status == CertificateValidationStatus.VALID) {
                    log.debug("The OCSP responder {} reports serial number {} good", ocspUrl, serialNumber);
                    return;
                }
                log
                        .debug("The OCSP responder {} did not report serial number {} good or revoked", ocspUrl,
                                serialNumber);
            }
            checkCrl(route, certificate, issuer, serialNumber);
        } catch (IOException | ValidationException e) {
            throw refused(route, EstError.SERVICE_UNAVAILABLE,
                    "the revocation of serial number " + serialNumber + " cannot be checked: " + e.getMessage());
        }
    }

    /**
     * The entries and the dates of the CRL are read in one statement, since another request may refresh the CRL between
     * two, and EST would then accept on the absence from one version and the freshness of the other.
     * <p>
     * {@link CrlService#getCurrentCrl} finds no CRL both for a certificate without CRL distribution points and for one
     * whose distribution points name no URI or that names only a delta CRL. A certificate that names a revocation
     * source of any kind is not one that carries no revocation information.
     */
    private void checkCrl(EstRoute route, X509Certificate certificate, X509Certificate issuer, String serialNumber)
            throws IOException {
        UUID crlUuid = crlService.getCurrentCrl(certificate, issuer);
        if (crlUuid == null) {
            if (namesRevocationSource(certificate)) {
                throw refused(route, EstError.SERVICE_UNAVAILABLE,
                        "no revocation source that serial number " + serialNumber + " names gave an answer");
            }
            log.debug("Serial number {} names no revocation source", serialNumber);
            return;
        }
        CrlStateView state = crlRepository.findStateByUuidAndSerialNumber(crlUuid, serialNumber).orElse(null);
        if (state == null) {
            throw refused(route, EstError.SERVICE_UNAVAILABLE,
                    "the CRL for serial number " + serialNumber + " is no longer stored");
        }
        if (state.lists()) {
            throw refused(route, EstError.CERTIFICATE_REJECTED,
                    "the CRL of its issuer lists serial number " + serialNumber);
        }
        requireCurrent(route, certificate, state, serialNumber);
        log.debug("The CRL of its issuer does not list serial number {}", serialNumber);
    }

    /**
     * {@link CrlService} keeps a stored CRL when no newer one can be had, and keeps the base CRL in force when the
     * delta CRL cannot be fetched, so absence from the CRL proves nothing unless the CRL, and the delta CRL that the
     * certificate names, are still current. A listing proves revocation whatever the freshness, so this is asked only
     * of a serial number that the CRL does not list.
     */
    private static void requireCurrent(EstRoute route, X509Certificate certificate, CrlStateView state,
            String serialNumber) {
        if (!CrlUtil.isCurrent(state.getNextUpdate())) {
            throw refused(route, EstError.SERVICE_UNAVAILABLE,
                    "the CRL for serial number " + serialNumber + " is no longer current");
        }
        boolean deltaCrlNamed = certificate.getExtensionValue(Extension.freshestCRL.getId()) != null;
        if (deltaCrlNamed && !CrlUtil.isCurrent(state.getNextUpdateDelta())) {
            throw refused(route, EstError.SERVICE_UNAVAILABLE,
                    "the delta CRL for serial number " + serialNumber + " is missing or no longer current");
        }
    }

    /**
     * An OCSP responder counts whether or not it has a URL that can be asked, and a CRL distribution point or a delta
     * CRL whether or not it names a location that can be fetched.
     */
    private static boolean namesRevocationSource(X509Certificate certificate) {
        return certificate.getExtensionValue(Extension.cRLDistributionPoints.getId()) != null
                || certificate.getExtensionValue(Extension.freshestCRL.getId()) != null
                || namesOcspResponder(certificate);
    }

    /**
     * An extension that cannot be read counts as naming a responder, since nothing shows that it names none.
     * BouncyCastle reports an extension that is not built as it is defined with an unchecked exception, an
     * {@code IllegalArgumentException} or an {@code IllegalStateException}, according to what is wrong with it, and one
     * that is no ASN.1 encoding with an {@link IOException}.
     */
    private static boolean namesOcspResponder(X509Certificate certificate) {
        byte[] extension = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (extension == null) {
            return false;
        }
        try {
            AccessDescription[] accessDescriptions = AuthorityInformationAccess
                    .getInstance(JcaX509ExtensionUtils.parseExtensionValue(extension))
                    .getAccessDescriptions();
            return Arrays
                    .stream(accessDescriptions)
                    .anyMatch(description -> AccessDescription.id_ad_ocsp.equals(description.getAccessMethod()));
        } catch (IOException | RuntimeException e) {
            return true;
        }
    }

    /**
     * @return the URLs of the OCSP responders that the certificate names; none when its authority information access
     * extension cannot be read
     */
    private static List<String> ocspUrlsOf(X509Certificate certificate) {
        try {
            return OcspUtil.getOcspUrlFromCertificate(certificate);
        } catch (IOException | RuntimeException e) {
            return List.of();
        }
    }

    /**
     * Every failure to get a trusted answer, an unreachable responder or an answer that does not verify, is handled as
     * no answer at all, so the next source is asked.
     */
    private static CertificateValidationStatus askOcspResponder(X509Certificate certificate, X509Certificate issuer,
            String ocspUrl, String serialNumber) {
        try {
            return OcspUtil.checkOcsp(certificate, issuer, ocspUrl);
        } catch (Exception e) {
            log
                    .debug("The OCSP responder {} gave no trusted answer for serial number {}: {}", ocspUrl,
                            serialNumber, e.getMessage());
            return CertificateValidationStatus.FAILED;
        }
    }

    private static EstException refused(EstRoute route, EstError error, String reason) {
        log.debug("EST client certificate refused as {} for realm {}: {}", error, route.realm(), reason);
        return new EstException(error, route.realm());
    }
}
