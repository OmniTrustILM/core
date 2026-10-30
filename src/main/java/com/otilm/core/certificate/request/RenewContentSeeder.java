package com.otilm.core.certificate.request;

import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.v2.ClientCertificateRenewRequestDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.util.CertificateRequestUtils;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.X509RequestContentRenderer;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * Seeds what a successor inherits, for the structured renew wire and for the rekey CSR the platform builds itself. A
 * predecessor certificate yields its subject DN and SAN; the extensions of an issued certificate are the CA's and are
 * never seeded. A CSR source yields what the operator requested in it, extensions included, because the content is
 * authoritative for a structured connector.
 */
@Slf4j
public final class RenewContentSeeder {

    private RenewContentSeeder() {
    }

    /**
     * The typed identity for the structured renew wire: the CSR the operator supplied when there is one, and otherwise
     * the predecessor certificate. Empty when that identity cannot be carried in full, in which case the caller leaves
     * {@code requestContent} unset and the connector parses the CSR the wire already carries.
     */
    public static Optional<X509RequestContent> seed(Certificate oldCertificate, Certificate newCertificate,
            ClientCertificateRenewRequestDto request) {
        try {
            ParsedRequestContent parsed;
            X500Name sourceSubject;
            if (operatorSuppliedCsr(newCertificate, request)) {
                CertificateRequest csr = storedCsr(newCertificate);
                sourceSubject = csr.getSubject();
                parsed = X509RequestContentParser.parse(csr);
            } else {
                X509Certificate certificate = storedCertificate(oldCertificate);
                sourceSubject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
                parsed = X509RequestContentParser.parse(certificate);
            }
            if (hasMultiValuedRdn(sourceSubject)) {
                log
                        .warn("Not seeding structured renew content: the subject packs a multi-valued RDN, which typed content cannot express");
                return Optional.empty();
            }
            if (!parsed.unsupportedSans().isEmpty() || !parsed.unrepresentableExtensionValues().isEmpty()) {
                // The content is authoritative for the connector, so a partial one narrows what was requested.
                // Both lists hold what the typed model could not carry; either one means send nothing.
                log
                        .warn("Not seeding structured renew content: {} has no typed representation",
                                Stream
                                        .concat(parsed.unsupportedSans().stream(),
                                                parsed.unrepresentableExtensionValues().stream())
                                        .toList());
                return Optional.empty();
            }
            X509RequestContent content = parsed.content();
            if (!content.isRequestContentProvided()) {
                log.warn("Not seeding structured renew content: the source carries no identity to send");
                return Optional.empty();
            }
            return Optional.of(content);
        } catch (CertificateException | CertificateRequestException | RuntimeException e) {
            log.warn("Not seeding structured renew content: the identity to carry forward could not be read", e);
            return Optional.empty();
        }
    }

    /**
     * The SAN extension block a rekey CSR inherits, or null when the predecessor carries no SAN. Fails closed: the
     * platform builds this CSR itself, so nothing downstream can recover a SAN dropped here.
     */
    public static Extensions rekeySanExtensions(X509Certificate oldCertificate) {
        ParsedRequestContent parsed;
        try {
            parsed = X509RequestContentParser.parse(oldCertificate);
        } catch (RuntimeException e) {
            // Malformed ASN.1 surfaces as unchecked BouncyCastle exceptions whose messages may carry internals,
            // and this one reaches the client as a 422 body; log it and answer with fixed wording.
            log.warn("The certificate's identity could not be decoded for a re-keyed request", e);
            throw new ValidationException(
                    "The certificate's identity could not be decoded, so it cannot be carried into a re-keyed request");
        }
        if (!parsed.unsupportedSans().isEmpty()) {
            throw new ValidationException(
                    "The certificate carries a subject alternative name the platform cannot re-request: %s"
                            .formatted(String.join(", ", parsed.unsupportedSans())));
        }
        try {
            return X509RequestContentRenderer.toExtensions(parsed.content());
        } catch (IOException e) {
            log.warn("Failed to encode the subject alternative name of a re-keyed request", e);
            throw new ValidationException("Failed to build the subject alternative name of the re-keyed request");
        }
    }

    /**
     * Whether the subject packs two or more attributes into a single RDN, rendered {@code CN=host+O=Acme}. A typed
     * subject is a flat ordered list, so that grouping is lost and rebuilding the DN yields {@code CN=host,O=Acme} — a
     * different DER encoding and a different X.500 name, which no DN comparison treats as equal. The CSR beside the
     * content carries the true subject, so the content is dropped rather than sent altered.
     */
    private static boolean hasMultiValuedRdn(X500Name subject) {
        for (RDN rdn : subject.getRDNs()) {
            if (rdn.size() > 1) {
                return true;
            }
        }
        return false;
    }

    private static boolean operatorSuppliedCsr(Certificate newCertificate, ClientCertificateRenewRequestDto request) {
        return request != null && request.getRequest() != null && newCertificate.getCertificateRequest() != null;
    }

    private static CertificateRequest storedCsr(Certificate certificate) throws CertificateRequestException {
        CertificateRequestEntity stored = certificate.getCertificateRequest();
        return CertificateRequestUtils
                .createCertificateRequest(stored.getContent(), stored.getCertificateRequestFormat());
    }

    private static X509Certificate storedCertificate(Certificate certificate) throws CertificateException {
        return CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent());
    }
}
