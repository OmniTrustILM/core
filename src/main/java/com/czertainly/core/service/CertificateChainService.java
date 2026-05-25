package com.czertainly.core.service;

import com.czertainly.core.dao.entity.Certificate;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * <p>Performs certificate-chain reconstruction (looking up issuers in the local inventory, optionally downloading
 * missing chain certificates from the AIA extension) and persisting the resulting issuer references through
 * {@link com.czertainly.core.service.writer.CertificateChainWriter}.</p>
 */
public interface CertificateChainService {

    /**
     * Reconstructs the issuer reference for {@code certificate} from its parsed content.
     * No-op if the certificate has no content.
     */
    void updateCertificateChain(Certificate certificate) throws CertificateException;

    /**
     * Reconstructs the issuer reference for {@code certificate} given its already-parsed X.509 form. First searches
     * the local inventory by subject DN; if no issuer is found, downloads the chain from the certificate's AIA extension
     * and inserts each downloaded certificate atomically.
     */
    void updateCertificateChain(Certificate certificate, X509Certificate subCert) throws CertificateException;

    /**
     * Returns the ancestor chain of {@code certificate} from the local inventory, optionally including {@code certificate} itself as the leaf.
     */
    List<Certificate> getCertificateChainInternal(Certificate certificate, boolean withEndCertificate);

    /**
     * Attempts to extend the chain to a self-signed root. Returns {@code true} if the chain ends with a self-signed
     * certificate.
     */
    boolean completeCertificateChain(Certificate lastCertificate, List<Certificate> certificateChain);

    /**
     * Builds {@code certificateChain} from the local inventory using {@code certificate}as the starting point.
     * Clears the issuer reference on the deepest reachable certificate if a dangling FK is detected.
     * Returns the deepest certificate reached.
     */
    Certificate constructCertificateChainFromInventory(Certificate certificate, List<Certificate> certificateChain);
}
