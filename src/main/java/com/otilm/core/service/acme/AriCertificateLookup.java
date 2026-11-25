package com.otilm.core.service.acme;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.util.CertificateUtil;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/** Finds the certificate an RFC 9773 certificate identifier names among the issued certificates of an RA profile. */
@Component
public class AriCertificateLookup {

    private static final Logger logger = LoggerFactory.getLogger(AriCertificateLookup.class);

    private CertificateRepository certificateRepository;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    /** The issued, non-archived certificate of the RA profile with the identifier's serial number and issuer key. */
    public Optional<Certificate> find(UUID raProfileUuid, AriCertId id) {
        return certificateRepository
                .findIssuedNotArchivedBySerialNumberAndRaProfile(id.serialHex(), raProfileUuid)
                .stream()
                .filter(candidate -> issuedUnderRequestedKey(candidate, id))
                .findFirst();
    }

    /** The certificate table stores no authority key identifier, so it is read from the stored certificate. */
    private static boolean issuedUnderRequestedKey(Certificate candidate, AriCertId id) {
        String content = candidate.getContentData();
        if (content == null) {
            return false;
        }
        try {
            X509Certificate x509 = CertificateUtil.getX509Certificate(content);
            return id.matchesIssuerOf(x509);
        } catch (CertificateException | IllegalArgumentException e) {
            logger
                    .warn("Stored certificate {} cannot be parsed: {}", candidate.getUuid(),
                            e.getClass().getSimpleName());
            return false;
        }
    }
}
