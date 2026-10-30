package com.otilm.core.service.notifications;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Exports the certificate's stored Base64 DER -- public material by definition, no key material exists in the
 * certificate content. Certificates in request or pre-registered states have no DER yet and yield no content.
 */
@Component
public class CertificateContentExporter implements NotificationObjectContentExporter {

    static final String FORMAT_X509_DER_BASE64 = "X509_DER_BASE64";

    private final CertificateRepository certificateRepository;

    @Autowired
    public CertificateContentExporter(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Override
    public Resource resource() {
        return Resource.CERTIFICATE;
    }

    @Override
    public String format() {
        return FORMAT_X509_DER_BASE64;
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<String> export(UUID objectUuid) {
        return certificateRepository.findByUuid(objectUuid).map(Certificate::getContentData);
    }
}
