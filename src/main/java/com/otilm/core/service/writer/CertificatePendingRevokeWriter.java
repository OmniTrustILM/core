package com.otilm.core.service.writer;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writes the revoke attributes preserved while a certificate is {@code PENDING_REVOKE}. They go through a targeted
 * update because Hibernate leaves a changed {@link Certificate#getPendingRevokeAttributes()} out of the UPDATE it
 * issues for the entity. Joins the caller's transaction, or opens one when there is none.
 */
@Component
public class CertificatePendingRevokeWriter {

    private final CertificateRepository certificateRepository;

    public CertificatePendingRevokeWriter(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Transactional
    public void save(UUID certificateUuid, List<RequestAttribute> attributes) {
        certificateRepository.updatePendingRevokeAttributes(certificateUuid, attributes);
    }

    @Transactional
    public void clear(UUID certificateUuid) {
        certificateRepository.updatePendingRevokeAttributes(certificateUuid, null);
    }
}
