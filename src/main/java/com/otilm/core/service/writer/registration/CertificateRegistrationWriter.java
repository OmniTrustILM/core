package com.otilm.core.service.writer.registration;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.core.dao.repository.CertificateRegistrationRepository;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Short transactional writes against {@code certificate_registration} (repositories carry no
 * {@code @Transactional}). Methods are {@code REQUIRED} so they join an ambient transaction or open their own.
 */
@Component
public class CertificateRegistrationWriter {

    private final CertificateRegistrationRepository registrationRepository;

    public CertificateRegistrationWriter(CertificateRegistrationRepository registrationRepository) {
        this.registrationRepository = registrationRepository;
    }

    /**
     * Creates the binding, or replaces its meta when one already exists. An empty/null meta still creates the
     * row — its presence marks the certificate register-bound.
     */
    @Transactional
    public void upsert(UUID certificateUuid, List<MetadataAttribute> meta) {
        String serialized = meta == null || meta.isEmpty() ? null : AttributeDefinitionUtils.serialize(meta);
        registrationRepository.upsert(UUID.randomUUID(), certificateUuid, serialized);
    }

    /** Removes the binding once the register-bound issuance completed (idempotent). */
    @Transactional
    public void clear(UUID certificateUuid) {
        registrationRepository.deleteByCertificateUuid(certificateUuid);
    }
}
