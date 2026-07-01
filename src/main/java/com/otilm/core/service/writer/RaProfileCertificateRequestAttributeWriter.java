package com.otilm.core.service.writer;

import com.otilm.api.model.core.raprofile.AttributeSetMergeMode;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RaProfileCertificateRequestAttribute;
import com.otilm.core.dao.entity.RaProfileValueSourceBinding;
import com.otilm.core.dao.repository.RaProfileCertificateRequestAttributeRepository;
import com.otilm.core.dao.repository.RaProfileValueSourceBindingRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Writer bean for the platform-owned RA-Profile static request-attribute set and the Core-side value-source bindings.
 *
 * <p>No external HTTP call occurs on these write paths, so they are safe to run inside a transaction.
 */
@Service
public class RaProfileCertificateRequestAttributeWriter {

    private final RaProfileCertificateRequestAttributeRepository requestAttributeRepository;
    private final RaProfileValueSourceBindingRepository valueSourceBindingRepository;

    @Autowired
    public RaProfileCertificateRequestAttributeWriter(RaProfileCertificateRequestAttributeRepository requestAttributeRepository,
                                                      RaProfileValueSourceBindingRepository valueSourceBindingRepository) {
        this.requestAttributeRepository = requestAttributeRepository;
        this.valueSourceBindingRepository = valueSourceBindingRepository;
    }

    /**
     * Upserts the single request-attribute config row for the RA Profile (one row per profile, enforced by the
     * unique constraint): the serialized static definitions, the merge mode, and the external-CSR strictness flag.
     */
    @Transactional
    public void saveStaticSet(RaProfile raProfile, String serializedDefinitions,
                              AttributeSetMergeMode mergeMode, Boolean externalCsrValidationStrict) {
        RaProfileCertificateRequestAttribute set = requestAttributeRepository.findByRaProfileUuid(raProfile.getUuid())
                .orElseGet(RaProfileCertificateRequestAttribute::new);
        set.setRaProfile(raProfile);
        set.setRequestAttributes(serializedDefinitions);
        set.setMergeMode(mergeMode);
        set.setExternalCsrValidationStrict(externalCsrValidationStrict);
        requestAttributeRepository.save(set);
    }

    /**
     * Clears the static-set definitions for the RA Profile (keeps the row, nulls the payload).
     */
    @Transactional
    public void clearStaticSet(UUID raProfileUuid) {
        requestAttributeRepository.findByRaProfileUuid(raProfileUuid).ifPresent(set -> {
            set.setRequestAttributes(null);
            requestAttributeRepository.save(set);
        });
    }

    /**
     * Replaces all value-source-binding rows for the RA Profile atomically: delete the existing rows, insert the supplied ones.
     */
    @Transactional
    public void replaceValueSourceBindings(UUID raProfileUuid, List<RaProfileValueSourceBinding> bindings) {
        valueSourceBindingRepository.deleteByRaProfileUuid(raProfileUuid);
        if (bindings != null) {
            for (RaProfileValueSourceBinding binding : bindings) {
                binding.setRaProfileUuid(raProfileUuid);
                valueSourceBindingRepository.save(binding);
            }
        }
    }
}
