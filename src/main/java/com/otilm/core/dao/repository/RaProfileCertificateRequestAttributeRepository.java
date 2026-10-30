package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.RaProfileCertificateRequestAttribute;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface RaProfileCertificateRequestAttributeRepository
        extends
            SecurityFilterRepository<RaProfileCertificateRequestAttribute, Long> {

    Optional<RaProfileCertificateRequestAttribute> findByRaProfileUuid(UUID raProfileUuid);
}
