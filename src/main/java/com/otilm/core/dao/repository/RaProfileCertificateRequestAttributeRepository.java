package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.RaProfileCertificateRequestAttribute;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RaProfileCertificateRequestAttributeRepository extends SecurityFilterRepository<RaProfileCertificateRequestAttribute, Long> {

    Optional<RaProfileCertificateRequestAttribute> findByRaProfileUuid(UUID raProfileUuid);
}
