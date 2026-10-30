package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateRequestEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateRequestRepository extends ComplianceSubjectRepository<CertificateRequestEntity> {

    Optional<CertificateRequestEntity> findByUuid(final UUID uuid);

    Optional<CertificateRequestEntity> findByUuidIn(final List<UUID> uuids);

    Optional<CertificateRequestEntity> findByFingerprint(final String fingerprint);
}
