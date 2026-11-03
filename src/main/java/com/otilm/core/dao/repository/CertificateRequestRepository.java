package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateRequestEntity;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateRequestRepository extends ComplianceSubjectRepository<CertificateRequestEntity> {

    Optional<CertificateRequestEntity> findByUuid(final UUID uuid);

    Optional<CertificateRequestEntity> findByUuidIn(final List<UUID> uuids);

    @Query("SELECT r.uuid FROM CertificateRequestEntity r WHERE r.uuid IN :uuids"
            + " AND NOT EXISTS (SELECT 1 FROM Certificate c WHERE c.certificateRequestUuid = r.uuid)")
    List<UUID> findUuidsWithoutCertificate(@Param("uuids") Collection<UUID> uuids);

    @Modifying
    @Query("DELETE FROM CertificateRequestEntity r WHERE r.uuid IN :uuids")
    int deleteByUuidIn(@Param("uuids") Collection<UUID> uuids);
}
