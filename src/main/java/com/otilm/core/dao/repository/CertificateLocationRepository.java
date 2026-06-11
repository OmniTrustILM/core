package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateLocation;
import com.otilm.core.dao.entity.CertificateLocationId;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface CertificateLocationRepository extends SecurityFilterRepository<CertificateLocation, CertificateLocationId> {
    List<CertificateLocation> findByCertificateUuidIn(List<UUID> certificateUuids);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("DELETE FROM CertificateLocation cl WHERE cl.id.locationUuid = :locationUuid")
    void deleteByLocationUuid(@Param("locationUuid") UUID locationUuid);
}
