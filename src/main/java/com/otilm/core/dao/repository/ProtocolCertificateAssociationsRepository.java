package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.ProtocolCertificateAssociations;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface ProtocolCertificateAssociationsRepository extends SecurityFilterRepository<ProtocolCertificateAssociations, UUID> {

    @Query("""
                SELECT pca
                FROM ProtocolCertificateAssociations pca
                JOIN ScepProfile sp
                  ON pca.uuid = sp.certificateAssociationsUuid
                WHERE sp.uuid = :profileUuid
            """)
    ProtocolCertificateAssociations findByScepProfileUuid(UUID profileUuid);

    @Query("""
                SELECT pca
                FROM ProtocolCertificateAssociations pca
                JOIN AcmeProfile ap
                  ON pca.uuid = ap.certificateAssociationsUuid
                WHERE ap.uuid = :profileUuid
            """)
    ProtocolCertificateAssociations findByAcmeProfileUuid(UUID profileUuid);

    @Query("""
                SELECT pca
                FROM ProtocolCertificateAssociations pca
                JOIN CmpProfile cp
                  ON pca.uuid = cp.certificateAssociationsUuid
                WHERE cp.uuid = :profileUuid
            """)
    ProtocolCertificateAssociations findByCmpProfileUuid(UUID profileUuid);
}
