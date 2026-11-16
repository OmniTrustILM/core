package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateProtocolAssociationRepository
        extends
            SecurityFilterRepository<CertificateProtocolAssociation, Long> {

    Optional<CertificateProtocolAssociation> findByCertificateUuid(UUID certificateUuid);
}
