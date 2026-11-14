package com.otilm.core.dao.repository.custom;

import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.handler.StoredCertificateHealthProjector;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface CustomCertificateRepository {

    List<CertificateDto> findScopedCertificateDtos(SecurityFilter filter, List<UUID> selectedPage);

    Optional<StoredCertificateHealthProjector.Snapshot> findStoredCertificateHealth(UUID expectedProfile,
            UUID certificate);

    void bulkUpdateQuery(String query);
}
