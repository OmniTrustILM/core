package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.TrustedCertificateSync;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TrustedCertificateSyncRepository extends JpaRepository<TrustedCertificateSync, UUID> {
}
