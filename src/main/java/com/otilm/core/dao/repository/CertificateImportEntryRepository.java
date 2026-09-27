package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.CertificateImportEntry;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateImportEntryRepository extends JpaRepository<CertificateImportEntry, UUID> {

    Optional<CertificateImportEntry> findByRequesterUuidAndImportId(UUID requesterUuid, String importId);
}
