package com.otilm.core.dao.repository.custom;

import com.otilm.core.dao.entity.Certificate;
import java.util.Optional;
import java.util.UUID;

public interface CustomCertificateRepository {

    void bulkUpdateQuery(String query);

    /**
     * Locks the certificate's row and reads it from the database. A copy the persistence context already holds is
     * overwritten, as a request-wide EntityManager may have read the certificate before another transaction changed it.
     */
    Optional<Certificate> findAndLockFreshByUuid(UUID uuid);
}
