package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.KeyImport;
import com.otilm.core.dao.entity.KeyImportState;
import jakarta.persistence.LockModeType;
import java.util.Collection;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface KeyImportRepository extends JpaRepository<KeyImport, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT i FROM KeyImport i WHERE i.uuid = :uuid")
    Optional<KeyImport> findForUpdateByUuid(@Param("uuid") UUID uuid);

    Optional<KeyImport> findFirstByIdempotencyKeyAndStateInOrderByCreatedAtDesc(String idempotencyKey,
            Collection<KeyImportState> states);
}
