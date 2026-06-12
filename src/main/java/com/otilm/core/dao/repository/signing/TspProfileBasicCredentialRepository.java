package com.otilm.core.dao.repository.signing;

import com.otilm.core.dao.entity.signing.TspProfileBasicCredential;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface TspProfileBasicCredentialRepository extends SecurityFilterRepository<TspProfileBasicCredential, UUID> {
    List<TspProfileBasicCredential> findByTspProfileUuid(UUID tspProfileUuid);
    Optional<TspProfileBasicCredential> findByTspProfileUuidAndUsername(UUID tspProfileUuid, String username);

    @Modifying
    @Query("DELETE FROM TspProfileBasicCredential c WHERE c.uuid = :uuid")
    void deleteByUuid(@Param("uuid") UUID uuid);
}
