package com.otilm.core.dao.repository.scep;

import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.entity.scep.ScepTransaction;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface ScepTransactionRepository extends SecurityFilterRepository<ScepTransaction, UUID> {
    Optional<ScepProfile> findByUuid(UUID uuid);

    boolean existsByTransactionIdAndScepProfile(String transactionId, ScepProfile scepProfile);

    Optional<ScepTransaction> findByTransactionId(String transactionId);

    Optional<ScepTransaction> findByTransactionIdAndScepProfile(String transactionId, ScepProfile scepProfile);

    void deleteByTransactionIdAndScepProfileUuid(String transactionId, UUID scepProfileUuid);
}
