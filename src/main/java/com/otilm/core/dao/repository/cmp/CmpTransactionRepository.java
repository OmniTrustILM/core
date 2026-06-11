package com.otilm.core.dao.repository.cmp;

import com.otilm.core.dao.entity.cmp.CmpTransaction;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CmpTransactionRepository extends SecurityFilterRepository<CmpTransaction, UUID> {

    List<CmpTransaction> findByTransactionId(String transactionId);

    @Query("SELECT t FROM CmpTransaction t JOIN t.certificate c WHERE t.transactionId=?1 and c.fingerprint=?2")
    Optional<CmpTransaction> findByTransactionIdAndFingerprint(String transactionId, String fingerprint);

    @Query("SELECT t FROM CmpTransaction t JOIN t.certificate c WHERE t.transactionId=?1 and c.serialNumber=?2")
    Optional<CmpTransaction> findByTransactionIdAndSerialNumber(String transactionId, String serialNumber);

}
