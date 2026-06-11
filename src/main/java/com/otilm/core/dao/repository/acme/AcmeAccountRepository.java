package com.otilm.core.dao.repository.acme;

import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AcmeAccountRepository extends SecurityFilterRepository<AcmeAccount, Long> {
    Optional<AcmeAccount> findByUuid(UUID uuid);
    Optional<AcmeAccount> findByAccountId(String accountId);
    AcmeAccount findByPublicKey(String publicKey);
    boolean existsByAcmeProfileUuidAndIsDefaultRaProfileTrue(UUID acmeProfileUuid);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("UPDATE AcmeAccount a SET a.raProfileUuid = :newRaProfileUuid WHERE a.acmeProfileUuid = :acmeProfileUuid AND a.isDefaultRaProfile = true")
    void updateRaProfileForDefaultAccounts(@Param("acmeProfileUuid") UUID acmeProfileUuid, @Param("newRaProfileUuid") UUID newRaProfileUuid);
}
