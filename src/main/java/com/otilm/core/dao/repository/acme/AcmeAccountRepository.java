package com.otilm.core.dao.repository.acme;

import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AcmeAccountRepository extends SecurityFilterRepository<AcmeAccount, Long> {
    Optional<AcmeAccount> findByUuid(UUID uuid);

    Optional<AcmeAccount> findByAccountId(String accountId);

    AcmeAccount findByPublicKey(String publicKey);

    boolean existsByAcmeProfileUuidAndIsDefaultRaProfileTrue(UUID acmeProfileUuid);

    /**
     * Counts one more failed order against the account in the database itself, so that orders of one account failing
     * concurrently cannot lose a count the way a read-modify-write of the entity would.
     */
    @Modifying(flushAutomatically = true)
    @Query("UPDATE AcmeAccount a SET a.failedOrders = a.failedOrders + 1, a.updated = :now WHERE a.uuid = :uuid")
    int incrementFailedOrders(@Param("uuid") UUID uuid, @Param("now") OffsetDateTime now);

    /**
     * Counts one more valid order against the account in the database itself, for the same reason as
     * {@link #incrementFailedOrders(UUID, OffsetDateTime)}.
     */
    @Modifying(flushAutomatically = true)
    @Query("UPDATE AcmeAccount a SET a.validOrders = a.validOrders + 1, a.updated = :now WHERE a.uuid = :uuid")
    int incrementValidOrders(@Param("uuid") UUID uuid, @Param("now") OffsetDateTime now);

    /**
     * Counts several failed orders against the account in one statement, so a caller that settles a batch of orders
     * writes the account once, after it holds every row lock it needs.
     */
    @Modifying(flushAutomatically = true)
    @Query("UPDATE AcmeAccount a SET a.failedOrders = a.failedOrders + :count, a.updated = :now WHERE a.uuid = :uuid")
    int incrementFailedOrdersBy(@Param("uuid") UUID uuid, @Param("count") int count, @Param("now") OffsetDateTime now);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("UPDATE AcmeAccount a SET a.raProfileUuid = :newRaProfileUuid WHERE a.acmeProfileUuid = :acmeProfileUuid AND a.isDefaultRaProfile = true")
    void updateRaProfileForDefaultAccounts(@Param("acmeProfileUuid") UUID acmeProfileUuid,
            @Param("newRaProfileUuid") UUID newRaProfileUuid);
}
