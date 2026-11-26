package com.otilm.core.dao.repository.acme;

import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import jakarta.persistence.LockModeType;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AcmeOrderRepository extends SecurityFilterRepository<AcmeOrder, Long> {

    Optional<AcmeOrder> findByUuid(UUID uuid);

    Optional<AcmeOrder> findByOrderId(String orderId);

    Optional<AcmeOrder> findByCertificateId(String certificateId);

    boolean existsByCertificateReferenceUuidAndAcmeAccountUuid(UUID certificateUuid, UUID acmeAccountUuid);

    /**
     * Whether a live order of any account replaces the certificate: one that is neither invalid nor a pending or ready
     * order past its expiry, which is only marked invalid when its account is next used.
     */
    @Query("""
            SELECT COUNT(o) > 0 FROM AcmeOrder o
            WHERE o.replacesCertificateUuid = :certificateUuid
              AND o.status <> com.otilm.api.model.core.acme.OrderStatus.INVALID
              AND (o.status NOT IN (com.otilm.api.model.core.acme.OrderStatus.PENDING,
                                    com.otilm.api.model.core.acme.OrderStatus.READY)
                   OR o.expires IS NULL OR o.expires > CURRENT_TIMESTAMP)
            """)
    boolean existsLiveOrderReplacing(@Param("certificateUuid") UUID certificateUuid);

    /**
     * Locks the order row ({@code SELECT ... FOR UPDATE}) so that every status write to the order, its authorizations
     * and their challenges is serialised on it. Must be called inside an active transaction, otherwise the lock is
     * released as soon as the query completes.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<AcmeOrder> findWithLockByUuid(UUID uuid);

    @Modifying
    @Query("""
            UPDATE AcmeOrder o SET o.errorDetail = :errorDetail, o.updated = CURRENT_TIMESTAMP
            WHERE o.certificateReferenceUuid = :certificateUuid
            """)
    void recordErrorDetailByCertificate(UUID certificateUuid, String errorDetail);

    @Modifying
    @Query(value = """
            UPDATE AcmeOrder ac SET status = ?#{T(com.otilm.api.model.core.acme.OrderStatus).INVALID}
            WHERE ac.acmeAccount = :acmeAccount AND ac.expires <= :expires AND ac.status != ?#{T(com.otilm.api.model.core.acme.OrderStatus).INVALID}
            AND ac.status != ?#{T(com.otilm.api.model.core.acme.OrderStatus).VALID}
            """)
    Integer invalidateExpiredOrders(AcmeAccount acmeAccount, Date expires);
}
