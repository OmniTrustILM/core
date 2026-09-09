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
import org.springframework.stereotype.Repository;

@Repository
public interface AcmeOrderRepository extends SecurityFilterRepository<AcmeOrder, Long> {

    Optional<AcmeOrder> findByUuid(UUID uuid);

    Optional<AcmeOrder> findByOrderId(String orderId);

    Optional<AcmeOrder> findByCertificateId(String certificateId);

    /**
     * Locks the order row ({@code SELECT ... FOR UPDATE}) so that every status write to the order, its authorizations
     * and their challenges is serialised on it. Must be called inside an active transaction, otherwise the lock is
     * released as soon as the query completes.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<AcmeOrder> findWithLockByUuid(UUID uuid);

    @Modifying
    @Query(value = """
            UPDATE AcmeOrder ac SET status = ?#{T(com.otilm.api.model.core.acme.OrderStatus).INVALID}
            WHERE ac.acmeAccount = :acmeAccount AND ac.expires <= :expires AND ac.status != ?#{T(com.otilm.api.model.core.acme.OrderStatus).INVALID}
            AND ac.status != ?#{T(com.otilm.api.model.core.acme.OrderStatus).VALID}
            """)
    Integer invalidateExpiredOrders(AcmeAccount acmeAccount, Date expires);
}
