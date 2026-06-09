package com.czertainly.core.dao.repository.acme;

import com.czertainly.core.dao.entity.acme.AcmeAccount;
import com.czertainly.core.dao.entity.acme.AcmeOrder;
import com.czertainly.core.dao.repository.SecurityFilterRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AcmeOrderRepository extends SecurityFilterRepository<AcmeOrder, Long> {

    Optional<AcmeOrder> findByUuid(UUID uuid);

    Optional<AcmeOrder> findByOrderId(String orderId);

    Optional<AcmeOrder> findByCertificateId(String certificateId);

    @Modifying
    @Query(value = """
            UPDATE AcmeOrder ac SET status = ?#{T(com.otilm.api.model.core.acme.OrderStatus).INVALID}
            WHERE ac.acmeAccount = :acmeAccount AND ac.expires <= :expires AND ac.status != ?#{T(com.otilm.api.model.core.acme.OrderStatus).INVALID}
            AND ac.status != ?#{T(com.otilm.api.model.core.acme.OrderStatus).VALID}
            """)
    Integer invalidateExpiredOrders(AcmeAccount acmeAccount, Date expires);
}
