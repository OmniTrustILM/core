package com.otilm.core.service.writer;

import com.otilm.api.model.core.acme.AuthorizationStatus;
import com.otilm.api.model.core.acme.ChallengeStatus;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.core.dao.entity.acme.AcmeAuthorization;
import com.otilm.core.dao.entity.acme.AcmeChallenge;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import com.otilm.core.dao.repository.acme.AcmeAccountRepository;
import com.otilm.core.dao.repository.acme.AcmeAuthorizationRepository;
import com.otilm.core.dao.repository.acme.AcmeChallengeRepository;
import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import com.otilm.core.service.acme.AcmeChallengeStateMachine;
import com.otilm.core.service.acme.ChallengeValidationResult;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Writer bean for the status transitions of ACME challenges, authorizations and orders.
 *
 * <p>
 * Every method locks the order row first ({@code SELECT ... FOR UPDATE}) and re-reads the rows under that lock before
 * deciding anything, so all writes to one order — the same challenge accepted twice, sibling challenges of one
 * authorization, sibling authorizations of one order — are serialised. Methods use the default propagation
 * ({@code REQUIRED}): they join an ambient transaction if one is active and open one otherwise, which lets the
 * challenge endpoint keep its DNS and HTTP lookups outside any transaction.
 */
@Service
public class AcmeChallengeWriter {

    private static final Logger logger = LoggerFactory.getLogger(AcmeChallengeWriter.class);

    private final AcmeOrderRepository acmeOrderRepository;
    private final AcmeAuthorizationRepository acmeAuthorizationRepository;
    private final AcmeChallengeRepository acmeChallengeRepository;
    private final AcmeAccountRepository acmeAccountRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    public AcmeChallengeWriter(AcmeOrderRepository acmeOrderRepository,
            AcmeAuthorizationRepository acmeAuthorizationRepository, AcmeChallengeRepository acmeChallengeRepository,
            AcmeAccountRepository acmeAccountRepository) {
        this.acmeOrderRepository = acmeOrderRepository;
        this.acmeAuthorizationRepository = acmeAuthorizationRepository;
        this.acmeChallengeRepository = acmeChallengeRepository;
        this.acmeAccountRepository = acmeAccountRepository;
    }

    /**
     * Records the verdict of a validation attempt on the challenge, its authorization and its order. A challenge or
     * authorization that settled while the attempt was running is left as it is, and that recorded state is returned.
     *
     * @param orderUuid the order the challenge belongs to, locked for the duration of the write
     * @param challengeId the challenge the verdict is for
     * @param result the verdict
     * @return the challenge as it stands after this call
     */
    @Transactional
    public AcmeChallenge applyValidationResult(UUID orderUuid, String challengeId, ChallengeValidationResult result) {
        AcmeOrder order = lockOrder(orderUuid);
        AcmeChallenge challenge = challengeUnderLock(challengeId);
        AcmeAuthorization authorization = challenge.getAuthorization();
        if (challenge.getStatus() != ChallengeStatus.PENDING
                || authorization.getStatus() != AuthorizationStatus.PENDING) {
            logger
                    .debug("Challenge {} settled as {} on a {} authorization while it was being validated", challengeId,
                            challenge.getStatus(), authorization.getStatus());
            return challenge;
        }

        OrderStatus orderStatusBefore = order.getStatus();
        AcmeChallengeStateMachine.applyValidationResult(challenge, result);
        acmeChallengeRepository.save(challenge);
        acmeAuthorizationRepository.save(authorization);
        recordOrderTransition(order, orderStatusBefore);
        return challenge;
    }

    /**
     * Settles the authorizations of an order left pending behind a failed challenge, and the order itself if any of its
     * authorizations has failed. Such rows are written by an instance that does not yet propagate failures; an order
     * whose rows are consistent is left untouched.
     */
    @Transactional
    public void settleOrder(UUID orderUuid) {
        AcmeOrder order = lockOrder(orderUuid);
        OrderStatus orderStatusBefore = order.getStatus();
        List<AcmeAuthorization> settled = AcmeChallengeStateMachine.settleOrder(order);
        acmeAuthorizationRepository.saveAll(settled);
        if (!settled.isEmpty() || order.getStatus() != orderStatusBefore) {
            logger.info("Settled order {} left open behind a failed challenge", order.getOrderId());
        }
        recordOrderTransition(order, orderStatusBefore);
    }

    /**
     * Deactivates an authorization at the client's request (RFC 8555 section 7.5.2), under the same lock as every other
     * status write to its order, so a validation running at the same time cannot write over it.
     *
     * @return the authorization as it stands after this call
     */
    @Transactional
    public AcmeAuthorization deactivateAuthorization(UUID orderUuid, String authorizationId) {
        AcmeOrder order = lockOrder(orderUuid);
        AcmeAuthorization authorization = order
                .getAuthorizations()
                .stream()
                .filter(candidate -> authorizationId.equals(candidate.getAuthorizationId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "ACME authorization " + authorizationId + " no longer belongs to order " + orderUuid));
        OrderStatus orderStatusBefore = order.getStatus();
        AcmeChallengeStateMachine.deactivate(authorization);
        acmeAuthorizationRepository.save(authorization);
        recordOrderTransition(order, orderStatusBefore);
        return authorization;
    }

    /**
     * Invalidates an order whose account is being deactivated: the order becomes {@code INVALID}, its authorizations
     * {@code DEACTIVATED} and their challenges {@code INVALID}, under the same lock as every other status write to the
     * order.
     *
     * <p>
     * The account is deliberately not written here. A caller deactivating an account walks its orders one by one and
     * holds every lock until it commits, so writing the account between two of them would let a challenge failing
     * concurrently hold the next order while waiting for the account this call had already written, deadlocking both.
     * The caller counts the orders it closed once it has locked all of them.
     *
     * @return whether the order was still open, for the caller to count against the account
     */
    @Transactional
    public boolean deactivateOrder(UUID orderUuid) {
        AcmeOrder order = lockOrder(orderUuid);
        OrderStatus statusBefore = order.getStatus();
        order.setStatus(OrderStatus.INVALID);
        for (AcmeAuthorization authorization : order.getAuthorizations()) {
            authorization.setStatus(AuthorizationStatus.DEACTIVATED);
            authorization.getChallenges().forEach(challenge -> challenge.setStatus(ChallengeStatus.INVALID));
            acmeChallengeRepository.saveAll(authorization.getChallenges());
        }
        acmeAuthorizationRepository.saveAll(order.getAuthorizations());
        acmeOrderRepository.save(order);
        return statusBefore != OrderStatus.INVALID;
    }

    /**
     * Brings the order's status in line with the certificate requested for it and counts the transition against its
     * account. Both happen under the order lock, so two requests polling the same order record one transition between
     * them rather than each counting the one it observed.
     *
     * @param orderUuid the order to reconcile
     * @return the order as it stands after this call
     */
    @Transactional
    public AcmeOrder reconcileCertificateStatus(UUID orderUuid) {
        AcmeOrder order = lockOrder(orderUuid);
        if (order.getCertificateReferenceUuid() == null) {
            return order;
        }
        OrderStatus statusBefore = order.getStatus();
        OrderStatus statusFromCertificate = AcmeChallengeStateMachine
                .statusFromCertificate(order.getCertificateReference().getState());
        if (statusFromCertificate == statusBefore) {
            return order;
        }
        logger
                .info("ACME order {} status changed from {} to {}", order.getOrderId(), statusBefore,
                        statusFromCertificate);
        order.setStatus(statusFromCertificate);
        acmeOrderRepository.save(order);
        countOrderOutcome(order, statusBefore);
        return order;
    }

    /**
     * Counts a failed order against its account.
     */
    @Transactional
    public void countFailedOrder(UUID accountUuid) {
        acmeAccountRepository.incrementFailedOrders(accountUuid, OffsetDateTime.now(ZoneOffset.UTC));
    }

    /**
     * Counts a batch of failed orders against an account in one statement.
     */
    @Transactional
    public void countFailedOrders(UUID accountUuid, int count) {
        if (count > 0) {
            acmeAccountRepository.incrementFailedOrdersBy(accountUuid, count, OffsetDateTime.now(ZoneOffset.UTC));
        }
    }

    /**
     * Counts a valid order against its account.
     */
    @Transactional
    public void countValidOrder(UUID accountUuid) {
        acmeAccountRepository.incrementValidOrders(accountUuid, OffsetDateTime.now(ZoneOffset.UTC));
    }

    /**
     * Locks the order row and re-reads the order, all of its authorizations and all of their challenges. The
     * persistence context may already hold any of these rows from reads made before the lock was taken, and every
     * decision below depends on their current state, not on what a sibling looked like before another request
     * committed.
     */
    private AcmeOrder lockOrder(UUID orderUuid) {
        AcmeOrder order = acmeOrderRepository
                .findWithLockByUuid(orderUuid)
                .orElseThrow(() -> new IllegalStateException("ACME order " + orderUuid + " no longer exists"));
        // Changes made earlier in the same transaction are written before the rows are re-read: refresh discards
        // what is still pending, and a query on the order table alone need not have flushed them.
        entityManager.flush();
        entityManager.refresh(order);
        for (AcmeAuthorization authorization : order.getAuthorizations()) {
            entityManager.refresh(authorization);
            authorization.getChallenges().forEach(entityManager::refresh);
        }
        return order;
    }

    private AcmeChallenge challengeUnderLock(String challengeId) {
        return acmeChallengeRepository
                .findWithContextByChallengeId(challengeId)
                .orElseThrow(() -> new IllegalStateException("ACME challenge " + challengeId + " no longer exists"));
    }

    private void recordOrderTransition(AcmeOrder order, OrderStatus statusBefore) {
        if (order.getStatus() == statusBefore) {
            return;
        }
        acmeOrderRepository.save(order);
        countOrderOutcome(order, statusBefore);
    }

    /**
     * Counts a settled order against its account, in the database, when this call is the one that settled it.
     */
    private void countOrderOutcome(AcmeOrder order, OrderStatus statusBefore) {
        if (order.getStatus() == statusBefore) {
            return;
        }
        if (order.getStatus() == OrderStatus.INVALID) {
            acmeAccountRepository.incrementFailedOrders(order.getAcmeAccountUuid(), OffsetDateTime.now(ZoneOffset.UTC));
        } else if (order.getStatus() == OrderStatus.VALID) {
            acmeAccountRepository.incrementValidOrders(order.getAcmeAccountUuid(), OffsetDateTime.now(ZoneOffset.UTC));
        }
    }

}
