package com.czertainly.core.cluster;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Component;

/**
 * Coordinates operations that must run on a single cluster node at a time (e.g. scheduled
 * housekeeping that every instance triggers on its own timer). Backed by PostgreSQL
 * transaction-scoped advisory locks: the lock is acquired without blocking and released
 * automatically when the surrounding transaction commits or rolls back.
 */
@Component
public class ClusterOperationSynchronizer {

    /**
     * Named cluster-wide locks. Each constant owns a distinct advisory-lock key; keys must stay
     * stable and unique across the application so two unrelated operations never collide.
     */
    public enum Operation {
        SIGNING_RECORD_RETENTION(0x51_67_4E_43_52_45_43_00L),
        SIGNING_RECORD_DELETE_AFTER_RETRIEVAL(0x51_67_4E_43_52_44_52_00L),
        SIGNING_RECORD_OUTBOX_DRAIN(0x51_67_4E_43_4F_42_44_52L);

        private final long lockKey;

        Operation(long lockKey) {
            this.lockKey = lockKey;
        }
    }

    private final EntityManager entityManager;

    public ClusterOperationSynchronizer(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    /**
     * Tries to acquire the cluster-wide lock for the given operation without blocking.
     * <p>
     * Must be called inside a transaction: the lock is transaction-scoped, so outside a
     * transaction it would be acquired and released within the single {@code SELECT} statement,
     * providing no mutual exclusion. Returns {@code true} if this node now holds the lock and
     * should perform the operation, {@code false} if another node holds it and this node should
     * skip the operation. The lock is released automatically when the transaction ends.
     */
    public boolean tryLock(Operation operation) {
        return (boolean) entityManager
                .createNativeQuery("SELECT pg_try_advisory_xact_lock(:key)")
                .setParameter("key", operation.lockKey)
                .getSingleResult();
    }
}
