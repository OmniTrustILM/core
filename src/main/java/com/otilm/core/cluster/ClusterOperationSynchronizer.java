package com.otilm.core.cluster;

import jakarta.persistence.EntityManager;
import java.util.Collection;
import org.springframework.stereotype.Component;

/**
 * Coordinates operations that must run on a single cluster node at a time (e.g. scheduled housekeeping that every
 * instance triggers on its own timer). Backed by PostgreSQL transaction-scoped advisory locks: the lock is acquired
 * without blocking and released automatically when the surrounding transaction commits or rolls back.
 */
@Component
public class ClusterOperationSynchronizer {

    /**
     * Named cluster-wide locks. Each constant owns a distinct advisory-lock key; keys must stay stable and unique
     * across the application so two unrelated operations never collide.
     */
    public enum Operation {
        SIGNING_RECORD_RETENTION(0x51_67_4E_43_52_45_43_00L),
        SIGNING_RECORD_DELETE_AFTER_RETRIEVAL(0x51_67_4E_43_52_44_52_00L),
        SIGNING_RECORD_OUTBOX_DRAIN(0x51_67_4E_43_4F_42_44_52L),
        PROVIDER_STATUS_POLL_SWEEP(0x50_52_4F_56_50_4F_4C_4CL),
        DISCOVERY_WORK_SWEEP(0x44_49_53_43_57_4B_53_50L),
        CRYPTO_ASSET_PQC_SWEEP(0x43_41_50_51_43_53_57_50L),
        CBOM_SYNC_SKIP_RETENTION(0x43_42_53_4B_52_45_54_4EL),
        KEY_IMPORT_SWEEP(0x4B_49_4D_50_53_57_45_50L);

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
     * Must be called inside a transaction: the lock is transaction-scoped, so outside a transaction it would be
     * acquired and released within the single {@code SELECT} statement, providing no mutual exclusion. Returns
     * {@code true} if this node now holds the lock and should perform the operation, {@code false} if another node
     * holds it and this node should skip the operation. The lock is released automatically when the transaction ends.
     */
    public boolean tryLock(Operation operation) {
        return (boolean) entityManager
                .createNativeQuery("SELECT pg_try_advisory_xact_lock(:key)")
                .setParameter("key", operation.lockKey)
                .getSingleResult();
    }

    /**
     * Tries to acquire a cluster-wide lock keyed on {@code key} without blocking.
     * <p>
     * The non-blocking counterpart of {@link #lock(String)}, for work that is scoped to one entity and that a node may
     * skip when another node is already doing it: one key per entity means two nodes working different entities never
     * contend, where an {@link Operation} constant would serialize the whole cluster onto one worker. The {@code key}
     * is hashed into the advisory-lock keyspace via {@code hashtext}, exactly as {@link #lock(String)} does, so the two
     * address the same lock and a caller may choose per call whether to wait.
     * <p>
     * Must be called inside a transaction, for the reason {@link #tryLock(Operation)} gives.
     */
    public boolean tryLock(String key) {
        return (boolean) entityManager
                .createNativeQuery("SELECT pg_try_advisory_xact_lock(hashtext(:key))")
                .setParameter("key", key)
                .getSingleResult();
    }

    /**
     * Acquires a cluster-wide lock keyed on {@code key}, blocking until it becomes available.
     * <p>
     * Unlike {@link #tryLock(Operation)}, this waits for the lock instead of skipping the work, so use it to serialize
     * a read-decide-write section that every caller must perform (e.g. the signing-profile version-bump decision)
     * rather than housekeeping only one node needs to run. The {@code key} is hashed into the advisory-lock keyspace
     * via {@code hashtext}; distinct keys serialize independently, so callers scope the lock by composing a stable
     * prefix with the entity identifier (e.g. {@code "signing-profile:" + uuid}).
     * <p>
     * Must be called inside a transaction: the lock is transaction-scoped and released automatically when the
     * transaction commits or rolls back.
     */
    public void lock(String key) {
        entityManager
                .createNativeQuery("SELECT pg_advisory_xact_lock(hashtext(:key))")
                .setParameter("key", key)
                .getSingleResult();
    }

    /**
     * Acquires the cluster-wide locks for all {@code keys} in one statement, blocking until every one is available.
     * <p>
     * Keyed exactly as {@link #lock(String)}, so the two address the same locks. The locks are taken in ascending order
     * of the hashed key, the lock id itself: the sort sits in a subquery, which the planner cannot flatten, and the
     * lock call runs over its rows. Two callers locking overlapping key sets therefore acquire the shared locks in the
     * same order and cannot deadlock on each other, even when two keys hash alike.
     * <p>
     * Must be called inside a transaction, for the reason {@link #tryLock(Operation)} gives.
     */
    public void lockAll(Collection<String> keys) {
        if (keys.isEmpty()) {
            return;
        }
        entityManager
                .createNativeQuery("SELECT pg_advisory_xact_lock(id) FROM (SELECT DISTINCT hashtext(k) AS id"
                        + " FROM unnest(CAST(:keys AS text[])) AS k ORDER BY id) AS ids")
                .setParameter("keys", keys.toArray(String[]::new))
                .getResultList();
    }
}
