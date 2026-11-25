package com.otilm.core.service.renewal.auto;

import jakarta.persistence.EntityManager;

/**
 * Bounds how long the current transaction waits for a row lock. Automatic renewal runs while the trigger evaluation
 * that started it is suspended on the same thread and may hold locks on rows an earlier action wrote; waiting for them
 * would never end, so the wait fails after the timeout and the renewal is recorded as failed.
 */
final class LockTimeout {

    private static final String SET_LOCK_TIMEOUT = "SET LOCAL lock_timeout = '10s'";

    private LockTimeout() {
    }

    static void bound(EntityManager entityManager) {
        entityManager.createNativeQuery(SET_LOCK_TIMEOUT).executeUpdate();
    }
}
