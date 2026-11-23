package com.otilm.core.security.authz;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.util.function.Function;

/**
 * Runs a read through an EntityManager of its own, closed after the read.
 */
final class DetachedReads {

    private DetachedReads() {
    }

    static <T> T read(EntityManagerFactory entityManagerFactory, Function<EntityManager, T> query) {
        try (EntityManager reader = entityManagerFactory.createEntityManager()) {
            return query.apply(reader);
        }
    }
}
