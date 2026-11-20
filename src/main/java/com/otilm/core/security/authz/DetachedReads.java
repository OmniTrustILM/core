package com.otilm.core.security.authz;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.util.function.Function;

/**
 * Runs a read through an EntityManager of its own, closed after the read. A batched authorization call reads between
 * OPA requests, and the request's EntityManager would hold its connection across all of them until the response is
 * written.
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
