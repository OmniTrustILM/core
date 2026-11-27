package com.otilm.core.architecture;

import jakarta.persistence.EntityManager;

/** A builder planted for {@link TestStyleArchSelfTest} that depends on an EntityManager. */
public final class PlantedEntityManagerBuilder {

    private final EntityManager entityManager;

    PlantedEntityManagerBuilder(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    public boolean build() {
        return entityManager.isOpen();
    }
}
