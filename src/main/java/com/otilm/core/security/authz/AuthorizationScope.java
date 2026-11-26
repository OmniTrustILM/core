package com.otilm.core.security.authz;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.config.cache.AuthorizationCacheProperties;
import com.otilm.core.security.authn.PlatformUserDetails;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.stereotype.Component;

/**
 * Supplies the association reader and all-resources grant that an authorization decision uses. Inside a
 * {@link #batched} call they belong to the batch, so its decisions share one set of association reads and, while the
 * authorization cache is enabled, an all-resources principal skips OPA. Outside one, associations are read through the
 * request's EntityManager and the grant is {@link AllResourcesGrant#NONE}, so every check asks OPA.
 */
@Component
class AuthorizationScope {

    private final ThreadLocal<Batch> active = new ThreadLocal<>();

    private final EntityManager entityManager;

    private final EntityManagerFactory entityManagerFactory;

    private final ObjectMapper objectMapper;

    private final AuthorizationCacheProperties cacheProperties;

    AuthorizationScope(EntityManagerFactory entityManagerFactory, ObjectMapper objectMapper,
            AuthorizationCacheProperties cacheProperties) {
        this.entityManager = SharedEntityManagerCreator.createSharedEntityManager(entityManagerFactory);
        this.entityManagerFactory = entityManagerFactory;
        this.objectMapper = objectMapper;
        this.cacheProperties = cacheProperties;
    }

    /**
     * Runs {@code body} as one batch for {@code principal}, reading the associations of {@code objectUuids} of
     * {@code resource} in the first query of each kind.
     *
     * @throws IllegalStateException when a batch is already running on this thread
     */
    <T> T batched(PlatformUserDetails principal, Resource resource, Collection<UUID> objectUuids, Supplier<T> body) {
        if (active.get() != null) {
            throw new IllegalStateException("An authorization batch is already running on this thread");
        }
        AssociationReader associations = AssociationReader.detached(entityManagerFactory, principal.getUserUuid());
        associations.prefetch(resource, objectUuids);
        AllResourcesGrant grant = cacheProperties.enabled()
                ? AllResourcesGrant.of(objectMapper, principal.getRawData())
                : AllResourcesGrant.NONE;
        active.set(new Batch(principal.getUserUuid(), principal.getRawData(), associations, grant));
        try {
            return body.get();
        } finally {
            active.remove();
        }
    }

    AssociationReader associationsFor(PlatformUserDetails principal) {
        return batchOf(principal)
                .map(Batch::associations)
                .orElseGet(() -> AssociationReader.attached(entityManager, principal.getUserUuid()));
    }

    AllResourcesGrant grantFor(PlatformUserDetails principal) {
        return batchOf(principal).map(Batch::grant).orElse(AllResourcesGrant.NONE);
    }

    /** Another principal never uses the batch's grant. */
    private Optional<Batch> batchOf(PlatformUserDetails principal) {
        return Optional.ofNullable(active.get()).filter(batch -> batch.isFor(principal));
    }

    private record Batch(String userUuid, String rawData, AssociationReader associations, AllResourcesGrant grant) {

        boolean isFor(PlatformUserDetails principal) {
            return Objects.equals(userUuid, principal.getUserUuid()) && Objects.equals(rawData, principal.getRawData());
        }
    }
}
