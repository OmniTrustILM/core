package com.otilm.core.security.authz;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.security.authn.PlatformUserDetails;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Tuple;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Caches one principal's owner and group associations for a single allowed-actions call, so the authorization fallbacks
 * read them with one query per resource instead of one per object. Each read opens and closes its own EntityManager,
 * because the request's EntityManager would keep a connection open across every OPA call.
 */
final class AssociationSnapshot {

    private static final String OWNED_QUERY = "SELECT DISTINCT oa.objectUuid FROM OwnerAssociation oa"
            + " WHERE oa.ownerUuid = :ownerUuid AND oa.resource = :resource AND oa.objectUuid IN :objectUuids";

    private static final String GROUPS_QUERY = "SELECT ga.objectUuid, ga.groupUuid FROM GroupAssociation ga"
            + " WHERE ga.resource = :resource AND ga.objectUuid IN :objectUuids";

    private final EntityManagerFactory entityManagerFactory;

    private final String userUuid;

    private final String rawData;

    private final AllResourcesGrant grant;

    private final Map<Resource, BatchLoader<Boolean>> owners = new EnumMap<>(Resource.class);

    private final Map<Resource, BatchLoader<List<String>>> groups = new EnumMap<>(Resource.class);

    AssociationSnapshot(EntityManagerFactory entityManagerFactory, ObjectMapper objectMapper,
            PlatformUserDetails principal) {
        this.entityManagerFactory = entityManagerFactory;
        this.userUuid = principal.getUserUuid();
        this.rawData = principal.getRawData();
        this.grant = AllResourcesGrant.of(objectMapper, rawData);
    }

    boolean isFor(PlatformUserDetails principal) {
        return Objects.equals(userUuid, principal.getUserUuid()) && Objects.equals(rawData, principal.getRawData());
    }

    boolean hasRawData(String principal) {
        return Objects.equals(rawData, principal);
    }

    AllResourcesGrant grant() {
        return grant;
    }

    /**
     * Announces objects to read in the same query as the first object of their resource asked about.
     */
    void prefetch(Resource resource, Collection<UUID> objectUuids) {
        if (resource.hasOwner()) {
            owners(resource).announce(objectUuids);
        }
        if (resource.hasGroups()) {
            groups(resource).announce(objectUuids);
        }
    }

    boolean ownsAll(Resource resource, Collection<UUID> objectUuids) {
        return owners(resource).get(objectUuids).values().stream().allMatch(Boolean::booleanValue);
    }

    List<String> groupsOf(Resource resource, UUID objectUuid) {
        return objectUuid == null ? List.of() : groups(resource).get(List.of(objectUuid)).get(objectUuid);
    }

    private BatchLoader<Boolean> owners(Resource resource) {
        return owners.computeIfAbsent(resource, key -> new BatchLoader<>(missing -> readOwned(key, missing), false));
    }

    private BatchLoader<List<String>> groups(Resource resource) {
        return groups
                .computeIfAbsent(resource, key -> new BatchLoader<>(missing -> readGroups(key, missing), List.of()));
    }

    private Map<UUID, Boolean> readOwned(Resource resource, Set<UUID> objectUuids) {
        List<UUID> owned = read(reader -> reader
                .createQuery(OWNED_QUERY, UUID.class)
                .setParameter("ownerUuid", UUID.fromString(userUuid))
                .setParameter("resource", resource)
                .setParameter("objectUuids", objectUuids)
                .getResultList());
        return owned.stream().collect(Collectors.toMap(Function.identity(), uuid -> true, (a, b) -> a));
    }

    private Map<UUID, List<String>> readGroups(Resource resource, Set<UUID> objectUuids) {
        List<Tuple> rows = read(reader -> reader
                .createQuery(GROUPS_QUERY, Tuple.class)
                .setParameter("resource", resource)
                .setParameter("objectUuids", objectUuids)
                .getResultList());
        return rows
                .stream()
                .collect(Collectors
                        .groupingBy(row -> row.get(0, UUID.class), Collectors
                                .mapping(row -> row.get(1, UUID.class).toString(), Collectors.toUnmodifiableList())));
    }

    private <T> T read(Function<EntityManager, T> query) {
        EntityManager reader = entityManagerFactory.createEntityManager();
        try {
            return query.apply(reader);
        } finally {
            reader.close();
        }
    }
}
