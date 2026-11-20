package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Tuple;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Answers which objects one principal owns and which groups an object belongs to. Each resource and kind is read with
 * one query covering the objects asked about and every object announced by {@link #prefetch}, and the answers are
 * remembered for the reader's lifetime.
 */
final class AssociationReader {

    private static final String OWNED_QUERY = "SELECT DISTINCT oa.objectUuid FROM OwnerAssociation oa"
            + " WHERE oa.ownerUuid = :ownerUuid AND oa.resource = :resource AND oa.objectUuid IN :objectUuids";

    private static final String GROUPS_QUERY = "SELECT ga.objectUuid, ga.groupUuid FROM GroupAssociation ga"
            + " WHERE ga.resource = :resource AND ga.objectUuid IN :objectUuids";

    private final BiFunction<Resource, Set<UUID>, Set<UUID>> readOwned;

    private final BiFunction<Resource, Set<UUID>, Map<UUID, List<String>>> readGroups;

    private final Map<Resource, BatchLoader<Boolean>> owners = new EnumMap<>(Resource.class);

    private final Map<Resource, BatchLoader<List<String>>> groups = new EnumMap<>(Resource.class);

    AssociationReader(BiFunction<Resource, Set<UUID>, Set<UUID>> readOwned,
            BiFunction<Resource, Set<UUID>, Map<UUID, List<String>>> readGroups) {
        this.readOwned = readOwned;
        this.readGroups = readGroups;
    }

    /** Reads through the caller's EntityManager, so the answers include rows its own transaction wrote. */
    static AssociationReader attached(EntityManager entityManager, String ownerUuid) {
        return new AssociationReader((resource, objectUuids) -> owned(entityManager, ownerUuid, resource, objectUuids),
                (resource, objectUuids) -> groups(entityManager, resource, objectUuids));
    }

    /** Reads through a short-lived EntityManager per query, so no connection is held between reads. */
    static AssociationReader detached(EntityManagerFactory entityManagerFactory, String ownerUuid) {
        return new AssociationReader(
                (resource, objectUuids) -> DetachedReads
                        .read(entityManagerFactory, reader -> owned(reader, ownerUuid, resource, objectUuids)),
                (resource, objectUuids) -> DetachedReads
                        .read(entityManagerFactory, reader -> groups(reader, resource, objectUuids)));
    }

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

    /** Objects already known to be owned are left out of the batched group read, as ownership grants them first. */
    List<String> groupsOf(Resource resource, UUID objectUuid) {
        if (objectUuid == null) {
            return List.of();
        }
        BatchLoader<List<String>> loader = groups(resource);
        if (resource.hasOwner()) {
            BatchLoader<Boolean> ownership = owners(resource);
            loader.withdraw(uuid -> ownership.known(uuid).orElse(false));
        }
        return loader.get(List.of(objectUuid)).get(objectUuid);
    }

    private BatchLoader<Boolean> owners(Resource resource) {
        return owners
                .computeIfAbsent(resource,
                        key -> new BatchLoader<>(missing -> readOwned
                                .apply(key, missing)
                                .stream()
                                .collect(Collectors.toMap(Function.identity(), owned -> true)), false));
    }

    private BatchLoader<List<String>> groups(Resource resource) {
        return groups
                .computeIfAbsent(resource,
                        key -> new BatchLoader<>(missing -> readGroups.apply(key, missing), List.of()));
    }

    private static Set<UUID> owned(EntityManager reader, String ownerUuid, Resource resource, Set<UUID> objectUuids) {
        return Set
                .copyOf(reader
                        .createQuery(OWNED_QUERY, UUID.class)
                        .setParameter("ownerUuid", UUID.fromString(ownerUuid))
                        .setParameter("resource", resource)
                        .setParameter("objectUuids", objectUuids)
                        .getResultList());
    }

    private static Map<UUID, List<String>> groups(EntityManager reader, Resource resource, Set<UUID> objectUuids) {
        return reader
                .createQuery(GROUPS_QUERY, Tuple.class)
                .setParameter("resource", resource)
                .setParameter("objectUuids", objectUuids)
                .getResultList()
                .stream()
                .collect(Collectors
                        .groupingBy(row -> row.get(0, UUID.class), Collectors
                                .mapping(row -> row.get(1, UUID.class).toString(), Collectors.toUnmodifiableList())));
    }
}
