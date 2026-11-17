package com.otilm.core.security.authz;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.security.authn.PlatformUserDetails;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Tuple;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

/**
 * Caches one principal's owner and group associations for a single allowed-actions call, so the authorization fallbacks
 * read them with one query per resource instead of one per object. Each read opens and closes its own EntityManager,
 * because the request's EntityManager would keep a connection open across every OPA call.
 *
 * <p>
 * It also answers, through {@link #grantsAllOf}, the checks OPA would grant a principal allowed all resources, so those
 * skip OPA entirely.
 */
final class AssociationSnapshot {

    private static final String OWNED_QUERY = "SELECT DISTINCT oa.objectUuid FROM OwnerAssociation oa"
            + " WHERE oa.ownerUuid = :ownerUuid AND oa.resource = :resource AND oa.objectUuid IN :objectUuids";

    private static final String GROUPS_QUERY = "SELECT ga.objectUuid, ga.groupUuid FROM GroupAssociation ga"
            + " WHERE ga.resource = :resource AND ga.objectUuid IN :objectUuids";

    private final EntityManagerFactory entityManagerFactory;

    private final ObjectMapper objectMapper;

    private final String userUuid;

    private final UUID ownerUuid;

    private final String rawData;

    private final Map<Resource, Set<UUID>> pendingOwners = new EnumMap<>(Resource.class);

    private final Map<Resource, Map<UUID, Boolean>> owned = new EnumMap<>(Resource.class);

    private final Map<Resource, Set<UUID>> pendingGroups = new EnumMap<>(Resource.class);

    private final Map<Resource, Map<UUID, List<String>>> groups = new EnumMap<>(Resource.class);

    private AllResourcesGrant allResourcesGrant;

    AssociationSnapshot(EntityManagerFactory entityManagerFactory, ObjectMapper objectMapper,
            PlatformUserDetails principal) {
        this.entityManagerFactory = entityManagerFactory;
        this.objectMapper = objectMapper;
        this.userUuid = principal.getUserUuid();
        this.ownerUuid = UUID.fromString(principal.getUserUuid());
        this.rawData = principal.getRawData();
    }

    boolean isFor(PlatformUserDetails principal) {
        return userUuid.equals(principal.getUserUuid()) && Objects.equals(rawData, principal.getRawData());
    }

    /**
     * Announces objects to read in the same query as the first object of their resource asked about.
     */
    void prefetch(Resource resource, Collection<UUID> objectUuids) {
        if (resource.hasOwner()) {
            pendingOwners.computeIfAbsent(resource, key -> new LinkedHashSet<>()).addAll(objectUuids);
        }
        if (resource.hasGroups()) {
            pendingGroups.computeIfAbsent(resource, key -> new LinkedHashSet<>()).addAll(objectUuids);
        }
    }

    boolean ownsAll(Resource resource, Collection<UUID> objectUuids) {
        Map<UUID, Boolean> known = owned.computeIfAbsent(resource, key -> new HashMap<>());
        Set<UUID> unknown = unknown(known.keySet(), pendingOwners, resource, objectUuids);
        if (!unknown.isEmpty()) {
            List<UUID> read = read(reader -> reader
                    .createQuery(OWNED_QUERY, UUID.class)
                    .setParameter("ownerUuid", ownerUuid)
                    .setParameter("resource", resource)
                    .setParameter("objectUuids", unknown)
                    .getResultList());
            Set<UUID> ownedNow = new HashSet<>(read);
            unknown.forEach(objectUuid -> known.put(objectUuid, ownedNow.contains(objectUuid)));
            pendingOwners.remove(resource);
        }
        return objectUuids.stream().allMatch(known::get);
    }

    List<String> groupsOf(Resource resource, UUID objectUuid) {
        if (objectUuid == null) {
            return List.of();
        }
        Map<UUID, List<String>> known = groups.computeIfAbsent(resource, key -> new HashMap<>());
        Set<UUID> unknown = unknown(known.keySet(), pendingGroups, resource, List.of(objectUuid));
        if (!unknown.isEmpty()) {
            List<Tuple> read = read(reader -> reader
                    .createQuery(GROUPS_QUERY, Tuple.class)
                    .setParameter("resource", resource)
                    .setParameter("objectUuids", unknown)
                    .getResultList());
            Map<UUID, List<String>> readGroups = new HashMap<>();
            unknown.forEach(uuid -> readGroups.put(uuid, new ArrayList<>()));
            read.forEach(row -> readGroups.get(row.get(0, UUID.class)).add(row.get(1, UUID.class).toString()));
            known.putAll(readGroups);
            pendingGroups.remove(resource);
        }
        return known.get(objectUuid);
    }

    /**
     * Whether OPA would grant the check on {@code resourceName} to {@code principal} without asking it: the principal
     * is this snapshot's, its permissions allow all resources, and they deny no object of that resource.
     */
    boolean grantsAllOf(String principal, String resourceName) {
        if (resourceName == null || !Objects.equals(rawData, principal)) {
            return false;
        }
        if (allResourcesGrant == null) {
            allResourcesGrant = AllResourcesGrant.parse(objectMapper, rawData);
        }
        return allResourcesGrant.grants(resourceName);
    }

    /**
     * The asked objects not read yet, together with every announced object of the resource not read yet. The announced
     * objects stay pending until a read succeeds, so a failed read is retried by the next decision.
     */
    private static Set<UUID> unknown(Set<UUID> known, Map<Resource, Set<UUID>> pending, Resource resource,
            Collection<UUID> asked) {
        Set<UUID> unknown = new LinkedHashSet<>();
        asked.stream().filter(objectUuid -> !known.contains(objectUuid)).forEach(unknown::add);
        if (!unknown.isEmpty()) {
            pending
                    .getOrDefault(resource, Set.of())
                    .stream()
                    .filter(objectUuid -> !known.contains(objectUuid))
                    .forEach(unknown::add);
        }
        return unknown;
    }

    private <T> T read(Function<EntityManager, T> query) {
        EntityManager reader = entityManagerFactory.createEntityManager();
        try {
            return query.apply(reader);
        } finally {
            reader.close();
        }
    }

    /**
     * The part of the OPA method policy that needs no request: {@code AllResourcesAllowed} allows every check when
     * {@code permissions.allowAllResources} is true, and the only deny, {@code ActionDeniedForSpecificObject}, needs an
     * object of the requested resource whose {@code deny} is not empty. Without such an object OPA authorizes the check
     * whatever it asks, so granting it here never grants what OPA would refuse. Any shape the policy might read
     * differently counts as a deny.
     */
    private record AllResourcesGrant(boolean allowAllResources, Set<String> resourcesWithDeny) {

        private static final AllResourcesGrant NONE = new AllResourcesGrant(false, Set.of());

        boolean grants(String resourceName) {
            return allowAllResources && !resourcesWithDeny.contains(resourceName);
        }

        static AllResourcesGrant parse(ObjectMapper objectMapper, String rawData) {
            JsonNode permissions;
            try {
                permissions = objectMapper.readTree(rawData).path("permissions");
            } catch (JsonProcessingException | IllegalArgumentException e) {
                return NONE;
            }
            JsonNode allowAllResources = permissions.path("allowAllResources");
            if (!allowAllResources.isBoolean() || !allowAllResources.booleanValue()) {
                return NONE;
            }
            JsonNode resources = permissions.path("resources");
            if (isAbsent(resources)) {
                return new AllResourcesGrant(true, Set.of());
            }
            if (!resources.isArray()) {
                return NONE;
            }
            Set<String> resourcesWithDeny = new HashSet<>();
            for (JsonNode resource : resources) {
                JsonNode name = resource.path("name");
                if (name.isTextual() && deniesAnObject(resource.path("objects"))) {
                    resourcesWithDeny.add(name.textValue());
                }
            }
            return new AllResourcesGrant(true, resourcesWithDeny);
        }

        private static boolean deniesAnObject(JsonNode objects) {
            if (isAbsent(objects)) {
                return false;
            }
            if (!objects.isArray()) {
                return true;
            }
            for (JsonNode object : objects) {
                JsonNode deny = object.path("deny");
                if (!isAbsent(deny) && !(deny.isArray() && deny.isEmpty())) {
                    return true;
                }
            }
            return false;
        }

        private static boolean isAbsent(JsonNode node) {
            return node.isMissingNode() || node.isNull();
        }
    }
}
