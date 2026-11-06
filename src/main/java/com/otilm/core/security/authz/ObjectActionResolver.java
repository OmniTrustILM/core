package com.otilm.core.security.authz;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.ObjectAllowedActionsDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ObjectActionRequirements.OnAncestor;
import com.otilm.core.security.authz.ObjectActionRequirements.OnLinked;
import com.otilm.core.security.authz.ObjectActionRequirements.OnLinkedThrough;
import com.otilm.core.security.authz.ObjectActionRequirements.OnObject;
import com.otilm.core.security.authz.ObjectActionRequirements.OnObjectUnder;
import com.otilm.core.security.authz.ObjectActionRequirements.OnResource;
import com.otilm.core.security.authz.ObjectActionRequirements.Requirement;
import com.otilm.core.security.authz.ObjectActionRequirements.ResourceObjects;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Tuple;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Selection;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.springframework.stereotype.Component;

/**
 * Reports the actions the current principal may perform on objects of one resource, as {@link ObjectActionRequirements}
 * describes the endpoints that perform them. Objects that do not exist, or that the principal may neither list nor
 * view, are left out. Each decision is the one enforcement makes, asked once per call, and the requested objects are
 * read in one query.
 */
@Component
public class ObjectActionResolver {

    private static final String UUID_ATTRIBUTE = "uuid";

    private final AuthorizationEnforcer authorizationEnforcer;

    @PersistenceContext
    private EntityManager entityManager;

    public ObjectActionResolver(AuthorizationEnforcer authorizationEnforcer) {
        this.authorizationEnforcer = authorizationEnforcer;
    }

    public List<ObjectAllowedActionsDto> resolve(Resource resource, List<UUID> objectUuids) {
        ResourceObjects objects = ObjectActionRequirements
                .of(resource)
                .orElseThrow(() -> new ValidationException(ValidationError
                        .create("Resource %s has no objects identified by UUID and authorized individually"
                                .formatted(resource.getCode()))));
        Call call = new Call();
        Set<UUID> requested = new LinkedHashSet<>(objectUuids);
        Set<UUID> existing = call.load(resource, objects, requested);
        List<ObjectAllowedActionsDto> items = new ArrayList<>();
        for (UUID objectUuid : requested) {
            if (!existing.contains(objectUuid) || !call.isVisible(resource, objects, objectUuid)) {
                continue;
            }
            List<ResourceAction> allowed = objects
                    .actions()
                    .entrySet()
                    .stream()
                    .filter(entry -> call.allMet(entry.getValue(), resource, objectUuid))
                    .map(Map.Entry::getKey)
                    .sorted(Comparator.comparing(ResourceAction::getCode))
                    .toList();
            items.add(new ObjectAllowedActionsDto(objectUuid, allowed));
        }
        return items;
    }

    private static Set<String> attributesRead(ResourceObjects objects) {
        Set<String> attributes = new LinkedHashSet<>();
        if (objects.parentAttribute() != null) {
            attributes.add(objects.parentAttribute());
        }
        Stream
                .of(Stream.of(objects.listing(), objects.viewing()), objects.actions().values().stream())
                .flatMap(lists -> lists.flatMap(List::stream))
                .forEach(requirement -> {
                    switch (requirement) {
                        case OnLinked onLinked -> attributes.add(onLinked.attribute());
                        case OnObjectUnder under -> attributes.add(under.parentAttribute());
                        case OnLinkedThrough through -> attributes.add(through.attribute());
                        default -> {
                        }
                    }
                });
        return attributes;
    }

    /** Decisions and attributes read while answering one request, so each is asked once. */
    private final class Call {

        private final Map<String, Boolean> decisions = new HashMap<>();

        private final Map<String, Optional<UUID>> attributes = new HashMap<>();

        /** Reads the requested objects with every attribute the requirements need; returns those that exist. */
        Set<UUID> load(Resource resource, ResourceObjects objects, Collection<UUID> objectUuids) {
            List<String> names = List.copyOf(attributesRead(objects));
            CriteriaBuilder cb = entityManager.getCriteriaBuilder();
            CriteriaQuery<Tuple> query = cb.createTupleQuery();
            Root<?> root = query.from(objects.entity());
            List<Selection<?>> selections = new ArrayList<>();
            selections.add(root.get(UUID_ATTRIBUTE));
            names.forEach(name -> selections.add(root.get(name)));
            query.multiselect(selections).where(root.get(UUID_ATTRIBUTE).in(objectUuids));
            Set<UUID> existing = new HashSet<>();
            for (Tuple row : entityManager.createQuery(query).getResultList()) {
                UUID objectUuid = row.get(0, UUID.class);
                existing.add(objectUuid);
                for (int i = 0; i < names.size(); i++) {
                    attributes
                            .put(key(resource, names.get(i), objectUuid),
                                    Optional.ofNullable(row.get(i + 1, UUID.class)));
                }
            }
            return existing;
        }

        boolean isVisible(Resource resource, ResourceObjects objects, UUID objectUuid) {
            return allMet(objects.listing(), resource, objectUuid) || allMet(objects.viewing(), resource, objectUuid);
        }

        boolean allMet(List<Requirement> requirements, Resource resource, UUID objectUuid) {
            return requirements.stream().allMatch(requirement -> isMet(requirement, resource, objectUuid));
        }

        private boolean isMet(Requirement requirement, Resource resource, UUID objectUuid) {
            return switch (requirement) {
                case OnObject onObject -> onObject(resource, onObject.action(), objectUuid);
                case OnObjectUnder under -> underParent(resource, under, objectUuid);
                case OnResource onResource ->
                    onResource(Objects.requireNonNullElse(onResource.resource(), resource), onResource.action());
                case OnAncestor onAncestor -> ancestor(resource, objectUuid, onAncestor.ancestor())
                        .map(ancestorUuid -> onObject(onAncestor.ancestor(), onAncestor.action(), ancestorUuid))
                        .orElse(false);
                case OnLinked onLinked -> attribute(resource, onLinked.attribute(), objectUuid)
                        .map(linkedUuid -> onObject(onLinked.resource(), onLinked.action(), linkedUuid))
                        .orElse(onLinked.metWhenEmpty());
                case OnLinkedThrough through -> attribute(resource, through.attribute(), objectUuid)
                        .map(linkedUuid -> isMet(through.requirement(), through.through(), linkedUuid))
                        .orElse(false);
            };
        }

        private boolean onObject(Resource resource, ResourceAction action, UUID objectUuid) {
            return decisions
                    .computeIfAbsent(resource.getCode() + ":" + action.getCode() + ":" + objectUuid,
                            key -> authorizationEnforcer
                                    .isAuthorized(resource, action, SecuredUUID.fromUUID(objectUuid)));
        }

        private boolean onResource(Resource resource, ResourceAction action) {
            return decisions
                    .computeIfAbsent(resource.getCode() + ":" + action.getCode(),
                            key -> authorizationEnforcer.isAuthorized(resource, action));
        }

        private boolean underParent(Resource resource, OnObjectUnder under, UUID objectUuid) {
            UUID parentUuid = attribute(resource, under.parentAttribute(), objectUuid).orElse(null);
            return decisions
                    .computeIfAbsent(
                            "%s:%s:%s under %s:%s:%s"
                                    .formatted(resource.getCode(), under.action().getCode(), objectUuid,
                                            under.parent().getCode(), under.parentAction().getCode(), parentUuid),
                            key -> authorizationEnforcer
                                    .isAuthorized(resource, under.action(), SecuredUUID.fromUUID(objectUuid),
                                            under.parent(), under.parentAction(),
                                            SecuredParentUUID.fromUUID(parentUuid)));
        }

        private Optional<UUID> ancestor(Resource resource, UUID objectUuid, Resource ancestor) {
            Resource current = resource;
            Optional<UUID> currentUuid = Optional.of(objectUuid);
            while (currentUuid.isPresent() && current != ancestor) {
                Optional<ResourceObjects> objects = ObjectActionRequirements.of(current);
                if (objects.isEmpty() || objects.get().parent() == Resource.NONE) {
                    return Optional.empty();
                }
                currentUuid = attribute(current, objects.get().parentAttribute(), currentUuid.get());
                current = objects.get().parent();
            }
            return currentUuid;
        }

        private Optional<UUID> attribute(Resource resource, String attribute, UUID objectUuid) {
            return attributes
                    .computeIfAbsent(key(resource, attribute, objectUuid),
                            key -> select(resource, attribute, objectUuid));
        }

        private Optional<UUID> select(Resource resource, String attribute, UUID objectUuid) {
            Class<?> entity = ObjectActionRequirements.of(resource).orElseThrow().entity();
            CriteriaBuilder cb = entityManager.getCriteriaBuilder();
            CriteriaQuery<UUID> query = cb.createQuery(UUID.class);
            Root<?> root = query.from(entity);
            query.select(root.get(attribute)).where(cb.equal(root.get(UUID_ATTRIBUTE), objectUuid));
            return entityManager
                    .createQuery(query)
                    .setMaxResults(1)
                    .getResultList()
                    .stream()
                    .filter(Objects::nonNull)
                    .findFirst();
        }

        private static String key(Resource resource, String attribute, UUID objectUuid) {
            return resource.getCode() + "." + attribute + ":" + objectUuid;
        }
    }
}
