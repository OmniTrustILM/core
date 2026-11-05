package com.otilm.core.security.authz;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.ObjectAllowedActionsDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ObjectActionRequirements.OnAncestor;
import com.otilm.core.security.authz.ObjectActionRequirements.OnObject;
import com.otilm.core.security.authz.ObjectActionRequirements.OnResource;
import com.otilm.core.security.authz.ObjectActionRequirements.Requirement;
import com.otilm.core.security.authz.ObjectActionRequirements.ResourceObjects;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Reports the actions the current principal may perform on objects of one resource, as {@link ObjectActionRequirements}
 * describes the endpoints that perform them. Objects that do not exist, or that the principal may neither list nor
 * view, are left out. Each decision is the one enforcement makes, asked once per call.
 */
@Component
public class ObjectActionResolver {

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
                        .create("Resource %s has no objects authorized individually".formatted(resource.getCode()))));
        Call call = new Call();
        List<ObjectAllowedActionsDto> items = new ArrayList<>();
        for (UUID objectUuid : new LinkedHashSet<>(objectUuids)) {
            if (!exists(objects, objectUuid) || !call.isVisible(resource, objectUuid)) {
                continue;
            }
            List<ResourceAction> allowed = objects
                    .actions()
                    .entrySet()
                    .stream()
                    .filter(entry -> entry
                            .getValue()
                            .stream()
                            .allMatch(requirement -> call.isMet(requirement, resource, objectUuid)))
                    .map(Map.Entry::getKey)
                    .sorted(Comparator.comparing(ResourceAction::getCode))
                    .toList();
            items.add(new ObjectAllowedActionsDto(objectUuid, allowed));
        }
        return items;
    }

    private boolean exists(ResourceObjects objects, UUID objectUuid) {
        return select(objects.entity(), "uuid", objectUuid).isPresent();
    }

    private Optional<UUID> parentOf(Resource resource, UUID objectUuid) {
        return ObjectActionRequirements
                .of(resource)
                .filter(objects -> objects.parentAttribute() != null)
                .flatMap(objects -> select(objects.entity(), objects.parentAttribute(), objectUuid));
    }

    private Optional<UUID> select(Class<?> entity, String attribute, UUID objectUuid) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<UUID> query = cb.createQuery(UUID.class);
        Root<?> root = query.from(entity);
        query.select(root.get(attribute)).where(cb.equal(root.get("uuid"), objectUuid));
        return entityManager.createQuery(query).getResultStream().filter(Objects::nonNull).findFirst();
    }

    /** Decisions made while answering one request, so a check shared by several actions or objects is asked once. */
    private final class Call {

        private final Map<String, Boolean> decisions = new HashMap<>();

        boolean isVisible(Resource resource, UUID objectUuid) {
            return onObject(resource, ResourceAction.LIST, objectUuid)
                    || onObject(resource, ResourceAction.DETAIL, objectUuid);
        }

        boolean isMet(Requirement requirement, Resource resource, UUID objectUuid) {
            return switch (requirement) {
                case OnObject onObject -> onObject(resource, onObject.action(), objectUuid);
                case OnResource onResource -> decisions
                        .computeIfAbsent(resource.getCode() + ":" + onResource.action().getCode(),
                                key -> authorizationEnforcer.isAuthorized(resource, onResource.action()));
                case OnAncestor onAncestor -> ancestor(resource, objectUuid, onAncestor.ancestor())
                        .map(ancestorUuid -> onObject(onAncestor.ancestor(), onAncestor.action(), ancestorUuid))
                        .orElse(false);
            };
        }

        private boolean onObject(Resource resource, ResourceAction action, UUID objectUuid) {
            return decisions
                    .computeIfAbsent(resource.getCode() + ":" + action.getCode() + ":" + objectUuid,
                            key -> authorizationEnforcer
                                    .isAuthorized(resource, action, SecuredUUID.fromUUID(objectUuid)));
        }

        private Optional<UUID> ancestor(Resource resource, UUID objectUuid, Resource ancestor) {
            Resource current = resource;
            Optional<UUID> currentUuid = Optional.of(objectUuid);
            while (currentUuid.isPresent() && current != ancestor) {
                Resource parent = ObjectActionRequirements
                        .of(current)
                        .map(ResourceObjects::parent)
                        .orElse(Resource.NONE);
                if (parent == Resource.NONE) {
                    return Optional.empty();
                }
                currentUuid = parentOf(current, currentUuid.get());
                current = parent;
            }
            return currentUuid;
        }
    }
}
