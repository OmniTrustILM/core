package com.otilm.core.reference;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.ResourceInternalService;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

/**
 * Refuses to delete an object while anything still references it, in one message that names every referrer the caller
 * may see and counts the rest.
 */
@Component
public class ObjectReferenceGuard {

    private final List<ObjectReferenceSource> sources;
    private final ResourceInternalService resourceService;
    private final AuthorizationEnforcer authorizationEnforcer;

    /** The resource service reaches the secret service, which needs this guard; it is looked up on first use. */
    public ObjectReferenceGuard(List<ObjectReferenceSource> sources, @Lazy ResourceInternalService resourceService,
            AuthorizationEnforcer authorizationEnforcer) {
        this.sources = sources;
        this.resourceService = resourceService;
        this.authorizationEnforcer = authorizationEnforcer;
    }

    /**
     * An owner that deletes the object together with itself names itself as {@code releasedBy}: its own reference goes
     * away with it, and every other reference still refuses. Anyone else passes null.
     */
    public void refuseWhileReferenced(ObjectRef referenced, String name, ObjectRef releasedBy) {
        List<ObjectReferrer> referrers = sources
                .stream()
                .filter(source -> source.referencedResources().contains(referenced.resource()))
                .flatMap(source -> source.findReferrers(referenced).stream())
                .filter(referrer -> !referrer.object().equals(releasedBy))
                .distinct()
                .toList();
        if (referrers.isEmpty()) {
            return;
        }
        Map<ObjectRef, Boolean> visibleObjects = new HashMap<>();
        Predicate<ObjectReferrer> visibleToCaller = referrer -> referrer
                .disclosedObjects()
                .stream()
                .allMatch(object -> visibleObjects.computeIfAbsent(object, this::isVisibleToCaller));
        Map<Boolean, List<ObjectReferrer>> byVisibility = referrers
                .stream()
                .collect(Collectors.partitioningBy(visibleToCaller));
        List<String> named = byVisibility.get(true).stream().map(ObjectReferrer::describe).distinct().toList();
        long hiddenCount = byVisibility.get(false).stream().map(ObjectReferrer::object).distinct().count();
        throw new ValidationException(ValidationError
                .create("Cannot delete %s '%s': it is still used by %s."
                        .formatted(referenced.resource().getLabel(), name, usedBy(named, hiddenCount))));
    }

    static String usedBy(List<String> namedReferrers, long hiddenCount) {
        List<String> parts = new ArrayList<>(namedReferrers);
        if (hiddenCount > 0) {
            parts
                    .add(hiddenCount == 1
                            ? "1 object you are not allowed to see"
                            : "%d objects you are not allowed to see".formatted(hiddenCount));
        }
        return String.join("; ", parts);
    }

    private boolean isVisibleToCaller(ObjectRef object) {
        try {
            authorizationEnforcer
                    .enforce(object.resource(), ResourceAction.DETAIL, SecuredUUID.fromUUID(object.uuid()));
            enforcePermissionChain(object);
            return true;
        } catch (AccessDeniedException e) {
            return false;
        }
    }

    /** The resource's own object read applies its parent's permission too, as the resource API does. */
    private void enforcePermissionChain(ObjectRef object) {
        try {
            resourceService.getResourceObject(object.resource(), object.uuid());
        } catch (NotFoundException | NotSupportedException e) {
            // the object's own permission, enforced already, decides
        }
    }
}
