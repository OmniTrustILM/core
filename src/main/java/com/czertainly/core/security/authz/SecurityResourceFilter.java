package com.czertainly.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Getter
@Setter
public class SecurityResourceFilter {

    private Resource resource;

    private ResourceAction resourceAction;

    /**
     * List of object uuids user can access
     */
    private final List<UUID> allowedObjects;

    /**
     * List of object uuids user can not access
     */
    private final List<UUID> forbiddenObjects;

    /**
     * Specifies whether the user has access to all objects or only those explicitly allowed.
     * When true, the user can access only objects to which access is explicitly allowed.
     * When false, the user can access all objects except those to which access is explicitly forbidden.
     */
    private boolean areOnlySpecificObjectsAllowed;

    protected SecurityResourceFilter() {
        this(new ArrayList<>(), new ArrayList<>(), false);
    }

    public SecurityResourceFilter(List<String> allowedObjects, List<String> forbiddenObjects, boolean areOnlySpecificObjectsAllowed) {
        this.allowedObjects = allowedObjects.stream().map(UUID::fromString).collect(Collectors.toList());
        this.forbiddenObjects = forbiddenObjects.stream().map(UUID::fromString).collect(Collectors.toList());
        this.areOnlySpecificObjectsAllowed = areOnlySpecificObjectsAllowed;
    }

    public static SecurityResourceFilter create() {
        return new SecurityResourceFilter();
    }

    public void addAllowedObjects(List<String> objectUUIDs) {
        this.allowedObjects.addAll(objectUUIDs.stream().map(UUID::fromString).toList());
    }

    public void addDeniedObjects(List<String> objectUUIDs) {
        this.forbiddenObjects.addAll(objectUUIDs.stream().map(UUID::fromString).toList());
    }

    public boolean areOnlySpecificObjectsAllowed() {
        return areOnlySpecificObjectsAllowed;
    }
}
