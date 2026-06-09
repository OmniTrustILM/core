package com.czertainly.core.logging;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.exception.NotSupportedException;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.logging.records.ResourceObjectIdentity;
import com.czertainly.core.service.ResourceInternalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
public class AuditLogEnhancer {

    private ResourceInternalService resourceService;

    @Autowired
    public void setResourceService(ResourceInternalService resourceService) {
        this.resourceService = resourceService;
    }

    public List<ResourceObjectIdentity> enrichObjectIdentities(List<ResourceObjectIdentity> objects, Resource resource) {
        if (objects == null || objects.isEmpty()) return objects;
        if (!resourceService.hasResourceExtensionService(resource)) return objects;
        List<ResourceObjectIdentity> enrichedObjects = new ArrayList<>();
        for (ResourceObjectIdentity object : objects) {
            if (object != null && object.uuid() != null && object.name() == null) {
                try {
                    enrichedObjects.add(new ResourceObjectIdentity(resourceService.getResourceObjectInternal(resource, object.uuid()).getName(), object.uuid()));
                } catch (NotFoundException | NotSupportedException ignored) {
                    // Did not manage to retrieve object name
                    enrichedObjects.add(object);
                }
            } else enrichedObjects.add(object);
        }
        return enrichedObjects;
    }

    public List<ResourceObjectIdentity> enrichObjectUuids(List<UUID> uuids, Resource resource) {
        if (uuids == null || uuids.isEmpty()) return new ArrayList<>();
        if (resourceService.hasResourceExtensionService(resource)) return uuids.stream().map(uuid -> {
                    String name;
                    try {
                        name = resourceService.getResourceObjectInternal(resource, uuid).getName();
                    } catch (NotFoundException | NotSupportedException e) {
                        name = null;
                    }
                    return new ResourceObjectIdentity(name, uuid);
                }
        ).toList();
        else return uuids.stream().map(uuid -> new ResourceObjectIdentity(null, uuid)).toList();
    }
}
