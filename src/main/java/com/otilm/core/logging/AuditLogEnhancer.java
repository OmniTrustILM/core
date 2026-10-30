package com.otilm.core.logging;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.logging.records.ResourceRecord;
import com.otilm.core.service.ResourceInternalService;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AuditLogEnhancer {

    private ResourceInternalService resourceService;

    @Autowired
    public void setResourceService(ResourceInternalService resourceService) {
        this.resourceService = resourceService;
    }

    /** The record with the names of its resource objects filled in, as the audit log keeps it. */
    public LogRecord withObjectIdentities(LogRecord logRecord) {
        return LogRecord
                .builder()
                .audited(true)
                .timestamp(logRecord.timestamp())
                .version(logRecord.version())
                .message(logRecord.message())
                .actor(logRecord.actor())
                .additionalData(logRecord.additionalData())
                .module(logRecord.module())
                .source(logRecord.source())
                .operationData(logRecord.operationData())
                .operation(logRecord.operation())
                .operationResult(logRecord.operationResult())
                .resource(new ResourceRecord(logRecord.resource().type(),
                        enrichObjectIdentities(logRecord.resource().objects(), logRecord.resource().type())))
                .affiliatedResource(logRecord.affiliatedResource() == null
                        ? null
                        : new ResourceRecord(logRecord.affiliatedResource().type(),
                                enrichObjectIdentities(logRecord.affiliatedResource().objects(),
                                        logRecord.affiliatedResource().type())))
                .build();
    }

    public List<ResourceObjectIdentity> enrichObjectIdentities(List<ResourceObjectIdentity> objects,
            Resource resource) {
        if (objects == null || objects.isEmpty()) {
            return objects;
        }
        if (!resourceService.hasResourceExtensionService(resource)) {
            return objects;
        }
        List<ResourceObjectIdentity> enrichedObjects = new ArrayList<>();
        for (ResourceObjectIdentity object : objects) {
            if (object != null && object.uuid() != null && StringUtils.isBlank(object.name())) {
                try {
                    enrichedObjects
                            .add(new ResourceObjectIdentity(
                                    resourceService.getResourceObjectInternal(resource, object.uuid()).getName(),
                                    object.uuid()));
                } catch (NotFoundException | NotSupportedException ignored) {
                    // Did not manage to retrieve object name
                    enrichedObjects.add(object);
                }
            } else {
                enrichedObjects.add(object);
            }
        }
        return enrichedObjects;
    }

    public List<ResourceObjectIdentity> enrichObjectUuids(List<UUID> uuids, Resource resource) {
        if (uuids == null || uuids.isEmpty()) {
            return new ArrayList<>();
        }
        if (resourceService.hasResourceExtensionService(resource)) {
            return uuids.stream().map(uuid -> {
                String name;
                try {
                    name = resourceService.getResourceObjectInternal(resource, uuid).getName();
                } catch (NotFoundException | NotSupportedException e) {
                    name = null;
                }
                return new ResourceObjectIdentity(name, uuid);
            }).toList();
        } else {
            return uuids.stream().map(uuid -> new ResourceObjectIdentity(null, uuid)).toList();
        }
    }
}
