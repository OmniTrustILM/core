package com.otilm.core.reference;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository.ResourceAttributeReferrer;
import com.otilm.core.service.ResourceInternalService;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

/**
 * Connector-defined RESOURCE attributes, such as a token's PIN or an authority's OAuth client, can point at an object
 * of any resource an attribute can name. This one source finds every such reference in the stored attribute values, so
 * a connector that adds such an attribute needs no change in Core.
 */
@Component
public class ResourceAttributeReferenceSource implements ObjectReferenceSource {

    private static final Set<Resource> ATTRIBUTE_REFERENCEABLE = Arrays
            .stream(AttributeResource.values())
            .map(attributeResource -> Resource.findByCode(attributeResource.getCode()))
            .collect(Collectors.toUnmodifiableSet());

    private final AttributeContent2ObjectRepository attributeContent2ObjectRepository;
    private final ResourceInternalService resourceService;
    private final Map<Resource, CurrentVersionSource> currentVersionSources;

    /**
     * The resource service reaches every resource's service, the secret service among them, which needs this source
     * through the guard; it is looked up on first use.
     */
    public ResourceAttributeReferenceSource(AttributeContent2ObjectRepository attributeContent2ObjectRepository,
            @Lazy ResourceInternalService resourceService, List<CurrentVersionSource> currentVersionSources) {
        this.attributeContent2ObjectRepository = attributeContent2ObjectRepository;
        this.resourceService = resourceService;
        this.currentVersionSources = currentVersionSources
                .stream()
                .collect(Collectors.toUnmodifiableMap(CurrentVersionSource::resource, Function.identity()));
    }

    @Override
    public Set<Resource> referencedResources() {
        return ATTRIBUTE_REFERENCEABLE;
    }

    @Override
    public List<ObjectReferrer> findReferrers(ObjectRef referenced) {
        return attributeContent2ObjectRepository
                .findResourceAttributeReferrers(referenced.resource().getCode(), referenced.uuid().toString())
                .stream()
                .filter(this::mayStillHoldReference)
                .map(this::toReferrer)
                .flatMap(Optional::stream)
                .filter(referrer -> !referrer.object().equals(referenced))
                .toList();
    }

    private boolean mayStillHoldReference(ResourceAttributeReferrer row) {
        if (row.getObjectVersion() == null) {
            return true;
        }
        CurrentVersionSource versions = currentVersionSources.get(Resource.valueOf(row.getObjectType()));
        return versions == null
                || versions.currentVersion(row.getObjectUuid()).map(row.getObjectVersion()::equals).orElse(false);
    }

    /** A row whose object is gone was left behind by that object's delete and holds nothing. */
    private Optional<ObjectReferrer> toReferrer(ResourceAttributeReferrer row) {
        ObjectRef object = new ObjectRef(Resource.valueOf(row.getObjectType()), row.getObjectUuid());
        String usage = "attribute '%s'".formatted(row.getAttributeLabel());
        if (!resourceService.hasResourceExtensionService(object.resource())) {
            return Optional.of(new ObjectReferrer(object, object.uuid().toString(), usage));
        }
        try {
            String name = resourceService.getResourceObjectInternal(object.resource(), object.uuid()).getName();
            return Optional.of(new ObjectReferrer(object, name, usage));
        } catch (NotFoundException e) {
            return Optional.empty();
        }
    }
}
