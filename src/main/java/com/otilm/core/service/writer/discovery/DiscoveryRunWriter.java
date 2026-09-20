package com.otilm.core.service.writer.discovery;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import com.otilm.core.service.TriggerExternalService;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The one transaction that creates a discovery run.
 *
 * <p>
 * The caller reads everything the connector has to say first, since a connector call must never hold a transaction
 * open, and hands it here as data, so the run, its attributes and its triggers commit as one unit; filed separately, a
 * later failure leaves an {@code IN_PROGRESS} run missing part of its configuration.
 *
 * <p>
 * The detail is mapped here because the caller runs {@code NOT_SUPPORTED} and cannot load the lazy associations.
 */
@Service
public class DiscoveryRunWriter {

    private final DiscoveryRepository discoveryRepository;
    private final AttributeEngine attributeEngine;
    private final TriggerExternalService triggerService;

    // Constructed rather than set, unlike the services that hold this same collaborator: a writer bean may expose no
    // public method that is not a REQUIRED transaction, which a setter would be.
    public DiscoveryRunWriter(DiscoveryRepository discoveryRepository, AttributeEngine attributeEngine,
            TriggerExternalService triggerService) {
        this.discoveryRepository = discoveryRepository;
        this.attributeEngine = attributeEngine;
        this.triggerService = triggerService;
    }

    /**
     * Persists a prepared run with its attributes and trigger associations, and returns its detail.
     *
     * @param discovery the populated, unsaved run
     * @param resourceDefinitions attribute definitions read from the connector and already validated against the
     * request, one entry per resource the run targets; empty for a v1 run, which targets certificates implicitly and
     * publishes no per-resource attribute definitions
     */
    // rollbackFor: the writes below throw checked AttributeException and NotFoundException, which Spring does not roll
    // back on by default -- an attribute that failed to persist would then commit the orphan run row this bean exists
    // to prevent.
    @Transactional(rollbackFor = Exception.class)
    public DiscoveryDetailDto createRun(Discovery discovery, DiscoveryDto request, UUID connectorUuid,
            Map<Resource, List<BaseAttribute>> resourceDefinitions) throws AttributeException, NotFoundException {
        Discovery saved = discoveryRepository.save(discovery);

        attributeEngine
                .updateObjectCustomAttributesContent(Resource.DISCOVERY, saved.getUuid(),
                        request.getCustomAttributes());
        attributeEngine
                .updateObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.DISCOVERY, saved.getUuid())
                        .connector(connectorUuid)
                        .build(), request.getAttributes());

        for (Map.Entry<Resource, List<BaseAttribute>> perResource : resourceDefinitions.entrySet()) {
            // The definitions must exist before content can be filed against them: the engine resolves every
            // submitted attribute to an attribute_definition row, and a relay hands the schema out without
            // recording it, so posting back what was just fetched would answer 404.
            //
            // Keyed by operation rather than by sourceObjectType, which records where content came from rather
            // than which schema it belongs to: a definition is keyed by operation, so two resources declaring an
            // attribute of the same name would otherwise collide on one definition, and the request builder reads
            // them back by operation too.
            String operation = perResource.getKey().getCode();
            attributeEngine.updateDataAttributeDefinitions(connectorUuid, operation, perResource.getValue());
            // A resource the request filed no content against still has an entry; the engine takes the empty list.
            List<RequestAttribute> content = request.getResourceAttributes() == null
                    ? List.of()
                    : request.getResourceAttributes().getOrDefault(perResource.getKey(), List.of());
            attributeEngine
                    .updateObjectDataAttributesContent(ObjectAttributeContentInfo
                            .builder(Resource.DISCOVERY, saved.getUuid())
                            .connector(connectorUuid)
                            .operation(operation)
                            .build(), content);
        }

        if (request.getTriggers() != null) {
            triggerService
                    .createTriggerAssociations(ResourceEvent.CERTIFICATE_DISCOVERED, Resource.DISCOVERY,
                            saved.getUuid(), request.getTriggers(), false);
            saved = discoveryRepository.findWithTriggersByUuid(saved.getUuid());
        }
        // All zero by construction: the run was inserted in this transaction and nothing since has written a message
        // or staged an item.
        return DiscoveryDtoMapper.toDetailDto(saved, new DiscoveryDtoMapper.DetailCounts(0, 0, 0, 0));
    }
}
