package com.otilm.core.service.writer.discovery;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.service.handler.discovery.StagedMetadata;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Staging writes against {@code discovery_item}. {@code REQUIRED} so a staged item commits or rolls back with the
 * cursor advance that accounts for it — a committed item the cursor does not cover would be drained and staged again.
 */
@Service
public class DiscoveryItemWriter {

    private final DiscoveryItemRepository itemRepository;
    private final ObjectMapper objectMapper;

    public DiscoveryItemWriter(DiscoveryItemRepository itemRepository, ObjectMapper objectMapper) {
        this.itemRepository = itemRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * Stages one drained item for the run, ignoring a repeat of one already staged.
     *
     * @param newlyDiscovered whether the item was absent from inventory when staged
     * @throws IllegalArgumentException when the connector's payload cannot be serialized — a page that cannot represent
     * one of its items must fail rather than commit a cursor that skips past it
     */
    @Transactional
    public void stage(UUID discoveryUuid, DiscoveredItemDto item, boolean newlyDiscovered) {
        StagedMetadata.Sealed stagedMeta = StagedMetadata.seal(item.getMeta());
        itemRepository
                // Stores the enum's name, since the column is read back through EnumType.STRING.
                .stage(UUID.randomUUID(), discoveryUuid, item.getResource().name(), item.getSequence(),
                        item.getUniqueRef(), asJson(item.getPayload()), item.getDiscoveredAt(), newlyDiscovered,
                        stagedMeta.meta() == null ? null : asJson(stagedMeta.meta()), stagedMeta.protectedMeta());
    }

    private String asJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Discovered item payload could not be serialized for staging", e);
        }
    }
}
