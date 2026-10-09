package com.otilm.core.mapper.discovery;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.client.discovery.DiscoveryListDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemPayloadDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.v2.ConnectorInterfaceDto;
import com.otilm.api.model.core.discovery.DiscoveryItemDto;
import com.otilm.api.model.core.discovery.DiscoveryMessageDto;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryMessage;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.repository.DiscoveryItemRow;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.handler.discovery.StagedMetadata;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.CertificateUtil;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Maps a discovery run and its message log onto the shapes the API publishes. */
public class DiscoveryDtoMapper {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryDtoMapper.class);

    private static final ObjectMapper JSON_COLUMN = ObjectMapperFactory.jsonColumn();

    private DiscoveryDtoMapper() {
    }

    /**
     * Detail counts read from other tables, not stored on the run row.
     *
     * @param runMessages distinct problems the run collected, as the message listing counts them
     * @param newlyDiscoveredItems staged items not already in the inventory
     * @param processedItems how many of those reached the inventory
     * @param failedItems how many of those failed, each with a recorded reason; the other new items are still waiting
     */
    public record DetailCounts(long runMessages, long newlyDiscoveredItems, long processedItems, long failedItems) {
    }

    public static DiscoveryDetailDto toDetailDto(Discovery discovery, DetailCounts counts) {
        DiscoveryDetailDto dto = new DiscoveryDetailDto();
        dto.setUuid(discovery.getUuid().toString());
        dto.setName(discovery.getName());
        dto.setEndTime(discovery.getEndTime());
        dto.setStartTime(discovery.getStartTime());
        dto.setTotalCertificatesDiscovered(discovery.getTotalCertificatesDiscovered());
        dto.setStatus(discovery.getStatus());
        dto.setConnectorUuid(discovery.getConnectorUuid().toString());
        dto.setKind(discovery.getKind());
        dto.setMessage(discovery.getMessage());
        dto.setConnectorName(discovery.getConnectorName());
        dto.setTriggers(discovery.getTriggers().stream().map(Trigger::mapToDto).toList());
        dto.setConnectorStatus(discovery.getConnectorStatus());
        dto.setConnectorTotalCertificatesDiscovered(discovery.getConnectorTotalCertificatesDiscovered());
        dto.setRunMessageCount(counts.runMessages());
        dto.setItemsNewlyDiscovered(counts.newlyDiscoveredItems());
        dto.setItemsProcessed(counts.processedItems());
        dto.setItemsFailed(counts.failedItems());
        dto.setResources(List.copyOf(discovery.getResources()));
        // REQUIRED on the wire. A v1 run stores none: it cannot be stopped, so false is exact.
        dto.setStoppable(Boolean.TRUE.equals(discovery.getStoppable()));
        // Null for a v1 run and for a connector that reports no progress; not defaulted.
        dto.setProgress(discovery.getProgress());
        dto.setConnectorInterface(connectorInterfaceOf(discovery));
        // Drain cursor: sequences are dense per run, so the highest received is how many items the connector sent.
        // An unstageable, malformed or repeated item advances it without adding a row. Null for a v1 run, which never
        // moves it, and for a run its connector's delete released before any item arrived.
        dto
                .setItemsDiscovered(
                        discovery.getConnectorInterfaceUuid() != null || discovery.getLastAppliedSequence() > 0
                                ? discovery.getLastAppliedSequence()
                                : null);
        return dto;
    }

    public static DiscoveryListDto toListDto(Discovery discovery) {
        DiscoveryListDto dto = new DiscoveryListDto();
        dto.setUuid(discovery.getUuid().toString());
        dto.setName(discovery.getName());
        dto.setEndTime(discovery.getEndTime());
        dto.setStartTime(discovery.getStartTime());
        dto.setTotalCertificatesDiscovered(discovery.getTotalCertificatesDiscovered());
        dto.setStatus(discovery.getStatus());
        dto.setConnectorUuid(discovery.getConnectorUuid().toString());
        dto.setKind(discovery.getKind());
        dto.setConnectorName(discovery.getConnectorName());
        dto.setConnectorInterface(connectorInterfaceOf(discovery));
        dto.setTotalItemsDiscovered(discovery.getTotalItemsDiscovered());
        dto.setResources(List.copyOf(discovery.getResources()));
        return dto;
    }

    /** The interface driving the run; null for a v1 run, which is how a client tells the generations apart. */
    private static ConnectorInterfaceDto connectorInterfaceOf(Discovery discovery) {
        return discovery.getConnectorInterface() == null ? null : discovery.getConnectorInterface().mapToDto();
    }

    /** The object the item became, null while unprocessed or failed; named as the certificate listing names it. */
    private static NameAndUuidDto inventoryOf(DiscoveryItemRow row) {
        if (row.getInventoryUuid() == null) {
            return null;
        }
        return new NameAndUuidDto(row.getInventoryUuid(), CertificateUtil.formatCommonName(row.getInventoryName()));
    }

    /**
     * A staged item, from either staging store; {@link DiscoveryItemRow} says why {@code payload} and {@code meta}
     * arrive as JSON text.
     */
    public static DiscoveryItemDto toItemDto(DiscoveryItemRow row) {
        DiscoveryItemDto dto = new DiscoveryItemDto();
        dto.setUuid(row.getUuid().toString());
        dto.setInventory(inventoryOf(row));
        dto.setResource(Resource.valueOf(row.getResource()));
        dto.setSequence(row.getSequence());
        dto.setUniqueRef(row.getUniqueRef());
        dto.setDiscoveredAt(row.getDiscoveredAt() == null ? null : row.getDiscoveredAt().atOffset(ZoneOffset.UTC));
        dto.setPayload(read(row.getUuid(), row.getPayload(), DiscoveredItemPayloadDto.class));
        dto.setNewlyDiscovered(row.isNewlyDiscovered());
        dto.setProcessed(row.isProcessed());
        dto.setProcessedError(row.getProcessedError());
        List<MetadataAttribute> stagedMeta = row.getMeta() == null
                ? null
                : AttributeDefinitionUtils.deserialize(row.getMeta(), MetadataAttribute.class);
        dto.setMeta(StagedMetadata.unseal(stagedMeta, row.getProtectedMeta()));
        return dto;
    }

    /**
     * Staging is permissive, so a payload can carry a resource this build has no type for. The row lists without it;
     * failing instead would 500 every listing of the run.
     */
    private static <T> T read(UUID itemUuid, String json, Class<T> type) {
        if (json == null) {
            return null;
        }
        try {
            return JSON_COLUMN.readValue(json, type);
        } catch (JsonProcessingException e) {
            logger
                    .warn("Discovery item {} has an unreadable {}; listing it without one", itemUuid,
                            type.getSimpleName(), e);
            return null;
        }
    }

    /** Drops the identity column, which orders the log but is not published. */
    public static DiscoveryMessageDto toMessageDto(DiscoveryMessage message) {
        return new DiscoveryMessageDto(message.getSeverity(), message.getCode(), message.getMessage(),
                message.getOccurrences(), message.getFirstSeenAt(), message.getLastSeenAt());
    }
}
