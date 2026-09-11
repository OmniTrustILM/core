package com.otilm.core.mapper.discovery;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.client.discovery.DiscoveryListDto;
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
import com.otilm.core.util.AttributeDefinitionUtils;
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
     * Counts a detail response carries that the run row does not hold — each lives in a table of its own. Passed as a
     * record rather than two bare longs: both are counts of the same type, and a swapped pair would still compile.
     *
     * @param runMessages kinds of problem the run collected, as the message listing would count them
     * @param newlyDiscoveredItems staged items that were not already in the inventory, counted per item
     */
    public record DetailCounts(long runMessages, long newlyDiscoveredItems) {
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
        // Counted rather than carried: a client polls this detail while a run is live, and both tables are read
        // from their own endpoints. Message kinds, not occurrences -- the count is what the listing would return.
        dto.setRunMessageCount(counts.runMessages());
        dto.setItemsNewlyDiscovered(counts.newlyDiscoveredItems());
        // Both are REQUIRED on the wire, and a v1 run stores neither: it targets certificates by definition and
        // cannot be stopped at all, so the synthesis below is exact rather than a default.
        dto
                .setResources(discovery.getResources() == null || discovery.getResources().isEmpty()
                        ? List.of(Resource.CERTIFICATE)
                        : List.copyOf(discovery.getResources()));
        dto.setStoppable(Boolean.TRUE.equals(discovery.getStoppable()));
        // Omitted rather than defaulted when absent: null is what a v1 run, and a connector that reports no
        // progress at all, are meant to publish.
        dto.setProgress(discovery.getProgress());
        dto.setConnectorInterface(connectorInterfaceOf(discovery));
        // The drain cursor is the count: sequences are dense per run, so the highest one applied is how many items
        // Core holds -- and it is what the items listing returns, which a larger connector-side total would not be.
        dto
                .setItemsDiscovered(
                        discovery.getConnectorInterfaceUuid() == null ? null : discovery.getLastAppliedSequence());
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
        return dto;
    }

    /**
     * Which interface drives the run, and so which generation. Null for a v1 run, which is how a client tells the two
     * apart without inferring it from behaviour.
     */
    private static ConnectorInterfaceDto connectorInterfaceOf(Discovery discovery) {
        return discovery.getConnectorInterface() == null ? null : discovery.getConnectorInterface().mapToDto();
    }

    /**
     * A staged item, from whichever store holds it. {@code payload} and {@code meta} arrive as JSON text because the
     * certificate branch builds its payload at read time from the deduplicated content rather than from a column.
     */
    public static DiscoveryItemDto toItemDto(DiscoveryItemRow row) {
        DiscoveryItemDto dto = new DiscoveryItemDto();
        dto.setUuid(row.getUuid().toString());
        dto.setInventoryUuid(row.getInventoryUuid() == null ? null : row.getInventoryUuid().toString());
        dto.setSequence(row.getSequence());
        dto.setUniqueRef(row.getUniqueRef());
        dto.setDiscoveredAt(row.getDiscoveredAt() == null ? null : row.getDiscoveredAt().atOffset(ZoneOffset.UTC));
        dto.setPayload(read(row.getUuid(), row.getPayload(), DiscoveredItemPayloadDto.class));
        dto.setNewlyDiscovered(row.isNewlyDiscovered());
        dto.setProcessed(row.isProcessed());
        dto.setProcessedError(row.getProcessedError());
        dto
                .setMeta(row.getMeta() == null
                        ? null
                        : AttributeDefinitionUtils.deserialize(row.getMeta(), MetadataAttribute.class));
        return dto;
    }

    /**
     * Staging is deliberately permissive, so a payload can carry a resource this build has no type for. That is
     * answered per row rather than by failing the page: one unreadable item would otherwise 500 the whole listing,
     * permanently, for a run whose other items are perfectly readable.
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

    /** The identity column stays behind: it orders the log, it is not published. */
    public static DiscoveryMessageDto toMessageDto(DiscoveryMessage message) {
        return new DiscoveryMessageDto(message.getSeverity(), message.getCode(), message.getMessage(),
                message.getOccurrences(), message.getFirstSeenAt(), message.getLastSeenAt());
    }
}
