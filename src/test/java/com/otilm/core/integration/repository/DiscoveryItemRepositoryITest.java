package com.otilm.core.integration.repository;

import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Schema proof for the resource-agnostic staging table: the jsonb payload and meta survive a round trip, the
 * {@code (discovery, resource, unique_ref)} dedupe constraint holds, and deleting a run cascades its staged items away
 * at the database level.
 */
@Transactional
class DiscoveryItemRepositoryITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryItemRepository itemRepository;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void stagedItemRoundTripsPayloadAndMeta() {
        UUID runUuid = aRun();
        MetadataAttributeV3 where = new MetadataAttributeV3();
        where.setName("discoverySource");
        // The attribute serializer reads contentType.getCode() unconditionally; a name-only fixture NPEs.
        where.setContentType(AttributeContentType.STRING);

        DiscoveryItem item = new DiscoveryItem();
        item.setDiscoveryUuid(runUuid);
        item.setResource(Resource.CRYPTOGRAPHIC_KEY);
        item.setSequence(1L);
        item.setUniqueRef("2b:9c:aa");
        item.setPayload(Map.of("resource", "keys", "fingerprint", "2b:9c:aa"));
        item.setDiscoveredAt(OffsetDateTime.of(2026, 8, 14, 10, 0, 0, 0, ZoneOffset.UTC));
        item.setNewlyDiscovered(true);
        item.setMeta(List.of(where));
        UUID itemUuid = itemRepository.saveAndFlush(item).getUuid();
        // Without the clear, findById answers from the persistence context and the jsonb columns are never read.
        entityManager.clear();

        DiscoveryItem back = itemRepository.findById(itemUuid).orElseThrow();
        assertThat(back.getPayload()).containsEntry("fingerprint", "2b:9c:aa");
        assertThat(back.getMeta())
                .extracting(m -> ((MetadataAttributeV3) m).getName())
                .containsExactly("discoverySource");
        assertThat(back.isNewlyDiscovered()).isTrue();
        assertThat(back.getProcessedAt()).isNull();
        assertThat(back.getInventoryUuid()).isNull();
    }

    @Test
    void duplicateUniqueRefWithinRunAndResourceIsRejected() {
        UUID runUuid = aRun();
        itemRepository.saveAndFlush(item(runUuid, 1L, "10.0.0.7:443"));
        DiscoveryItem duplicate = item(runUuid, 2L, "10.0.0.7:443");

        assertThatThrownBy(() -> itemRepository.saveAndFlush(duplicate))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void deletingTheRunCascadesItsStagedItems() {
        UUID runUuid = aRun();
        itemRepository.saveAndFlush(item(runUuid, 1L, "10.0.0.7:443"));
        itemRepository.saveAndFlush(item(runUuid, 2L, "10.0.0.8:443"));
        assertThat(itemRepository.count()).isEqualTo(2);

        discoveryRepository.deleteById(runUuid);
        discoveryRepository.flush();

        assertThat(itemRepository.count()).isZero();
    }

    private DiscoveryItem item(UUID runUuid, long sequence, String uniqueRef) {
        DiscoveryItem item = new DiscoveryItem();
        item.setDiscoveryUuid(runUuid);
        item.setResource(Resource.CERTIFICATE);
        item.setSequence(sequence);
        item.setUniqueRef(uniqueRef);
        item.setPayload(Map.of("resource", "certificates"));
        item.setNewlyDiscovered(false);
        return item;
    }

    private UUID aRun() {
        Discovery run = new Discovery();
        run.setName("nightly-scan");
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        return discoveryRepository.saveAndFlush(run).getUuid();
    }
}
