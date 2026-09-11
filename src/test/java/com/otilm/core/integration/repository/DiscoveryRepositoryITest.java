package com.otilm.core.integration.repository;

import com.otilm.api.model.connector.discovery.v2.DiscoveryProgressDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResourceProgressDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryRunMetaFixture;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Schema proof for the discovery v2 run columns. The critical case is {@code DiscoveryProgressDto#byResource}, the
 * first enum-keyed map persisted under {@code @JdbcTypeCode(SqlTypes.JSON)} in any core entity: {@link Resource} keys
 * serialize by wire code via {@code @JsonValue}, and enum-as-map-key handling through Hibernate's Jackson mapper is
 * exactly the kind of mapping that only fails at read time.
 */
@Transactional
class DiscoveryRepositoryITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryRepository discoveryRepository;
    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void v2RunColumnsRoundTrip() {
        DiscoveryResourceProgressDto keyProgress = new DiscoveryResourceProgressDto();
        keyProgress.setProduced(3L);
        DiscoveryProgressDto progress = new DiscoveryProgressDto();
        progress.setTargetsProcessed(11L);
        progress.setTargetsTotal(40L);
        progress.setPhase("scanning");
        progress.setByResource(Map.of(Resource.CRYPTOGRAPHIC_KEY, keyProgress));

        Discovery run = new Discovery();
        run.setName("nightly-scan");
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        UUID interfaceUuid = UUID.randomUUID();
        OffsetDateTime stoppedAt = OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);
        run.setConnectorInterfaceUuid(interfaceUuid);
        run.setRunMeta(DiscoveryRunMetaFixture.runMeta("connectorRunId", "run-42"));
        run.setResources(List.of(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY));
        run.setLastAppliedSequence(17L);
        run.setProgress(progress);
        run.setStoppedAt(stoppedAt);
        run.setConnectorState("running");
        run.setStoppable(true);
        UUID runUuid = discoveryRepository.saveAndFlush(run).getUuid();
        // Without the clear, findById answers from the persistence context and the jsonb columns are never read.
        entityManager.clear();

        Discovery back = discoveryRepository.findById(runUuid).orElseThrow();
        assertThat(back.getConnectorInterfaceUuid()).isEqualTo(interfaceUuid);
        assertThat(back.getRunMeta())
                .as("the connector handle round-trips through jsonb as the concrete attribute class")
                .singleElement()
                .satisfies(handle -> assertThat(handle.getName()).isEqualTo("connectorRunId"));
        assertThat(back.getResources()).containsExactly(Resource.CERTIFICATE, Resource.CRYPTOGRAPHIC_KEY);
        assertThat(back.getLastAppliedSequence()).isEqualTo(17L);
        assertThat(back.getProgress().getTargetsProcessed()).isEqualTo(11L);
        assertThat(back.getProgress().getTargetsTotal()).isEqualTo(40L);
        assertThat(back.getProgress().getPhase()).isEqualTo("scanning");
        assertThat(back.getProgress().getByResource()).containsOnlyKeys(Resource.CRYPTOGRAPHIC_KEY);
        assertThat(back.getProgress().getByResource().get(Resource.CRYPTOGRAPHIC_KEY).getProduced()).isEqualTo(3L);
        assertThat(back.getConnectorState()).isEqualTo("running");
        assertThat(back.getStoppable()).isTrue();
        // Compared as instants: the driver may hand the timestamptz back under a different zone offset.
        assertThat(back.getStoppedAt().toInstant()).isEqualTo(stoppedAt.toInstant());
    }
}
