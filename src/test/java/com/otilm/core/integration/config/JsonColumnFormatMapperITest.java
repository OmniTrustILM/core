package com.otilm.core.integration.config;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.converter.ObjectToJsonConverter;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryItem;
import com.otilm.core.dao.entity.ScheduledJob;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.ScheduledJobsRepository;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.type.format.FormatMapper;
import org.hibernate.type.format.jackson.JacksonJsonFormatMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proof that {@code JsonColumnFormatMapperConfig} reaches Hibernate and shapes what every
 * {@code @JdbcTypeCode(SqlTypes.JSON)} column stores. {@link DiscoveryItem} is the vehicle for the persisted-shape
 * case, {@link ScheduledJob} for the columns that a converter keeps out of the stated mapper's reach.
 */
@Transactional
class JsonColumnFormatMapperITest extends BaseSpringBootTest {

    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private DiscoveryItemRepository discoveryItemRepository;
    @PersistenceContext
    private EntityManager entityManager;
    @Autowired
    private JacksonJsonFormatMapper jsonColumnFormatMapper;
    @Autowired
    private ScheduledJobsRepository scheduledJobsRepository;

    @Autowired
    private CryptographicKeyRepository keyRepository;
    @Autowired
    private CryptographicKeyItemRepository keyItemRepository;

    @Test
    void keyMeta_roundTripsWithoutUuidReference() {
        // given
        String firstHandle = "hsm-key-123";
        String secondHandle = "partition-2";
        MetadataAttributeV3 keyId = keyMetadata("keyId", firstHandle);
        MetadataAttributeV3 partition = keyMetadata("partition", secondHandle);
        CryptographicKeyItem item = keyItem();
        item.setKeyMeta(List.of(keyId, partition));

        // when
        UUID itemUuid = keyItemRepository.saveAndFlush(item).getUuid();
        entityManager.clear();
        CryptographicKeyItem restored = keyItemRepository.findById(itemUuid).orElseThrow();

        // then
        assertThat(restored.getKeyReferenceUuid()).isNull();
        assertThat(restored.getKeyMeta()).extracting(MetadataAttribute::getName).containsExactly("keyId", "partition");
        assertThat(restored.getKeyMeta().getFirst()).isInstanceOf(MetadataAttributeV3.class);
        MetadataAttributeV3 restoredKeyId = (MetadataAttributeV3) restored.getKeyMeta().getFirst();
        MetadataAttributeV3 restoredPartition = (MetadataAttributeV3) restored.getKeyMeta().getLast();
        assertThat(restoredKeyId.getContent().getFirst().getData()).isEqualTo(firstHandle);
        assertThat(restoredPartition.getContent().getFirst().getData()).isEqualTo(secondHandle);
    }

    @Test
    void keyUuidReference_remainsSupportedWithoutMeta() {
        // given
        UUID referenceUuid = UUID.randomUUID();
        CryptographicKeyItem item = keyItem();
        item.setKeyReferenceUuid(referenceUuid);

        // when
        UUID itemUuid = keyItemRepository.saveAndFlush(item).getUuid();
        entityManager.clear();
        CryptographicKeyItem restored = keyItemRepository.findById(itemUuid).orElseThrow();

        // then
        assertThat(restored.getKeyReferenceUuid()).isEqualTo(referenceUuid);
        assertThat(restored.getKeyMeta()).isNull();
    }

    @Test
    void keyReferences_areBothOptional() {
        // given
        CryptographicKeyItem item = keyItem();

        // when
        UUID itemUuid = keyItemRepository.saveAndFlush(item).getUuid();
        entityManager.clear();
        CryptographicKeyItem restored = keyItemRepository.findById(itemUuid).orElseThrow();

        // then
        assertThat(restored.getKeyReferenceUuid()).isNull();
        assertThat(restored.getKeyMeta()).isNull();
    }

    private CryptographicKeyItem keyItem() {
        CryptographicKey key = aCryptographicKey().withName("metadata-key").build();
        keyRepository.save(key);
        CryptographicKeyItem item = aKeyItem()
                .withName("metadata-key private key")
                .withType(KeyType.PRIVATE_KEY)
                .withState(KeyState.ACTIVE)
                .build();
        item.setKey(key);
        return item;
    }

    private static MetadataAttributeV3 keyMetadata(String name, String value) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        StringAttributeContentV3 content = new StringAttributeContentV3(value);
        attribute.setContent(List.of(content));
        return attribute;
    }

    /**
     * Hibernate must use the stated mapper. The stored bytes cannot show this on their own, because a fallback mapper
     * writes the same output for the payload this test stores.
     */
    @Test
    void hibernateUsesTheStatedJsonFormatMapper() {
        FormatMapper active = entityManager
                .getEntityManagerFactory()
                .unwrap(SessionFactoryImplementor.class)
                .getSessionFactoryOptions()
                .getJsonFormatMapper();

        assertThat(active).isSameAs(jsonColumnFormatMapper);
    }

    /**
     * Pins the persisted shape: a null map value reaches the column. The payload is a plain {@code Map} because
     * inclusion declared on a DTO outranks the mapper.
     */
    @Test
    void jsonColumnsKeepNullMembers() {
        Map<String, Object> payloadWithUnsetMember = new HashMap<>();
        payloadWithUnsetMember.put("connectorRunId", "run-42");
        payloadWithUnsetMember.put("connectorBuild", null);

        Discovery run = new Discovery();
        run.setName("mapper-proof");
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorUuid(UUID.randomUUID());
        run.setConnectorName("network-discovery");
        UUID runUuid = discoveryRepository.saveAndFlush(run).getUuid();

        DiscoveryItem item = new DiscoveryItem();
        item.setDiscoveryUuid(runUuid);
        item.setResource(Resource.CRYPTOGRAPHIC_KEY);
        item.setSequence(1L);
        item.setUniqueRef("mapper-proof-item");
        item.setPayload(payloadWithUnsetMember);
        UUID itemUuid = discoveryItemRepository.saveAndFlush(item).getUuid();
        entityManager.clear();

        String storedJson = (String) entityManager
                .createNativeQuery("SELECT payload::text FROM discovery_item WHERE uuid = :uuid")
                .setParameter("uuid", itemUuid)
                .getSingleResult();

        assertThat(storedJson)
                .describedAs("the null member must reach the column, which is what Jackson's default inclusion does")
                .contains("\"connectorBuild\": null")
                .contains("\"connectorRunId\": \"run-42\"");
    }

    /**
     * Marks the boundary of what the stated mapper governs. A column carrying {@link ObjectToJsonConverter} alongside
     * {@code @JdbcTypeCode(SqlTypes.JSON)} is serialized by the converter's wire mapper instead: Hibernate resolves the
     * JPA converter, which makes the relational type {@code String}, and a {@code String} reaches the driver verbatim.
     * The wire mapper's {@code NON_NULL} is therefore visible here and nowhere else in this class.
     */
    @Test
    void convertedColumnsAreSerializedByTheConverterNotTheStatedMapper() {
        Map<String, Object> payloadWithUnsetMember = new HashMap<>();
        payloadWithUnsetMember.put("resourceUuid", "run-42");
        payloadWithUnsetMember.put("cancelledAt", null);

        ScheduledJob job = new ScheduledJob();
        job.setJobName("mapper-proof-" + UUID.randomUUID());
        job.setJobClassName("com.otilm.core.tasks.DiscoveryCertificateTask");
        job.setCronExpression("0 0 * * * *");
        job.setObjectData(payloadWithUnsetMember);
        UUID jobUuid = scheduledJobsRepository.saveAndFlush(job).getUuid();
        entityManager.clear();

        String storedJson = (String) entityManager
                .createNativeQuery("SELECT object_data::text FROM scheduled_job WHERE uuid = :uuid")
                .setParameter("uuid", jobUuid)
                .getSingleResult();

        assertThat(storedJson)
                .describedAs(
                        "the converter's wire mapper omits nulls, so this column does not follow the stated mapper")
                .contains("\"resourceUuid\": \"run-42\"")
                .doesNotContain("cancelledAt");
    }
}
