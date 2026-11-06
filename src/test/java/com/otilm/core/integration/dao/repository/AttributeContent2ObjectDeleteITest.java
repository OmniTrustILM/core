package com.otilm.core.integration.dao.repository;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.AttributeContent2Object;
import com.otilm.core.dao.entity.AttributeContentItem;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository;
import com.otilm.core.dao.repository.AttributeContentItemRepository;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SqlCapture;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;
import static org.assertj.core.api.Assertions.assertThat;

class AttributeContent2ObjectDeleteITest extends BaseSpringBootTest {

    private static final String OPERATION = "SIGN";
    private static final Pattern JDBC_PARAMETER = Pattern.compile("\\?");

    @Autowired
    private AttributeContent2ObjectRepository mappingRepository;
    @Autowired
    private AttributeContentItemRepository itemRepository;
    @Autowired
    private AttributeDefinitionRepository definitionRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private DataSource dataSource;

    private UUID objectUuid;

    @BeforeEach
    void pickObject() {
        objectUuid = UUID.randomUUID();
    }

    @ParameterizedTest
    @EnumSource(MappingDelete.class)
    void sendsOnePlainDelete_withoutJoinEmulation(MappingDelete delete) throws Exception {
        // given — no mapping rows

        // when
        List<String> statements = captureStatements(delete);

        // then
        assertThat(statements)
                .singleElement()
                .satisfies(sql -> assertThat(sql)
                        .startsWith("delete from core.attribute_content_2_object")
                        .doesNotContain("values(0)"));
    }

    @ParameterizedTest
    @EnumSource(MappingDelete.class)
    void reachesTheRowsThroughTheObjectIndex(MappingDelete delete) throws Exception {
        // given
        String deleteSql = captureStatements(delete).getFirst();

        // when
        String plan = explainGenericPlan(deleteSql);

        // then
        assertThat(plan).contains("idx_aco_type_uuid_version").doesNotContain("SubPlan");
    }

    @Test
    void deletesOnlyTheRowWithNullColumns_whenUnversionedDeleteGetsNullArguments() {
        // given
        SeededMappings seeded = seedMappingsVaryingOneColumnEach();

        // when
        inTransaction(() -> mappingRepository
                .deleteOperationObjectAttributesUnversioned(AttributeType.DATA, null, null, null, Resource.CERTIFICATE,
                        objectUuid, null, null));

        // then
        assertThat(remainingMappings())
                .containsExactlyInAnyOrder(seeded.withOperation(), seeded.withPurpose(), seeded.withConnector(),
                        seeded.withSource(), seeded.versioned());
    }

    @Test
    void deletesOnlyTheRowWithNullColumns_whenVersionedDeleteGetsNullArguments() {
        // given
        SeededMappings seeded = seedMappingsVaryingOneColumnEach();

        // when
        inTransaction(() -> mappingRepository
                .deleteOperationObjectAttributesByVersion(AttributeType.DATA, null, null, null, Resource.CERTIFICATE,
                        objectUuid, 1, null, null));

        // then
        assertThat(remainingMappings())
                .containsExactlyInAnyOrder(seeded.allNull(), seeded.withOperation(), seeded.withPurpose(),
                        seeded.withConnector(), seeded.withSource());
    }

    @Test
    void deletesNothing_whenWideVersionedDeleteGetsNullOperation() {
        // given
        SeededMappings seeded = seedMappingsVaryingOneColumnEach();

        // when
        inTransaction(() -> mappingRepository
                .deleteAllOperationAttributesByVersion(AttributeType.DATA, null, null, Resource.CERTIFICATE, objectUuid,
                        1));

        // then
        assertThat(remainingMappings()).containsExactlyInAnyOrderElementsOf(seeded.all());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private List<String> captureStatements(MappingDelete delete) throws Exception {
        return SqlCapture.during(() -> inTransaction(() -> delete.run(mappingRepository, objectUuid))).statements();
    }

    private Long inTransaction(Supplier<Long> delete) {
        return new TransactionTemplate(transactionManager).execute(status -> delete.get());
    }

    /**
     * The plan PostgreSQL keeps for the statement once it is cached, which no bound value can steer towards an index.
     * Each JDBC placeholder becomes its own parameter, as it is on the wire; an occurrence that is only tested for
     * {@code NULL} gets a type, which PostgreSQL cannot infer from {@code IS NULL}. Sequential scans are priced out so
     * the plan shows whether an index path exists at all on the near-empty test table.
     */
    private String explainGenericPlan(String sql) throws SQLException {
        AtomicInteger parameters = new AtomicInteger();
        String numbered = JDBC_PARAMETER
                .matcher(sql)
                .replaceAll(match -> Matcher.quoteReplacement("$" + parameters.incrementAndGet()));
        String typed = numbered.replaceAll("(\\$\\d+) is null", "$1::text is null");
        String nullArguments = String.join(", ", Collections.nCopies(parameters.get(), "NULL"));

        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            connection.setAutoCommit(false);
            try {
                statement.execute("SET LOCAL plan_cache_mode = force_generic_plan");
                statement.execute("SET LOCAL enable_seqscan = off");
                statement.execute("PREPARE aco_delete AS " + typed);
                StringBuilder plan = new StringBuilder();
                try (ResultSet rows = statement.executeQuery("EXPLAIN EXECUTE aco_delete(" + nullArguments + ")")) {
                    while (rows.next()) {
                        plan.append(rows.getString(1)).append('\n');
                    }
                }
                return plan.toString();
            } finally {
                connection.rollback();
                connection.setAutoCommit(true);
                deallocateQuietly(statement);
            }
        }
    }

    private static void deallocateQuietly(Statement statement) {
        try {
            statement.execute("DEALLOCATE aco_delete");
        } catch (SQLException notPrepared) {
            // the PREPARE itself failed, so there is nothing to release
        }
    }

    private SeededMappings seedMappingsVaryingOneColumnEach() {
        AttributeDefinition definitionWithoutOperation = saveDataDefinition(null);
        AttributeDefinition definitionWithOperation = saveDataDefinition(OPERATION);
        UUID connectorUuid = connectorRepository.save(aConnector().withGeneratedUuid().build()).getUuid();

        UUID allNull = saveMapping(definitionWithoutOperation);
        UUID withOperation = saveMapping(definitionWithOperation);
        UUID withPurpose = saveMapping(definitionWithoutOperation, mapping -> mapping.setPurpose("purpose"));
        UUID withConnector = saveMapping(definitionWithoutOperation,
                mapping -> mapping.setConnectorUuid(connectorUuid));
        UUID withSource = saveMapping(definitionWithoutOperation, mapping -> {
            mapping.setSourceObjectType(Resource.DISCOVERY);
            mapping.setSourceObjectUuid(UUID.randomUUID());
        });
        UUID versioned = saveMapping(definitionWithoutOperation, mapping -> mapping.setObjectVersion(1));
        return new SeededMappings(allNull, withOperation, withPurpose, withConnector, withSource, versioned);
    }

    private AttributeDefinition saveDataDefinition(String operation) {
        UUID attributeUuid = UUID.randomUUID();
        String name = "mappingDelete-" + attributeUuid;
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid(attributeUuid.toString());
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);

        AttributeDefinition definition = new AttributeDefinition();
        definition.setName(name);
        definition.setAttributeUuid(attributeUuid);
        definition.setLabel(name);
        definition.setType(AttributeType.DATA);
        definition.setContentType(AttributeContentType.STRING);
        definition.setDefinition(attribute);
        definition.setOperation(operation);
        return definitionRepository.save(definition);
    }

    private UUID saveMapping(AttributeDefinition definition) {
        return saveMapping(definition, mapping -> {
        });
    }

    private UUID saveMapping(AttributeDefinition definition, Consumer<AttributeContent2Object> variation) {
        AttributeContentItem item = new AttributeContentItem();
        item.setAttributeDefinitionUuid(definition.getUuid());
        item.setJson(new StringAttributeContentV3(UUID.randomUUID().toString()));
        itemRepository.save(item);

        AttributeContent2Object mapping = new AttributeContent2Object();
        mapping.setAttributeContentItemUuid(item.getUuid());
        mapping.setObjectType(Resource.CERTIFICATE);
        mapping.setObjectUuid(objectUuid);
        variation.accept(mapping);
        return mappingRepository.save(mapping).getUuid();
    }

    private List<UUID> remainingMappings() {
        return mappingRepository
                .findByObjectTypeAndObjectUuid(Resource.CERTIFICATE, objectUuid)
                .stream()
                .map(AttributeContent2Object::getUuid)
                .toList();
    }

    private record SeededMappings(UUID allNull, UUID withOperation, UUID withPurpose, UUID withConnector,
            UUID withSource, UUID versioned) {

        List<UUID> all() {
            return List.of(allNull, withOperation, withPurpose, withConnector, withSource, versioned);
        }
    }

    private enum MappingDelete {
        VERSIONED {
            @Override
            Long run(AttributeContent2ObjectRepository repository, UUID objectUuid) {
                return repository
                        .deleteOperationObjectAttributesByVersion(AttributeType.DATA, OPERATION, null, null,
                                Resource.CERTIFICATE, objectUuid, 1, null, null);
            }
        },
        WIDE_VERSIONED {
            @Override
            Long run(AttributeContent2ObjectRepository repository, UUID objectUuid) {
                return repository
                        .deleteAllOperationAttributesByVersion(AttributeType.DATA, OPERATION, null,
                                Resource.CERTIFICATE, objectUuid, 1);
            }
        },
        UNVERSIONED {
            @Override
            Long run(AttributeContent2ObjectRepository repository, UUID objectUuid) {
                return repository
                        .deleteOperationObjectAttributesUnversioned(AttributeType.DATA, OPERATION, null, null,
                                Resource.CERTIFICATE, objectUuid, null, null);
            }
        };

        abstract Long run(AttributeContent2ObjectRepository repository, UUID objectUuid);
    }
}
