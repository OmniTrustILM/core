package com.otilm.core.integration.dao.repository;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeOperation;
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
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;
import static com.otilm.core.util.builders.DataAttributeV3Builder.aDataAttribute;
import static org.assertj.core.api.Assertions.assertThat;

class AttributeContent2ObjectDeleteITest extends BaseSpringBootTest {

    private static final String OPERATION = AttributeOperation.SIGN;
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
    void sendsOneDeleteWithoutJoinEmulation_whenAnOperationDeleteRuns(MappingDelete delete) throws Exception {
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
    void reachesTheRowsThroughTheObjectIndex_whenAnOperationDeleteRuns(MappingDelete delete) throws Exception {
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
        SeededMappings unversioned = seedMappingsVaryingOneColumnEach(null);
        SeededMappings versioned = seedMappingsVaryingOneColumnEach(1);

        // when
        inTransaction(() -> mappingRepository
                .deleteOperationObjectAttributesUnversioned(AttributeType.DATA, null, null, null, Resource.CERTIFICATE,
                        objectUuid, null, null));

        // then
        assertThat(findRemainingMappings())
                .containsExactlyInAnyOrderElementsOf(allExcept(unversioned.allNull(), unversioned, versioned));
    }

    @Test
    void deletesOnlyTheRowWithNullColumns_whenVersionedDeleteGetsNullArguments() {
        // given
        SeededMappings unversioned = seedMappingsVaryingOneColumnEach(null);
        SeededMappings versioned = seedMappingsVaryingOneColumnEach(1);

        // when
        inTransaction(() -> mappingRepository
                .deleteOperationObjectAttributesByVersion(AttributeType.DATA, null, null, null, Resource.CERTIFICATE,
                        objectUuid, 1, null, null));

        // then
        assertThat(findRemainingMappings())
                .containsExactlyInAnyOrderElementsOf(allExcept(versioned.allNull(), unversioned, versioned));
    }

    @Test
    void deletesNothing_whenWideVersionedDeleteGetsNullOperation() {
        // given
        SeededMappings unversioned = seedMappingsVaryingOneColumnEach(null);
        SeededMappings versioned = seedMappingsVaryingOneColumnEach(1);

        // when
        inTransaction(() -> mappingRepository
                .deleteAllOperationAttributesByVersion(AttributeType.DATA, null, null, Resource.CERTIFICATE, objectUuid,
                        1));

        // then
        assertThat(findRemainingMappings())
                .containsExactlyInAnyOrderElementsOf(allExcept(null, unversioned, versioned));
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

    /**
     * One row whose nullable filter columns are all {@code NULL}, one for each such column set to a value, and one that
     * differs only in being a custom attribute, all at the given object version.
     */
    private SeededMappings seedMappingsVaryingOneColumnEach(Integer version) {
        AttributeDefinition dataWithoutOperation = saveDataDefinition(null);
        AttributeDefinition dataWithOperation = saveDataDefinition(OPERATION);
        AttributeDefinition custom = saveCustomDefinition();
        UUID connectorUuid = connectorRepository
                .save(aConnector().withGeneratedUuid().withUrl("http://" + UUID.randomUUID() + ".test").build())
                .getUuid();

        UUID allNull = saveMapping(dataWithoutOperation, version);
        UUID withOperation = saveMapping(dataWithOperation, version);
        UUID withPurpose = saveMapping(dataWithoutOperation, version, mapping -> mapping.setPurpose("purpose"));
        UUID withConnector = saveMapping(dataWithoutOperation, version,
                mapping -> mapping.setConnectorUuid(connectorUuid));
        UUID withSource = saveMapping(dataWithoutOperation, version, mapping -> {
            mapping.setSourceObjectType(Resource.DISCOVERY);
            mapping.setSourceObjectUuid(UUID.randomUUID());
        });
        UUID ofCustomAttribute = saveMapping(custom, version);
        return new SeededMappings(allNull, withOperation, withPurpose, withConnector, withSource, ofCustomAttribute);
    }

    private AttributeDefinition saveDataDefinition(String operation) {
        UUID attributeUuid = UUID.randomUUID();
        BaseAttribute attribute = aDataAttribute().withUuid(attributeUuid).withName("data-" + attributeUuid).build();
        return saveDefinition(AttributeType.DATA, attribute, operation);
    }

    private AttributeDefinition saveCustomDefinition() {
        UUID attributeUuid = UUID.randomUUID();
        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(attributeUuid.toString());
        attribute.setName("custom-" + attributeUuid);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(AttributeContentType.STRING);
        return saveDefinition(AttributeType.CUSTOM, attribute, null);
    }

    private AttributeDefinition saveDefinition(AttributeType type, BaseAttribute attribute, String operation) {
        AttributeDefinition definition = new AttributeDefinition();
        definition.setName(attribute.getName());
        definition.setAttributeUuid(UUID.fromString(attribute.getUuid()));
        definition.setLabel(attribute.getName());
        definition.setType(type);
        definition.setContentType(AttributeContentType.STRING);
        definition.setDefinition(attribute);
        definition.setOperation(operation);
        return definitionRepository.save(definition);
    }

    private UUID saveMapping(AttributeDefinition definition, Integer version) {
        return saveMapping(definition, version, mapping -> {
        });
    }

    private UUID saveMapping(AttributeDefinition definition, Integer version,
            Consumer<AttributeContent2Object> variation) {
        AttributeContentItem item = new AttributeContentItem();
        item.setAttributeDefinitionUuid(definition.getUuid());
        item.setJson(new StringAttributeContentV3(UUID.randomUUID().toString()));
        itemRepository.save(item);

        AttributeContent2Object mapping = new AttributeContent2Object();
        mapping.setAttributeContentItemUuid(item.getUuid());
        mapping.setObjectType(Resource.CERTIFICATE);
        mapping.setObjectUuid(objectUuid);
        mapping.setObjectVersion(version);
        variation.accept(mapping);
        return mappingRepository.save(mapping).getUuid();
    }

    /** Every test starts from an empty database, so the rows left in the table are the object's. */
    private List<UUID> findRemainingMappings() {
        return mappingRepository.findAll().stream().map(AttributeContent2Object::getUuid).toList();
    }

    private static List<UUID> allExcept(UUID deleted, SeededMappings... seeded) {
        return Stream
                .of(seeded)
                .flatMap(mappings -> mappings.all().stream())
                .filter(uuid -> !Objects.equals(uuid, deleted))
                .toList();
    }

    private record SeededMappings(UUID allNull, UUID withOperation, UUID withPurpose, UUID withConnector,
            UUID withSource, UUID ofCustomAttribute) {

        List<UUID> all() {
            return List.of(allNull, withOperation, withPurpose, withConnector, withSource, ofCustomAttribute);
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
