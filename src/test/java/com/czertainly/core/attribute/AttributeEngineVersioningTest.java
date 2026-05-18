package com.czertainly.core.attribute;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.RequestAttributeV3;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttributeV3;
import com.czertainly.api.model.client.metadata.MetadataResponseDto;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.czertainly.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.czertainly.api.model.common.attribute.v3.DataAttributeV3;
import com.czertainly.api.model.common.attribute.v3.MetadataAttributeV3;
import com.czertainly.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.czertainly.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.repository.AttributeContent2ObjectRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.UUID;

/**
 * Integration tests for versioned attribute content.
 *
 * <p>Core invariants tested:
 * <ul>
 *   <li>Backward compatibility: unversioned (null) writes/reads still work.</li>
 *   <li>Version isolation: v1 and v2 rows are independent.</li>
 *   <li>Deduplication is scoped per version (the same content item may appear for different versions).</li>
 *   <li>Delete is version-scoped: removing v1 leaves v2 intact.</li>
 *   <li>deleteObjectAttributesContent removes all versions at once.</li>
 *   <li>Unversioned and versioned rows for the same logical object don't bleed into each other.</li>
 * </ul>
 */
class AttributeEngineVersioningTest extends BaseSpringBootTest {

    // ── Operation constants mimicking signing-profile usage ──────────────────
    private static final String OPERATION_SIGN = AttributeOperation.SIGN;
    private static final String OPERATION_FORMAT = "connectorFormatter";
    private static final Resource VERSIONED_RESOURCE = Resource.CRYPTOGRAPHIC_KEY;
    private static final List<RequestAttribute> EMPTY_REQUEST_ATTRIBUTES = List.of();

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private AttributeContent2ObjectRepository attributeContent2ObjectRepository;

    private Connector connector;


    @BeforeEach
    void setUp() {
        connector = new Connector();
        connector.setName("SigningConnector_" + UUID.randomUUID());
        connector.setUrl("http://localhost:9999");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);
    }

    // ── Helper builders ──────────────────────────────────────────────────────

    private DataAttributeV3 buildDataAttribute(String name) {
        DataAttributeV3 attr = new DataAttributeV3();
        attr.setUuid(UUID.randomUUID().toString());
        attr.setName(name);
        attr.setType(AttributeType.DATA);
        attr.setContentType(AttributeContentType.STRING);
        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel(name);
        attr.setProperties(props);
        return attr;
    }

    private RequestAttributeV3 buildRequest(DataAttributeV3 definition, String value) {
        RequestAttributeV3 req = new RequestAttributeV3();
        req.setUuid(UUID.fromString(definition.getUuid()));
        req.setName(definition.getName());
        req.setContent(List.of(new StringAttributeContentV3(value)));
        return req;
    }

    /**
     * Extracts the String data from the first content item of the first
     * attribute in a ResponseAttribute list.
     * Assumes the list has exactly one V3 attribute with exactly one STRING item.
     */
    private String firstStringValue(List<ResponseAttribute> attrs) {
        Assertions.assertFalse(attrs.isEmpty(), "ResponseAttribute list must not be empty");
        ResponseAttributeV3 v3 = (ResponseAttributeV3) attrs.getFirst();
        List<BaseAttributeContentV3<?>> items = v3.getContent();
        Assertions.assertFalse(items.isEmpty(), "Content list must not be empty");
        return items.getFirst().getData().toString();
    }

    /**
     * Returns the number of content items of the first attribute in the list.
     * Assumes the list has at least one V3 attribute.
     */
    private int firstContentSize(List<ResponseAttribute> attrs) {
        ResponseAttributeV3 v3 = (ResponseAttributeV3) attrs.getFirst();
        return v3.getContent().size();
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    /**
     * Verify that ObjectAttributeContentInfo constructed with the existing
     * convenience constructors always produces objectVersion() == null,
     * and the two new version-carrying constructors produce the expected value.
     */
    @Test
    void testObjectAttributeContentInfoVersionConstructors() {
        UUID conn = UUID.randomUUID();
        UUID obj = UUID.randomUUID();

        // All legacy constructors → null version
        Assertions.assertNull(ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, obj).build().objectVersion());
        Assertions.assertNull(ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, obj).connector(conn).build().objectVersion());
        Assertions.assertNull(ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, obj).connector(conn).purpose("purpose").build().objectVersion());
        Assertions.assertNull(ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, obj).connector(conn).source(Resource.CERTIFICATE, UUID.randomUUID()).build().objectVersion());

        // New constructors → carry version
        ObjectAttributeContentInfo v1Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, obj).connector(conn).version(1).build();
        Assertions.assertEquals(1, v1Info.objectVersion());
        Assertions.assertEquals(conn, v1Info.connectorUuid());
        Assertions.assertEquals(VERSIONED_RESOURCE, v1Info.objectType());
        Assertions.assertEquals(obj, v1Info.objectUuid());

        ObjectAttributeContentInfo v2WithPurpose = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, obj).connector(conn).purpose("myPurpose").version(2).build();
        Assertions.assertEquals(2, v2WithPurpose.objectVersion());
        Assertions.assertEquals("myPurpose", v2WithPurpose.purpose());
    }

    /**
     * Backward-compatibility: writing and reading attribute content WITHOUT an
     * objectVersion (null) must behave exactly as before the feature was added.
     */
    @Test
    void testUnversionedReadWriteStillWorks() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("unversioned_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        // unversioned write — no objectVersion argument
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).build(),
                List.of(buildRequest(def, "unversionedValue")));

        // read back with the unversioned overload
        var content = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).build());
        Assertions.assertEquals(1, content.size());
        Assertions.assertEquals("unversioned_attr", content.getFirst().getName());
        Assertions.assertEquals("unversionedValue", firstStringValue(content));
    }

    /**
     * Core isolation test: writing attributes for v1 and v2 of the same object
     * must produce independent rows.  Reading v1 must not return v2 values and
     * vice versa.
     */
    @Test
    void testVersionIsolation() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("versioned_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        // Write v1 and v2 with distinct values
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "value_v1")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build(),
                List.of(buildRequest(def, "value_v2")));

        var v1Content = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build());
        Assertions.assertEquals(1, v1Content.size(), "v1 read must return exactly one attribute");
        Assertions.assertEquals(1, firstContentSize(v1Content), "v1 must have one content item");
        Assertions.assertEquals("value_v1", firstStringValue(v1Content));

        var v2Content = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build());
        Assertions.assertEquals(1, v2Content.size(), "v2 read must return exactly one attribute");
        Assertions.assertEquals(1, firstContentSize(v2Content), "v2 must have one content item");
        Assertions.assertEquals("value_v2", firstStringValue(v2Content));
    }

    /**
     * Updating v1 in place (re-writing) must not affect v2.
     */
    @Test
    void testInPlaceUpdateOfV1DoesNotAffectV2() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("update_test_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "v1_original")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build(),
                List.of(buildRequest(def, "v2_value")));

        // Overwrite v1 with a new value
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "v1_updated")));

        Assertions.assertEquals("v1_updated", firstStringValue(
                        attributeEngine.getObjectDataAttributesContent(
                                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build())),
                "v1 should show updated value");

        Assertions.assertEquals("v2_value", firstStringValue(
                        attributeEngine.getObjectDataAttributesContent(
                                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build())),
                "v2 should not be affected by v1 update");
    }

    /**
     * Deleting v1 attributes must leave v2 rows untouched.
     */
    @Test
    void testDeleteV1LeavesV2Intact() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("delete_v1_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "v1_value")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build(),
                List.of(buildRequest(def, "v2_value")));

        ObjectAttributeContentInfo v1Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build();
        attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, v1Info);

        var v1After = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build());
        Assertions.assertTrue(v1After.isEmpty(), "v1 content must have been deleted");

        var v2After = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build());
        Assertions.assertEquals(1, v2After.size(), "v2 content must survive v1 deletion");
        Assertions.assertEquals("v2_value", firstStringValue(v2After));
    }

    /**
     * deleteObjectAttributesContent must remove ALL versions for a given object.
     */
    @Test
    void testDeleteObjectAttributeContentRemovesAllVersions() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("delete_all_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        for (int v = 1; v <= 3; v++) {
            attributeEngine.updateObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(v).build(),
                    List.of(buildRequest(def, "value_v" + v)));
        }

        var allBefore = attributeContent2ObjectRepository.getAllObjectDataAttributesContent(
                VERSIONED_RESOURCE, objectUuid);
        Assertions.assertEquals(3, allBefore.size(), "should have 3 versioned rows before delete");

        // deleteObjectAttributesContent removes by objectType+objectUuid regardless of version
        ObjectAttributeContentInfo anyVersionInfo = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).build();
        attributeEngine.deleteObjectAttributesContent(AttributeType.DATA, anyVersionInfo);

        var allAfter = attributeContent2ObjectRepository.getAllObjectDataAttributesContent(
                VERSIONED_RESOURCE, objectUuid);
        Assertions.assertTrue(allAfter.isEmpty(),
                "all versioned rows must be gone after deleteObjectAttributesContent");
    }

    /**
     * Deduplication fix: the same attribute definition content can exist for v1
     * and v2 of the same object as separate, distinct mapping rows.
     */
    @Test
    void testDeduplicationIsScopedPerVersion() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("dedup_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        // Same string value written for v1 and v2 — same content item UUID will be reused
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "same_value")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build(),
                List.of(buildRequest(def, "same_value")));

        var v1 = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build());
        var v2 = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build());

        Assertions.assertEquals(1, v1.size(), "v1 must have exactly one attribute");
        Assertions.assertEquals(1, v2.size(), "v2 must have exactly one attribute");

        // Two separate mapping rows at the repository level (different objectVersion)
        var allRows = attributeContent2ObjectRepository.getAllObjectDataAttributesContent(
                VERSIONED_RESOURCE, objectUuid);
        Assertions.assertEquals(2, allRows.size(),
                "dedup check must allow two separate mapping rows for v1 and v2");
    }

    /**
     * Namespace isolation: unversioned (null version) rows and versioned rows for
     * the same objectUuid must not bleed into each other's read queries.
     */
    @Test
    void testUnversionedAndVersionedRowsDontBleed() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("namespace_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        // Write an unversioned row (null objectVersion)
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).build(),
                List.of(buildRequest(def, "unversioned_value")));

        // Write a versioned row (v1)
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "v1_value")));

        // Unversioned read must only return the unversioned row
        var unversioned = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).build());
        Assertions.assertEquals(1, unversioned.size());
        Assertions.assertEquals("unversioned_value", firstStringValue(unversioned),
                "Unversioned read must return unversioned_value only");

        // Versioned read (v1) must only return the v1 row
        var v1Content = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build());
        Assertions.assertEquals(1, v1Content.size());
        Assertions.assertEquals("v1_value", firstStringValue(v1Content),
                "Versioned read (v1) must return v1_value only");
    }

    /**
     * Connector change: switching the connector between two in-place overwrites of the same version must leave no stale
     * rows from the old connector.
     *
     * <p>Scenario: version 1 is written with connector A. The resource is then updated in-place (no version bump) with connector B.
     * After the replacement, the only rows in the DB for this version+operation must belong to connector B.
     */
    @Test
    void testReplaceVersionedOperation_connectorChange_noStaleRows() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();

        // Two connectors representing "before" and "after" the connector change
        Connector connectorA = connector;  // created in setUp()
        Connector connectorB = new Connector();
        connectorB.setName("ConnectorB_" + UUID.randomUUID());
        connectorB.setUrl("http://localhost:9998");
        connectorB.setVersion(com.czertainly.api.model.client.connector.v2.ConnectorVersion.V1);
        connectorB.setStatus(com.czertainly.api.model.core.connector.ConnectorStatus.CONNECTED);
        connectorB = connectorRepository.save(connectorB);

        // Register attribute definitions under each connector for the same operation
        DataAttributeV3 defA = buildDataAttribute("formatter_attr_a");
        DataAttributeV3 defB = buildDataAttribute("formatter_attr_b");
        attributeEngine.updateDataAttributeDefinitions(connectorA.getUuid(), OPERATION_FORMAT, List.of(defA));
        attributeEngine.updateDataAttributeDefinitions(connectorB.getUuid(), OPERATION_FORMAT, List.of(defB));

        // Write v1 using connector A (simulates initial resource creation)
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connectorA.getUuid()).operation(OPERATION_FORMAT).version(1).build(),
                List.of(buildRequest(defA, "connA_value")));

        // Verify connector A's rows exist
        var beforeReplace = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connectorA.getUuid()).operation(OPERATION_FORMAT).version(1).build());
        Assertions.assertEquals(1, beforeReplace.size(), "connector A rows must exist before replace");

        // In-place overwrite: connector changes from A to B — use replaceObjectDataAttributesContent (wide pre-delete)
        attributeEngine.replaceObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connectorB.getUuid()).operation(OPERATION_FORMAT).version(1).build(),
                List.of(buildRequest(defB, "connB_value")));

        // Connector A rows must be gone
        var staleRows = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connectorA.getUuid()).operation(OPERATION_FORMAT).version(1).build());
        Assertions.assertTrue(staleRows.isEmpty(),
                "stale rows from connector A must be purged after connector change");

        // Connector B rows must be present with the new value
        var freshRows = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connectorB.getUuid()).operation(OPERATION_FORMAT).version(1).build());
        Assertions.assertEquals(1, freshRows.size(), "connector B rows must be present");
        Assertions.assertEquals("connB_value", firstStringValue(freshRows));
    }

    @Test
    void testReplaceVersionedOperation_emptyList_clearsExistingRows() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();

        DataAttributeV3 def = buildDataAttribute("sign_op_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "sign_value")));

        Assertions.assertFalse(attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build()).isEmpty());

        attributeEngine.replaceObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of());

        var afterSwitch = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build());
        Assertions.assertTrue(afterSwitch.isEmpty());
    }

    @Test
    void testReplaceVersionedOperation_doesNotAffectOtherVersions() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();

        DataAttributeV3 def = buildDataAttribute("isolated_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_FORMAT, List.of(def));

        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_FORMAT).version(1).build(),
                List.of(buildRequest(def, "v1_value")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_FORMAT).version(2).build(),
                List.of(buildRequest(def, "v2_value")));

        // Replace v1 — v2 must be unaffected
        attributeEngine.replaceObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_FORMAT).version(1).build(),
                List.of(buildRequest(def, "v1_replaced")));

        Assertions.assertEquals("v1_replaced", firstStringValue(
                        attributeEngine.getObjectDataAttributesContent(
                                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                                        .connector(connector.getUuid()).operation(OPERATION_FORMAT).version(1).build())),
                "v1 must show replaced value");

        Assertions.assertEquals("v2_value", firstStringValue(
                        attributeEngine.getObjectDataAttributesContent(
                                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                                        .connector(connector.getUuid()).operation(OPERATION_FORMAT).version(2).build())),
                "v2 must be unaffected by v1 replace");
    }

    @Test
    void testReplaceVersionedOperation_requiresNonNullVersion() {
        ObjectAttributeContentInfo noVersion = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, UUID.randomUUID())
                .connector(connector.getUuid()).operation(OPERATION_SIGN).build();

        Assertions.assertThrows(IllegalArgumentException.class,
                () -> attributeEngine.replaceObjectDataAttributesContent(noVersion, EMPTY_REQUEST_ATTRIBUTES),
                "must throw when objectVersion is null");
    }

    @Test
    void testReplaceVersionedOperation_requiresNonNullOperation() {
        ObjectAttributeContentInfo noOperation = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, UUID.randomUUID())
                .connector(connector.getUuid()).version(1).build();

        Assertions.assertThrows(IllegalArgumentException.class,
                () -> attributeEngine.replaceObjectDataAttributesContent(noOperation, EMPTY_REQUEST_ATTRIBUTES),
                "must throw when operation is null");
    }

    @Test
    void testReplaceVersionedOperation_doesNotAffectOtherPurposes() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        String altPurpose = "alt-signature";

        DataAttributeV3 def = buildDataAttribute("multi_purpose_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        // Write two independent purpose-scoped attribute sets for the same version+operation.
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "primary_value")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).purpose(altPurpose).version(1).build(),
                List.of(buildRequest(def, "alt_value")));

        // Sanity: both are readable before the replace.
        Assertions.assertEquals("primary_value", firstStringValue(
                        attributeEngine.getObjectDataAttributesContent(
                                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build())),
                "primary purpose must be readable before replace");
        Assertions.assertEquals("alt_value", firstStringValue(
                        attributeEngine.getObjectDataAttributesContent(
                                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                                        .connector(connector.getUuid()).operation(OPERATION_SIGN).purpose(altPurpose).version(1).build())),
                "alt purpose must be readable before replace");

        // Replace only the primary-purpose set (purpose == null).
        attributeEngine.replaceObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "primary_replaced")));

        // The primary purpose must show the new value.
        Assertions.assertEquals("primary_replaced", firstStringValue(
                        attributeEngine.getObjectDataAttributesContent(
                                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build())),
                "primary purpose must reflect the replaced value");

        // Alt-purpose rows must be completely untouched.
        var altAfter = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).purpose(altPurpose).version(1).build());
        Assertions.assertEquals(1, altAfter.size(),
                "alt-purpose rows must survive the replace of the primary-purpose set");
        Assertions.assertEquals("alt_value", firstStringValue(altAfter),
                "alt-purpose value must be unchanged after replacing the primary-purpose set");
    }

    @Test
    void testDeleteForVersion_deletesOnlySpecifiedVersion() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("version_prune_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        for (int v = 1; v <= 3; v++) {
            attributeEngine.updateObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                            .connector(connector.getUuid()).operation(OPERATION_SIGN).version(v).build(),
                    List.of(buildRequest(def, "value_v" + v)));
        }

        attributeEngine.deleteObjectAttributeContentForVersion(VERSIONED_RESOURCE, objectUuid, 2);

        Assertions.assertFalse(attributeEngine.getObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                                .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build()).isEmpty(),
                "v1 must still have rows");

        Assertions.assertTrue(attributeEngine.getObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                                .connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build()).isEmpty(),
                "v2 must be gone");

        Assertions.assertFalse(attributeEngine.getObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                                .connector(connector.getUuid()).operation(OPERATION_SIGN).version(3).build()).isEmpty(),
                "v3 must still have rows");
    }

    @Test
    void testDeleteForVersion_doesNotTouchUnversionedRows() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("unversioned_survive_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        // Write an unversioned row
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).build(),
                List.of(buildRequest(def, "unversioned_value")));

        // Write versioned v1
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "v1_value")));

        attributeEngine.deleteObjectAttributeContentForVersion(VERSIONED_RESOURCE, objectUuid, 1);

        // v1 must be gone
        Assertions.assertTrue(attributeEngine.getObjectDataAttributesContent(
                        ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                                .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build()).isEmpty(),
                "v1 rows must be deleted");

        // unversioned row must survive
        var unversionedAfter = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).build());
        Assertions.assertEquals(1, unversionedAfter.size(),
                "unversioned row must survive deleteObjectAttributeContentForVersion");
        Assertions.assertEquals("unversioned_value", firstStringValue(unversionedAfter));
    }

    /**
     * Guard: deleteObjectAttributeContentForVersion must reject a null version.
     */
    @Test
    void testDeleteForVersion_requiresNonNullVersion() {
        UUID randomUUID = UUID.randomUUID();
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> attributeEngine.deleteObjectAttributeContentForVersion(VERSIONED_RESOURCE, randomUUID, null),
                "must throw when version is null");
    }

    /**
     * Contrast between deleteObjectAttributeContent and deleteObjectAttributeContentForVersion:
     * when versioned rows exist for multiple versions alongside unversioned rows,
     * deleteObjectAttributeContent removes everything, while deleteObjectAttributeContentForVersion is selective.
     * <p>
     * This test documents the intended boundary between the two methods.
     */
    @Test
    void testDelete_vs_deleteForVersion_boundary() throws AttributeException, NotFoundException {
        UUID objectForAll = UUID.randomUUID();
        UUID objectForOne = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("boundary_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        // Populate both objects with v1 + v2 + unversioned
        for (UUID oid : List.of(objectForAll, objectForOne)) {
            attributeEngine.updateObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, oid)
                            .connector(connector.getUuid()).operation(OPERATION_SIGN).build(),
                    List.of(buildRequest(def, "unversioned")));
            attributeEngine.updateObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, oid)
                            .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                    List.of(buildRequest(def, "v1")));
            attributeEngine.updateObjectDataAttributesContent(
                    ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, oid)
                            .connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build(),
                    List.of(buildRequest(def, "v2")));
        }

        // deleteObjectAttributeContent removes every row for objectForAll
        attributeEngine.deleteObjectAttributeContent(VERSIONED_RESOURCE, objectForAll);
        Assertions.assertTrue(
                attributeContent2ObjectRepository.getAllObjectDataAttributesContent(VERSIONED_RESOURCE, objectForAll).isEmpty(),
                "deleteObjectAttributeContent must remove every row including all versions and unversioned");

        // deleteObjectAttributeContentForVersion removes only v1 for objectForOne
        attributeEngine.deleteObjectAttributeContentForVersion(VERSIONED_RESOURCE, objectForOne, 1);
        var remaining = attributeContent2ObjectRepository.getAllObjectDataAttributesContent(VERSIONED_RESOURCE, objectForOne);
        Assertions.assertEquals(2, remaining.size(),
                "deleteForVersion(1) must leave unversioned row and v2 row intact");
    }

    @Test
    void testVersionedWriteReadWithPurpose() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        String purpose = "signingPurpose";
        DataAttributeV3 def = buildDataAttribute("purpose_versioned_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_FORMAT, List.of(def));

        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_FORMAT).purpose(purpose).version(1).build(),
                List.of(buildRequest(def, "purpose_v1")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_FORMAT).purpose(purpose).version(2).build(),
                List.of(buildRequest(def, "purpose_v2")));

        var v1 = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_FORMAT).purpose(purpose).version(1).build());
        var v2 = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_FORMAT).purpose(purpose).version(2).build());

        Assertions.assertEquals(1, v1.size());
        Assertions.assertEquals("purpose_v1", firstStringValue(v1));
        Assertions.assertEquals(1, v2.size());
        Assertions.assertEquals("purpose_v2", firstStringValue(v2));
    }

    @Test
    void testGetRequestObjectDataAttributesContentVersioned() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("request_versioned_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "req_v1")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build(),
                List.of(buildRequest(def, "req_v2")));

        var reqV1 = attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build());
        var reqV2 = attributeEngine.getRequestObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build());

        Assertions.assertEquals(1, reqV1.size(), "getRequest v1 must return one attribute");
        Assertions.assertEquals(1, reqV2.size(), "getRequest v2 must return one attribute");

        // Cast to V3 to access the typed content list
        RequestAttributeV3 rv1 = (RequestAttributeV3) reqV1.getFirst();
        RequestAttributeV3 rv2 = (RequestAttributeV3) reqV2.getFirst();

        String dataV1 = rv1.getContent().getFirst().getData().toString();
        String dataV2 = rv2.getContent().getFirst().getData().toString();

        Assertions.assertEquals("req_v1", dataV1, "v1 request data must be req_v1");
        Assertions.assertEquals("req_v2", dataV2, "v2 request data must be req_v2");
        Assertions.assertNotEquals(dataV1, dataV2, "v1 and v2 request content must differ");
    }

    // ── Metadata (META type) versioning tests ────────────────────────────────

    /**
     * Builds a minimal MetadataAttributeV3 with a single STRING content item and
     * persists it for the given object via updateMetadataAttribute.
     */
    private MetadataAttributeV3 buildAndStoreMetaAttribute(String name, String value,
                                                           ObjectAttributeContentInfo contentInfo) throws AttributeException {
        return buildAndStoreMetaAttribute(UUID.randomUUID(), name, value, contentInfo);
    }

    private MetadataAttributeV3 buildAndStoreMetaAttribute(UUID uuid, String name, String value,
                                                           ObjectAttributeContentInfo contentInfo) throws AttributeException {
        MetadataAttributeV3 meta = new MetadataAttributeV3();
        meta.setUuid(uuid.toString());
        meta.setName(name);
        meta.setType(AttributeType.META);
        meta.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties props = new MetadataAttributeProperties();
        props.setLabel(name);
        props.setVisible(true);
        props.setGlobal(false);
        meta.setProperties(props);
        meta.setContent(List.of(new StringAttributeContentV3(value)));
        attributeEngine.updateMetadataAttribute(meta, contentInfo);
        return meta;
    }

    /**
     * getMappedMetadataContent must return only the metadata rows belonging to the requested version.
     * Writing meta for v1 and v2 of the same object and reading each version must exclusively return that version's value.
     */
    @Test
    void testGetMappedMetadataContentIsVersionScoped() throws AttributeException {
        UUID objectUuid = UUID.randomUUID();

        ObjectAttributeContentInfo v1Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).version(1).build();
        ObjectAttributeContentInfo v2Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).version(2).build();

        buildAndStoreMetaAttribute("meta_attr", "meta_value_v1", v1Info);
        buildAndStoreMetaAttribute("meta_attr", "meta_value_v2", v2Info);

        // Reading v1 must return only the v1 value
        List<MetadataResponseDto> v1Meta = attributeEngine.getMappedMetadataContent(v1Info);
        Assertions.assertFalse(v1Meta.isEmpty(), "v1 metadata must not be empty");
        String v1Value = v1Meta.stream()
                .flatMap(dto -> dto.getItems().stream())
                .flatMap(item -> item.getContent().stream())
                .map(c -> c.getData().toString())
                .filter(s -> s.contains("meta_value"))
                .findFirst()
                .orElse(null);
        Assertions.assertEquals("meta_value_v1", v1Value,
                "getMappedMetadataContent for v1 must return meta_value_v1 only");

        // Reading v2 must return only the v2 value
        List<MetadataResponseDto> v2Meta = attributeEngine.getMappedMetadataContent(v2Info);
        Assertions.assertFalse(v2Meta.isEmpty(), "v2 metadata must not be empty");
        String v2Value = v2Meta.stream()
                .flatMap(dto -> dto.getItems().stream())
                .flatMap(item -> item.getContent().stream())
                .map(c -> c.getData().toString())
                .filter(s -> s.contains("meta_value"))
                .findFirst()
                .orElse(null);
        Assertions.assertEquals("meta_value_v2", v2Value,
                "getMappedMetadataContent for v2 must return meta_value_v2 only");
    }

    /**
     * getMetadataAttributesDefinitionContent must also be version-scoped. Writing metadata definitions for v1 and v2
     * and reading each version must return only the definitions that belong to that version.
     */
    @Test
    void testGetMetadataAttributesDefinitionContentIsVersionScoped() throws AttributeException {
        UUID objectUuid = UUID.randomUUID();

        ObjectAttributeContentInfo v1Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).version(1).build();
        ObjectAttributeContentInfo v2Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).version(2).build();

        // Unique attribute names per version so we can distinguish them by name
        buildAndStoreMetaAttribute("meta_def_v1_only", "val_v1", v1Info);
        buildAndStoreMetaAttribute("meta_def_v2_only", "val_v2", v2Info);

        var v1Defs = attributeEngine.getMetadataAttributesDefinitionContent(v1Info);
        var v2Defs = attributeEngine.getMetadataAttributesDefinitionContent(v2Info);

        // v1 read must contain the v1 definition and must NOT contain the v2 definition
        boolean v1HasOwnDef = v1Defs.stream().anyMatch(a -> a.getName().equals("meta_def_v1_only"));
        boolean v1HasV2Def = v1Defs.stream().anyMatch(a -> a.getName().equals("meta_def_v2_only"));
        Assertions.assertTrue(v1HasOwnDef, "v1 definitions must include meta_def_v1_only");
        Assertions.assertFalse(v1HasV2Def, "v1 definitions must NOT include meta_def_v2_only");

        // v2 read must contain the v2 definition and must NOT contain the v1 definition
        boolean v2HasOwnDef = v2Defs.stream().anyMatch(a -> a.getName().equals("meta_def_v2_only"));
        boolean v2HasV1Def = v2Defs.stream().anyMatch(a -> a.getName().equals("meta_def_v1_only"));
        Assertions.assertTrue(v2HasOwnDef, "v2 definitions must include meta_def_v2_only");
        Assertions.assertFalse(v2HasV1Def, "v2 definitions must NOT include meta_def_v1_only");
    }

    @Test
    void testVersionedDeleteWithNullOperationDeletesCorrectRows() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        // Register a definition with no operation (null) — mimics connector attribute
        // types that do not carry an operation discriminator.
        DataAttributeV3 def = buildDataAttribute("null_op_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(def));

        ObjectAttributeContentInfo v1Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).version(1).build();
        ObjectAttributeContentInfo v2Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).version(2).build();

        attributeEngine.updateObjectDataAttributesContent(v1Info, List.of(buildRequest(def, "null_op_v1")));
        attributeEngine.updateObjectDataAttributesContent(v2Info, List.of(buildRequest(def, "null_op_v2")));

        // Delete v1 only
        attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, v1Info);

        // v1 must be gone
        var v1After = attributeEngine.getObjectDataAttributesContent(v1Info);
        Assertions.assertTrue(v1After.isEmpty(),
                "v1 attributes with null operation must be deleted");

        // v2 must be untouched
        var v2After = attributeEngine.getObjectDataAttributesContent(v2Info);
        Assertions.assertEquals(1, v2After.size(),
                "v2 attributes with null operation must remain after deleting v1");
        Assertions.assertEquals("null_op_v2", firstStringValue(v2After),
                "v2 value must be unchanged");
    }

    @Test
    void testUnversionedDeleteWithNullOperationAndNoPurposeDeletesCorrectRows() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("unv_null_op_no_purpose");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(def));

        ObjectAttributeContentInfo info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).build();  // null operation, null purpose, null version

        attributeEngine.updateObjectDataAttributesContent(info, List.of(buildRequest(def, "val")));

        // Verify the row exists
        var before = attributeEngine.getObjectDataAttributesContent(info);
        Assertions.assertEquals(1, before.size(), "row must exist before delete");

        // Delete — this previously failed silently because operation = NULL never matched
        attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, info);

        var after = attributeEngine.getObjectDataAttributesContent(info);
        Assertions.assertTrue(after.isEmpty(),
                "unversioned row with null operation (no purpose) must be deleted");
    }

    @Test
    void testUnversionedDeleteWithNullOperationAndPurposeDeletesCorrectRows() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        String purpose = "nullOpPurpose";
        DataAttributeV3 def = buildDataAttribute("unv_null_op_with_purpose");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(def));

        ObjectAttributeContentInfo info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).purpose(purpose).build();  // null operation, with purpose, null version

        attributeEngine.updateObjectDataAttributesContent(info, List.of(buildRequest(def, "val_purpose")));

        var before = attributeEngine.getObjectDataAttributesContent(info);
        Assertions.assertEquals(1, before.size(), "row must exist before delete");

        attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, info);

        var after = attributeEngine.getObjectDataAttributesContent(info);
        Assertions.assertTrue(after.isEmpty(),
                "unversioned row with null operation (with purpose) must be deleted");
    }

    @Test
    void testUnversionedDeleteDoesNotAffectVersionedRows() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("unv_vs_versioned_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(def));

        // Write one unversioned row (objectVersion = null)
        ObjectAttributeContentInfo unvInfo = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).build();
        attributeEngine.updateObjectDataAttributesContent(unvInfo, List.of(buildRequest(def, "unversioned")));

        // Write a versioned row (objectVersion = 1) for the same object
        ObjectAttributeContentInfo v1Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).version(1).build();
        attributeEngine.updateObjectDataAttributesContent(v1Info, List.of(buildRequest(def, "v1")));

        // Delete the unversioned row only
        attributeEngine.deleteOperationObjectAttributesContent(AttributeType.DATA, unvInfo);

        // Unversioned row must be gone
        var unvAfter = attributeEngine.getObjectDataAttributesContent(unvInfo);
        Assertions.assertTrue(unvAfter.isEmpty(),
                "unversioned row must be deleted");

        // Versioned row must remain intact
        var v1After = attributeEngine.getObjectDataAttributesContent(v1Info);
        Assertions.assertEquals(1, v1After.size(),
                "versioned row (v1) must survive the unversioned delete");
        Assertions.assertEquals("v1", firstStringValue(v1After),
                "v1 value must be unchanged after unversioned delete");
    }

    @Test
    void testReadingUnwrittenVersionReturnsEmptyList() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 def = buildDataAttribute("unwritten_version_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        // Only write v1
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(def, "v1_only")));

        // Reading v2 — which was never written — must return an empty list
        var v2Content = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build());
        Assertions.assertTrue(v2Content.isEmpty(),
                "Reading a version that was never written must return an empty list");

        // Reading v1 must still work normally
        var v1Content = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build());
        Assertions.assertEquals(1, v1Content.size(),
                "v1 must be readable after checking that v2 returns empty");
        Assertions.assertEquals("v1_only", firstStringValue(v1Content));
    }

    @Test
    void testDeleteVersionedWithPurposeIsScoped() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        String purpose = "deletePurpose";
        DataAttributeV3 def = buildDataAttribute("delete_purpose_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_FORMAT, List.of(def));

        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_FORMAT).purpose(purpose).version(1).build(),
                List.of(buildRequest(def, "v1_purp_value")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_FORMAT).purpose(purpose).version(2).build(),
                List.of(buildRequest(def, "v2_purp_value")));

        ObjectAttributeContentInfo v1Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_FORMAT).purpose(purpose).version(1).build();
        attributeEngine.deleteOperationObjectAttributesContent(
                AttributeType.DATA, v1Info);

        var v1After = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_FORMAT).purpose(purpose).version(1).build());
        Assertions.assertTrue(v1After.isEmpty(), "v1 with purpose must have been deleted");

        var v2After = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid).connector(connector.getUuid()).operation(OPERATION_FORMAT).purpose(purpose).version(2).build());
        Assertions.assertEquals(1, v2After.size(), "v2 with purpose must remain");
        Assertions.assertEquals("v2_purp_value", firstStringValue(v2After));
    }

    @Test
    void testDeduplicationIsScopedByPurpose() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        String purposeA = "signature";
        String purposeB = "alt-signature";

        DataAttributeV3 def = buildDataAttribute("dedup_purpose_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        // Write the SAME content value for the same object+version+connector but different purposes.
        // The same AttributeContentItem UUID will be reused for both writes (identical JSON).
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).purpose(purposeA).version(1).build(),
                List.of(buildRequest(def, "shared_value")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).purpose(purposeB).version(1).build(),
                List.of(buildRequest(def, "shared_value")));

        // Both purpose-scoped reads must return the value — not be empty.
        var contentA = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).purpose(purposeA).version(1).build());
        var contentB = attributeEngine.getObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).purpose(purposeB).version(1).build());

        Assertions.assertEquals(1, contentA.size(),
                "purpose '" + purposeA + "' must have exactly one attribute after the fix");
        Assertions.assertEquals("shared_value", firstStringValue(contentA),
                "purpose '" + purposeA + "' must return the correct value");

        Assertions.assertEquals(1, contentB.size(),
                "purpose '" + purposeB + "' must have exactly one attribute — was silently dropped before the fix");
        Assertions.assertEquals("shared_value", firstStringValue(contentB),
                "purpose '" + purposeB + "' must return the correct value");

        // Two distinct mapping rows must exist at the repository level (one per purpose, sharing the same AttributeContentItem).
        var allRows = attributeContent2ObjectRepository.getAllObjectDataAttributesContent(
                VERSIONED_RESOURCE, objectUuid);
        Assertions.assertEquals(2, allRows.size(),
                "two separate mapping rows must exist — one per purpose");
    }

    @Test
    void testNoVersionOverloadReturnsOnlyUnversionedRows() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        DataAttributeV3 unversionedDef = buildDataAttribute("no_version_overload_unversioned");
        DataAttributeV3 versionedDef = buildDataAttribute("no_version_overload_versioned");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(unversionedDef, versionedDef));

        // Write an unversioned row (the kind written before versioning was introduced)
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).build(),
                List.of(buildRequest(unversionedDef, "unversioned_value")));

        // Write versioned rows for v1 and v2 — these must NOT appear via the no-version overload
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(1).build(),
                List.of(buildRequest(versionedDef, "v1_value")));
        attributeEngine.updateObjectDataAttributesContent(
                ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                        .connector(connector.getUuid()).operation(OPERATION_SIGN).version(2).build(),
                List.of(buildRequest(versionedDef, "v2_value")));

        // getObjectDataAttributesContentUnversioned must return exactly the one unversioned row
        var result = attributeEngine.getObjectDataAttributesContentUnversioned(VERSIONED_RESOURCE, objectUuid);
        Assertions.assertEquals(1, result.size(),
                "unversioned overload must return only unversioned rows — versioned rows must not bleed in");
        Assertions.assertEquals("unversioned_value", firstStringValue(result),
                "unversioned overload must return the unversioned_value, not a versioned one");
    }

    @Test
    void testDeduplicationStillSuppressesTrueDuplicates() throws AttributeException, NotFoundException {
        UUID objectUuid = UUID.randomUUID();
        String purpose = "signature";

        DataAttributeV3 def = buildDataAttribute("dedup_same_purpose_attr");
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), OPERATION_SIGN, List.of(def));

        ObjectAttributeContentInfo info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).operation(OPERATION_SIGN).purpose(purpose).version(1).build();

        // Write the same content twice under the same purpose — the second write must be suppressed.
        attributeEngine.updateObjectDataAttributesContent(info, List.of(buildRequest(def, "dup_value")));
        attributeEngine.updateObjectDataAttributesContent(info, List.of(buildRequest(def, "dup_value")));

        var content = attributeEngine.getObjectDataAttributesContent(info);
        Assertions.assertEquals(1, content.size(),
                "a true duplicate write (same purpose) must still be deduplicated to exactly one row");
        Assertions.assertEquals("dup_value", firstStringValue(content));
    }

    /**
     * Verifies that metadata overwrite (properties.overwrite=true) is version-scoped:
     * overwriting a meta attribute for v1 must NOT delete v2's mapping for the same definition.
     */
    @Test
    void testMetadataOverwriteIsVersionScoped() throws AttributeException {
        UUID objectUuid = UUID.randomUUID();

        ObjectAttributeContentInfo v1Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).version(1).build();
        ObjectAttributeContentInfo v2Info = ObjectAttributeContentInfo.builder(VERSIONED_RESOURCE, objectUuid)
                .connector(connector.getUuid()).version(2).build();

        // All three writes must share one attribute UUID+name so they map to a single AttributeDefinition —
        // that is what makes v1 and v2 "the same definition" and what overwrite=true is defined to replace.
        UUID metaUuid = UUID.randomUUID();

        // Write distinct meta values for v1 and v2 (overwrite=false — accumulate first)
        buildAndStoreMetaAttribute(metaUuid, "overwrite_attr", "original_v1", v1Info);
        buildAndStoreMetaAttribute(metaUuid, "overwrite_attr", "original_v2", v2Info);

        // Now overwrite v1 with a new value — must not touch v2
        MetadataAttributeV3 overwriteMeta = new MetadataAttributeV3();
        overwriteMeta.setUuid(metaUuid.toString());
        overwriteMeta.setName("overwrite_attr");
        overwriteMeta.setType(AttributeType.META);
        overwriteMeta.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties props = new MetadataAttributeProperties();
        props.setLabel("overwrite_attr");
        props.setVisible(true);
        props.setGlobal(false);
        props.setOverwrite(true);       // ← key: replacement semantics
        overwriteMeta.setProperties(props);
        overwriteMeta.setContent(List.of(new StringAttributeContentV3("replaced_v1")));
        attributeEngine.updateMetadataAttribute(overwriteMeta, v1Info);

        // v1 must now hold exactly the replacement value — original_v1 was overwritten
        List<String> v1Values = attributeEngine.getMappedMetadataContent(v1Info).stream()
                .flatMap(dto -> dto.getItems().stream())
                .flatMap(item -> item.getContent().stream())
                .map(c -> c.getData().toString())
                .toList();
        Assertions.assertEquals(List.of("replaced_v1"), v1Values,
                "v1 meta must hold only the replacement value after overwrite");

        // v2 must still hold exactly its original value — the overwrite of v1 must not have deleted it
        List<String> v2Values = attributeEngine.getMappedMetadataContent(v2Info).stream()
                .flatMap(dto -> dto.getItems().stream())
                .flatMap(item -> item.getContent().stream())
                .map(c -> c.getData().toString())
                .toList();
        Assertions.assertEquals(List.of("original_v2"), v2Values,
                "v2 meta must be untouched after overwriting v1 (version isolation violated)");
    }
}
