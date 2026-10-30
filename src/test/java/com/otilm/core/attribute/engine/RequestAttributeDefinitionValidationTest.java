package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.constraint.JsonSchemaAttributeConstraint;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.ExtendedKeyUsageMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.ExtensionMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.KeyUsageMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.MappedField;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.attribute.CsrAttributes;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Plain unit test (no Spring context) for the authoring-time request-attribute definition validation. RDN-code mapping
 * validation resolves against the OidHandler registry, seeded from SystemOid here.
 *
 * <p>
 * The OID registry is process-wide static state shared across the surefire JVM, so this class snapshots the RDN
 * category in {@code @BeforeAll} and restores it in {@code @AfterAll}. When no cache existed beforehand, the restore
 * leaves an empty map rather than the absent ({@code null}) state — equivalent for every reader of the RDN category
 * ({@code getCodeToOidMap} treats absent as empty). Assumes the default serial per-JVM test execution — seeding a
 * shared static is not parallel-safe.
 */
class RequestAttributeDefinitionValidationTest {

    private static Map<String, OidRecord> savedRdnRegistry;

    @BeforeAll
    static void seedRdnRegistry() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnRegistry = existing == null ? null : new HashMap<>(existing);
        Map<String, OidRecord> rdn = new HashMap<>();
        for (SystemOid systemOid : SystemOid.values()) {
            if (systemOid.getCategory() == OidCategory.RDN_ATTRIBUTE_TYPE) {
                rdn
                        .put(systemOid.getOid(),
                                OidRecord.builder().displayName(systemOid.name()).code(systemOid.getCode()).build());
            }
        }
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);
    }

    @AfterAll
    static void restoreRdnRegistry() {
        OidHandler
                .cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                        savedRdnRegistry == null ? new HashMap<>() : savedRdnRegistry);
    }

    @Test
    void jsonSchemaConstraintWithABrokenSchemaDocumentRejected() {
        DataAttributeV3 definition = validDefinition();
        JsonSchemaAttributeConstraint constraint = new JsonSchemaAttributeConstraint();
        constraint.setData("this is not json");
        definition.setConstraints(List.of(constraint));
        assertRejected(definition, "valid JSON Schema document");
    }

    @Test
    void jsonSchemaConstraintCheckedEvenWithoutAFieldMapping() {
        DataAttributeV3 definition = validDefinition();
        definition.setFieldMapping(null);
        JsonSchemaAttributeConstraint constraint = new JsonSchemaAttributeConstraint();
        constraint.setData("this is not json");
        definition.setConstraints(List.of(constraint));
        Assertions
                .assertThrows(AttributeException.class,
                        () -> AttributeEngine.validateJsonSchemaDeclarations(definition, null));
    }

    @Test
    void jsonSchemaConstraintWithAValidSchemaAccepted() {
        DataAttributeV3 definition = validDefinition();
        JsonSchemaAttributeConstraint constraint = new JsonSchemaAttributeConstraint();
        constraint.setData("{\"type\":\"object\"}");
        definition.setConstraints(List.of(constraint));
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestAttributeDefinitions(List.of(definition)));
    }

    private static DataAttributeV3 validDefinition() {
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid("9abaeba0-973d-11ed-a8fc-0242ac120002");
        attribute.setName("commonName");
        attribute.setContentType(AttributeContentType.STRING);

        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Common Name");
        properties.setRequired(true);
        properties.setReadOnly(false);
        properties.setVisible(true);
        attribute.setProperties(properties);

        RdnMappedField field = new RdnMappedField();
        field.setFieldType(FieldType.RDN);
        field.setRdn("CN");
        FieldMapping mapping = new FieldMapping();
        mapping.setObjectType(ObjectType.X509_CERTIFICATE);
        mapping.setFields(List.of(field));
        attribute.setFieldMapping(mapping);
        return attribute;
    }

    private static void assertRejected(BaseAttribute definition, String expectedMessagePart) {
        List<BaseAttribute> definitions = List.of(definition);
        ValidationException e = Assertions
                .assertThrows(ValidationException.class,
                        () -> AttributeEngine.validateRequestAttributeDefinitions(definitions));
        Assertions
                .assertTrue(e.getMessage().contains(expectedMessagePart),
                        "expected message containing '" + expectedMessagePart + "' but was: " + e.getMessage());
    }

    @Test
    void validDefinitionPasses() {
        Assertions
                .assertDoesNotThrow(
                        () -> AttributeEngine.validateRequestAttributeDefinitions(List.of(validDefinition())));
    }

    @Test
    void nullListIsNoOp() {
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestAttributeDefinitions(null));
    }

    @Test
    void seededDefaultSetPasses() {
        Assertions
                .assertDoesNotThrow(() -> AttributeEngine
                        .validateRequestAttributeDefinitions(
                                new ArrayList<>(CsrAttributes.csrAttributesAsDataAttributesV3())));
    }

    @Test
    void readOnlyWithoutContentRejected() {
        DataAttributeV3 definition = validDefinition();
        definition.getProperties().setReadOnly(true);
        assertRejected(definition, "Read only attribute must define its content");
    }

    @Test
    void requiredReadOnlyWithRealContentPasses() {
        DataAttributeV3 definition = validDefinition();
        definition.getProperties().setReadOnly(true);
        definition.getProperties().setRequired(true);
        definition.setContent(List.of(new StringAttributeContentV3("fixed-value")));
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestAttributeDefinitions(List.of(definition)));
    }

    @Test
    void missingFieldMappingRejected() {
        DataAttributeV3 definition = validDefinition();
        definition.setFieldMapping(null);
        assertRejected(definition, "must declare a field mapping");
    }

    @Test
    void emptyFieldMappingRejected() {
        DataAttributeV3 definition = validDefinition();
        definition.getFieldMapping().setFields(List.of());
        assertRejected(definition, "must declare a field mapping");
    }

    @Test
    void nonDataV3DefinitionRejected() {
        CustomAttributeV3 custom = new CustomAttributeV3();
        custom.setUuid("9abaeba0-973d-11ed-a8fc-0242ac120099");
        custom.setName("someCustom");
        assertRejected(custom, "must be a v3 data attribute");
    }

    @Test
    void missingPropertiesRejected() {
        DataAttributeV3 definition = validDefinition();
        definition.setProperties(null);
        assertRejected(definition, "does not have properties");
    }

    @Test
    void unknownRdnCodeRejected() {
        DataAttributeV3 definition = validDefinition();
        ((RdnMappedField) definition.getFieldMapping().getFields().get(0)).setRdn("NOPE");
        assertRejected(definition, "not a known RDN code");
    }

    private static DataAttributeV3 extensionDefinition(String extensionOid) {
        DataAttributeV3 attribute = validDefinition();
        attribute.setName("extension");
        ExtensionMappedField field = new ExtensionMappedField();
        field.setFieldType(FieldType.EXTENSION);
        field.setExtensionOid(extensionOid);
        FieldMapping mapping = new FieldMapping();
        mapping.setObjectType(ObjectType.X509_CERTIFICATE);
        mapping.setFields(List.of(field));
        attribute.setFieldMapping(mapping);
        return attribute;
    }

    @Test
    void extensionMappingOnSubjectAlternativeNameRejected() {
        // given — the parser diverts 2.5.29.17 into subjectAltNames, so such a mapping never matches
        // when / then
        assertRejected(extensionDefinition("2.5.29.17"), "SAN mapping target");
    }

    @Test
    void extensionMappingOnRequesterOwnedSystemExtensionPasses() {
        // given — a requester-owned system extension is a legitimate mapping target and must pass
        // the registry check. Basic Constraints, not extended key usage: the latter now has a structured
        // target, so the opaque route to it is closed.
        List<BaseAttribute> definitions = List.of(extensionDefinition("2.5.29.19"));

        // when / then
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestAttributeDefinitions(definitions));
    }

    @Test
    void rdnCodeResolvesRegardlessOfCase() {
        // given — the authoring gate reads getCodeToOidMap while request-time resolution uses the
        // case-insensitive index; a mixed-case system code such as PostalCode must resolve either way
        DataAttributeV3 attribute = validDefinition();
        ((RdnMappedField) attribute.getFieldMapping().getFields().getFirst()).setRdn("postalcode");
        List<BaseAttribute> definitions = List.of(attribute);

        // when / then
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestAttributeDefinitions(definitions));
    }

    @Test
    void dottedOidRdnPasses() {
        DataAttributeV3 definition = validDefinition();
        ((RdnMappedField) definition.getFieldMapping().getFields().get(0)).setRdn("2.5.4.3");
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestAttributeDefinitions(List.of(definition)));
    }

    @Test
    void defaultContentWithoutDataRejected() {
        DataAttributeV3 definition = validDefinition();
        definition.setContent(List.of(new StringAttributeContentV3()));
        assertRejected(definition, "does not contain data");
    }

    @Test
    void defaultContentNotMatchingContentTypeRejected() {
        DataAttributeV3 definition = validDefinition();
        definition.setContent(List.of(new IntegerAttributeContentV3(2)));
        assertRejected(definition, "does not match content type");
    }

    @Test
    void defaultContentViolatingConstraintsRejected() {
        // commonNameAttribute carries a regexp constraint: max 64 characters
        DataAttributeV3 definition = CsrAttributes.commonNameAttribute();
        definition.setContent(List.of(new StringAttributeContentV3("x".repeat(65))));
        assertRejected(definition, "violates constraints");
    }

    // ── Structured mapping targets ──────────────────────────────────────────

    @Test
    void structuredTargetOnANonListAttributeRejected() {
        // A structured target's value is a set of items, so the attribute has to be a list.
        DataAttributeV3 definition = structuredDefinition(keyUsageField(), false, "digitalSignature");
        definition.getProperties().setList(false);
        assertRejected(definition, "requires a list attribute");
    }

    @Test
    void structuredTargetWithNoPermittedItemsRejected() {
        // With no declared content, AttributeEngine's predefined-list check would refuse every CSR bit
        // at request time. Fail at authoring instead.
        DataAttributeV3 definition = structuredDefinition(keyUsageField(), false);
        assertRejected(definition, "extensibleList");
    }

    @Test
    void structuredTargetCannotBePinnedToAnExactSet() {
        // readOnly would mean "exactly these items", but a read-only attribute cannot be a list and a
        // set-valued target must be one. A structured selection is therefore always a permitted set.
        DataAttributeV3 definition = structuredDefinition(keyUsageField(), false, "digitalSignature");
        definition.getProperties().setReadOnly(true);
        assertRejected(definition, "Read only attribute cannot be list");
    }

    @Test
    void unknownKeyUsageItemRejected() {
        DataAttributeV3 definition = structuredDefinition(keyUsageField(), false, "digitalSignature", "notABit");
        assertRejected(definition, "'notABit', which is not a key usage");
    }

    @Test
    void unregisteredExtendedKeyUsagePurposeRejected() {
        DataAttributeV3 definition = structuredDefinition(extendedKeyUsageField(), false, "1.3.6.1.4.1.99999.42");
        // Naming the registry is the actionable part: the operator has to register the purpose, not guess.
        assertRejected(definition, "register it under the Extended Key Usage OID category");
    }

    @Test
    void extendedKeyUsagePurposeGivenAsACodeRejected() {
        // A plausible mistake: authoring "serverAuth" where the purpose OID belongs.
        DataAttributeV3 definition = structuredDefinition(extendedKeyUsageField(), false, "serverAuth");
        assertRejected(definition, "not a dotted-decimal OID");
    }

    @Test
    void systemExtendedKeyUsagePurposeAccepted() {
        // serverAuth ships in SystemOid under EXTENDED_KEY_USAGE, so it resolves without a registry row
        DataAttributeV3 definition = structuredDefinition(extendedKeyUsageField(), false, "1.3.6.1.5.5.7.3.1");
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestAttributeDefinitions(List.of(definition)));
    }

    @Test
    void extensibleStructuredTargetNeedsNoDeclaredItems() {
        DataAttributeV3 definition = structuredDefinition(keyUsageField(), true);
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestAttributeDefinitions(List.of(definition)));
    }

    @Test
    void sameStructuredTargetDeclaredTwiceRejected() {
        // Without this, the definition saves cleanly and then fails every projection as a duplicate OID.
        DataAttributeV3 definition = structuredDefinition(keyUsageField(), false, "digitalSignature");
        definition.getFieldMapping().setFields(List.of(keyUsageField(), keyUsageField()));
        assertRejected(definition, "more than once");
    }

    @Test
    void opaqueExtensionMappingOnAStructuredOidRejected() {
        // The base64-DER route to key usage is what this feature exists to replace, so it is closed for
        // authoring - the same treatment subjectAltName already gets.
        DataAttributeV3 definition = validDefinition();
        ExtensionMappedField field = new ExtensionMappedField();
        field.setFieldType(FieldType.EXTENSION);
        field.setExtensionOid("2.5.29.15");
        definition.getFieldMapping().setFields(List.of(field));
        assertRejected(definition, "Key Usage mapping target");
    }

    @Test
    void opaqueExtensionMappingOnExtendedKeyUsageRejected() {
        DataAttributeV3 definition = validDefinition();
        ExtensionMappedField field = new ExtensionMappedField();
        field.setFieldType(FieldType.EXTENSION);
        field.setExtensionOid("2.5.29.37");
        definition.getFieldMapping().setFields(List.of(field));
        assertRejected(definition, "Extended Key Usage mapping target");
    }

    private static KeyUsageMappedField keyUsageField() {
        KeyUsageMappedField field = new KeyUsageMappedField();
        field.setFieldType(FieldType.KEY_USAGE);
        return field;
    }

    private static ExtendedKeyUsageMappedField extendedKeyUsageField() {
        ExtendedKeyUsageMappedField field = new ExtendedKeyUsageMappedField();
        field.setFieldType(FieldType.EXTENDED_KEY_USAGE);
        return field;
    }

    private static DataAttributeV3 structuredDefinition(MappedField field, boolean extensibleList, String... items) {
        DataAttributeV3 definition = validDefinition();
        definition.getProperties().setRequired(false);
        definition.getProperties().setList(true);
        definition.getProperties().setExtensibleList(extensibleList);
        definition.getFieldMapping().setFields(List.of(field));
        List<com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3<?>> content = new ArrayList<>();
        for (String item : items) {
            content.add(new StringAttributeContentV3(item));
        }
        definition.setContent(content.isEmpty() ? null : content);
        return definition;
    }
}
