package com.otilm.core.attribute.engine;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.attribute.CsrAttributes;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Plain unit test (no Spring context) for the authoring-time request-attribute definition validation.
 * RDN-code mapping validation resolves against the OidHandler registry, seeded from SystemOid here.
 */
class RequestAttributeDefinitionValidationTest {

    @BeforeAll
    static void seedRdnRegistry() {
        Map<String, OidRecord> rdn = new HashMap<>();
        for (SystemOid systemOid : SystemOid.values()) {
            if (systemOid.getCategory() == OidCategory.RDN_ATTRIBUTE_TYPE) {
                rdn.put(systemOid.getOid(), OidRecord.builder()
                        .displayName(systemOid.name())
                        .code(systemOid.getCode())
                        .build());
            }
        }
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, rdn);
    }

    @AfterAll
    static void clearRdnRegistry() {
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
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
        ValidationException e = Assertions.assertThrows(ValidationException.class,
                () -> AttributeEngine.validateRequestAttributeDefinitions(List.of(definition)));
        Assertions.assertTrue(e.getMessage().contains(expectedMessagePart),
                "expected message containing '" + expectedMessagePart + "' but was: " + e.getMessage());
    }

    @Test
    void validDefinitionPasses() {
        Assertions.assertDoesNotThrow(
                () -> AttributeEngine.validateRequestAttributeDefinitions(List.of(validDefinition())));
    }

    @Test
    void nullListIsNoOp() {
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestAttributeDefinitions(null));
    }

    @Test
    void seededDefaultSetPasses() {
        Assertions.assertDoesNotThrow(() -> AttributeEngine.validateRequestAttributeDefinitions(
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
        Assertions.assertDoesNotThrow(
                () -> AttributeEngine.validateRequestAttributeDefinitions(List.of(definition)));
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

    @Test
    void dottedOidRdnPasses() {
        DataAttributeV3 definition = validDefinition();
        ((RdnMappedField) definition.getFieldMapping().getFields().get(0)).setRdn("2.5.4.3");
        Assertions.assertDoesNotThrow(
                () -> AttributeEngine.validateRequestAttributeDefinitions(List.of(definition)));
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
}