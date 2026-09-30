package com.otilm.core.attribute.engine;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.ExtensionMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AttributeEngineJsonExtensionValueTest {

    private static final String CUSTOM_OID = "1.3.6.1.4.1.99999.1.1";

    private static final String DEMO_MODULE = """
            Demo DEFINITIONS IMPLICIT TAGS ::= BEGIN
            Demo ::= SEQUENCE { count INTEGER, name UTF8String }
            END""";

    // The OidHandler cache is process-wide static state shared across the whole test JVM.
    // Snapshot CERTIFICATE_EXTENSION before this class replaces it; restore it afterwards.
    private static Map<String, OidRecord> savedExtensionCache;

    @BeforeAll
    static void snapshotExtensionCache() {
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION);
        savedExtensionCache = existing == null ? null : new HashMap<>(existing);
    }

    @AfterAll
    static void restoreExtensionCache() {
        OidHandler
                .cacheOidCategory(OidCategory.CERTIFICATE_EXTENSION,
                        savedExtensionCache != null ? savedExtensionCache : new HashMap<>());
    }

    @BeforeEach
    void seedRegistry() {
        OidHandler.cacheOidCategory(OidCategory.CERTIFICATE_EXTENSION, new HashMap<>());
        register(CUSTOM_OID, ExtensionValueEncoding.DER, DEMO_MODULE);
    }

    @Test
    void acceptsAValueTheModuleDescribes() {
        var definition = extensionDefinition(CUSTOM_OID);

        List<ValidationError> errors = AttributeEngine
                .validateJsonExtensionValues(definition, value(definition, "{\"count\":2,\"name\":\"gateway\"}"));

        assertThat(errors).isEmpty();
    }

    @Test
    void rejectsAValueMissingAMandatoryMember_namingIt() {
        var definition = extensionDefinition(CUSTOM_OID);

        List<ValidationError> errors = AttributeEngine
                .validateJsonExtensionValues(definition, value(definition, "{\"count\":2}"));

        assertThat(errors)
                .singleElement()
                .satisfies(error -> assertThat(error.getErrorDescription()).contains("$.name").contains("required"));
    }

    @Test
    void rejectsAMemberTheExtensionDoesNotDeclare() {
        var definition = extensionDefinition(CUSTOM_OID);

        List<ValidationError> errors = AttributeEngine
                .validateJsonExtensionValues(definition,
                        value(definition, "{\"count\":2,\"name\":\"g\",\"colour\":\"red\"}"));

        assertThat(errors)
                .singleElement()
                .satisfies(
                        error -> assertThat(error.getErrorDescription()).contains("$.colour").contains("not a member"));
    }

    @Test
    void anOidNobodyHasDescribedTakesItsValueAsBytes() {
        register("1.3.6.1.4.1.99999.2.2", ExtensionValueEncoding.DER, null);
        var definition = extensionDefinition("1.3.6.1.4.1.99999.2.2");

        assertThat(AttributeEngine.validateJsonExtensionValues(definition, value(definition, "MAYBAf8CAQA=")))
                .isEmpty();
    }

    @Test
    void ignoresAnExtensionWhoseEncodingIsNotDer() {
        register("1.3.6.1.4.1.99999.3.3", ExtensionValueEncoding.UTF8_STRING, null);
        var definition = extensionDefinition("1.3.6.1.4.1.99999.3.3");

        List<ValidationError> errors = AttributeEngine
                .validateJsonExtensionValues(definition, value(definition, "{not even json"));

        assertThat(errors).isEmpty();
    }

    @Test
    void appliesTheShippedModuleForABuiltInEntry() {
        registerSystem("2.5.29.19");
        var definition = extensionDefinition("2.5.29.19");

        assertThat(AttributeEngine
                .validateJsonExtensionValues(definition, value(definition, "{\"cA\":true,\"pathLenConstraint\":0}")))
                .isEmpty();
        assertThat(AttributeEngine
                .validateJsonExtensionValues(definition, value(definition, "{\"pathLenConstraint\":-1}"))).isNotEmpty();
    }

    @Test
    void appliesTheShippedModuleWhenTheRegistryHasNoEntry() {
        var definition = extensionDefinition("2.5.29.19");

        assertThat(AttributeEngine
                .validateJsonExtensionValues(definition, value(definition, "{\"pathLenConstraint\":-1}"))).isNotEmpty();
    }

    @Test
    void aCustomEntryDeclaringNoModuleLeavesTheValueUndescribed() {
        // The refusal below is what proves the shipped module is not quietly standing in for the operator's
        // entry: under it, -1 would fail its range instead.
        register("2.5.29.19", ExtensionValueEncoding.DER, null);
        var definition = extensionDefinition("2.5.29.19");

        assertThat(AttributeEngine.validateJsonExtensionValues(definition, value(definition, "MAYBAf8CAQA=")))
                .isEmpty();
        assertThat(AttributeEngine
                .validateJsonExtensionValues(definition, value(definition, "{\"pathLenConstraint\":-1}")))
                .singleElement()
                .satisfies(error -> assertThat(error.getErrorDescription()).contains("no registered ASN.1 module"));
    }

    @Test
    void anUnreadableStoredModuleIsReportedNotThrown() {
        // A row written straight into the database bypasses registration; every request touching the OID must
        // still get an answer rather than an escaping exception.
        register("1.3.6.1.4.1.99999.4.4", ExtensionValueEncoding.DER, "this is not a module");
        var definition = extensionDefinition("1.3.6.1.4.1.99999.4.4");

        assertThat(AttributeEngine.validateJsonExtensionValues(definition, value(definition, "{\"a\":1}")))
                .singleElement()
                .satisfies(error -> assertThat(error.getErrorDescription())
                        .contains("cannot be checked")
                        .contains("1.3.6.1.4.1.99999.4.4"));
    }

    @Test
    void aMalformedWrittenValueIsRefusedWithTheReason() {
        var definition = extensionDefinition(CUSTOM_OID);

        assertThat(AttributeEngine.validateJsonExtensionValues(definition, value(definition, "{\"count\":2,}")))
                .singleElement()
                .satisfies(error -> assertThat(error.getErrorDescription()).contains("not well-formed JSON"));
    }

    @Test
    void aBareScalarValueIsWrittenNotBytes() {
        register("1.3.6.1.4.1.99999.5.5", ExtensionValueEncoding.DER, """
                M DEFINITIONS IMPLICIT TAGS ::= BEGIN
                Tier ::= INTEGER (0..3)
                END""");
        var definition = extensionDefinition("1.3.6.1.4.1.99999.5.5");

        assertThat(AttributeEngine.validateJsonExtensionValues(definition, value(definition, "2"))).isEmpty();
        assertThat(AttributeEngine.validateJsonExtensionValues(definition, value(definition, "7")))
                .singleElement()
                .satisfies(error -> assertThat(error.getErrorDescription()).contains("permitted range"));
    }

    @Test
    void refusesAWrittenValueForAnExtensionThatHasATypedTarget() {
        // Authoring a new opaque mapping for these OIDs is already refused; a legacy one must not gain a
        // second, weaker way in. The typed target draws on a closed vocabulary and cannot express a malformed
        // value, which is exactly what a written one can.
        registerSystem("2.5.29.15");
        var definition = extensionDefinition("2.5.29.15");

        assertThat(AttributeEngine
                .validateJsonExtensionValues(definition, value(definition, "{\"value\":\"80\",\"length\":1}")))
                .singleElement()
                .satisfies(error -> assertThat(error.getErrorDescription()).contains("Key Usage"));
    }

    @Test
    void leavesALegacyBase64MappingToATypedTargetUntouched() {
        // A definition stored before the typed targets existed keeps projecting its DER blob; base64 cannot
        // begin with a character a written value starts with, so the two are told apart without ambiguity.
        registerSystem("2.5.29.15");
        var definition = extensionDefinition("2.5.29.15");

        assertThat(AttributeEngine.validateJsonExtensionValues(definition, value(definition, "AwIFoA=="))).isEmpty();
    }

    @Test
    void everyDeclaredContentErrorIsReportedNotJustTheFirst() {
        // Declared content with two bad values must name both; surfacing only the first sends the author round
        // the loop once per mistake.
        DataAttributeV3 definition = extensionDefinition("2.5.29.19");
        definition
                .setContent(List
                        .of(new StringAttributeContentV3("{\"pathLenConstraint\":-1}"),
                                new StringAttributeContentV3("{\"colour\":\"red\"}")));

        AttributeException thrown = Assertions
                .assertThrows(AttributeException.class,
                        () -> AttributeEngine.validateJsonSchemaDeclarations(definition, null));

        assertThat(thrown.getMessage()).contains("; ");
        assertThat(thrown.getMessage().split("; ")).hasSizeGreaterThan(1);
    }

    private static void registerSystem(String oid) {
        OidHandler
                .cacheOid(OidCategory.CERTIFICATE_EXTENSION, oid,
                        OidRecord
                                .builder()
                                .displayName("Built-in Extension")
                                .valueEncoding(ExtensionValueEncoding.DER)
                                .system(true)
                                .build());
    }

    private static void register(String oid, ExtensionValueEncoding encoding, String module) {
        OidHandler
                .cacheOid(OidCategory.CERTIFICATE_EXTENSION, oid,
                        OidRecord
                                .builder()
                                .displayName("Test Extension")
                                .valueEncoding(encoding)
                                .valueSchema(module)
                                .build());
    }

    private static DataAttributeV3 extensionDefinition(String oid) {
        ExtensionMappedField field = new ExtensionMappedField();
        field.setFieldType(FieldType.EXTENSION);
        field.setExtensionOid(oid);
        FieldMapping mapping = new FieldMapping();
        mapping.setObjectType(ObjectType.X509_CERTIFICATE);
        mapping.setFields(List.of(field));

        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid(UUID.randomUUID().toString());
        definition.setName("serviceIdentity");
        definition.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("Service Identity");
        definition.setProperties(properties);
        definition.setFieldMapping(mapping);
        return definition;
    }

    private static RequestAttribute value(DataAttributeV3 definition, String data) {
        return new RequestAttributeV3(UUID.fromString(definition.getUuid()), definition.getName(),
                AttributeContentType.STRING, List.<BaseAttributeContentV3<?>>of(new StringAttributeContentV3(data)));
    }
}
