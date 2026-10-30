package com.otilm.core.serialization.golden;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.connector.v2.ConnectorInfo;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.constraint.AttributeConstraintType;
import com.otilm.api.model.common.attribute.common.constraint.BaseAttributeConstraint;
import com.otilm.api.model.common.attribute.common.constraint.DateTimeAttributeConstraint;
import com.otilm.api.model.common.attribute.common.constraint.RangeAttributeConstraint;
import com.otilm.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.otilm.api.model.common.attribute.common.constraint.data.DateTimeAttributeConstraintData;
import com.otilm.api.model.common.attribute.common.constraint.data.RangeAttributeConstraintData;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.CodeBlockAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.FileAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.ProgrammingLanguageEnum;
import com.otilm.api.model.common.attribute.v2.CustomAttributeV2;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.GroupAttributeV2;
import com.otilm.api.model.common.attribute.v2.InfoAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.GroupAttributeV3;
import com.otilm.api.model.common.attribute.v3.InfoAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.BooleanAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.CodeBlockAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.DateAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.DateTimeAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.FileAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.FloatAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ObjectAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TimeAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceCertificateContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.common.attribute.v3.mapping.ExtensionMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.FieldSource;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.MappedField;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.SanMappedField;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.key.KeyData;
import com.otilm.api.model.connector.cryptography.key.value.CustomKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.EprkiKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.KeyValue;
import com.otilm.api.model.connector.cryptography.key.value.PrkiKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.RawKeyValue;
import com.otilm.api.model.connector.cryptography.key.value.SpkiKeyValue;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.connector.v2.ConnectInfo;
import com.otilm.api.model.core.connector.v2.ConnectInfoV1;
import com.otilm.api.model.core.connector.v2.ConnectInfoV2;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.Month;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Pins every polymorphic {@code @JsonTypeInfo} hierarchy: the discriminator's property name, emitted value and
 * placement are three independently breakable wire contracts shared with ~40 connector repositories.
 * <p>
 * Most hierarchies use {@code As.EXISTING_PROPERTY} with a {@code defaultImpl}, so a document that loses its
 * discriminator deserializes to the default instead of failing. {@code MappedField} declares no {@code defaultImpl} and
 * {@code KeyData.value} uses {@code As.EXTERNAL_PROPERTY}; both are pinned explicitly.
 */
class AttributeTypeInfoGoldenTest {

    private static final ZonedDateTime FIXED_INSTANT = ZonedDateTime.of(2026, 1, 15, 9, 30, 0, 0, ZoneOffset.UTC);

    private final ObjectMapper mapper = GoldenMappers.web();

    /**
     * One golden per {@code BaseAttributeContentV3} subtype. The date/time subtypes are the ones that flip to numeric
     * timestamps if the {@code JavaTimeModule} or {@code WRITE_DATES_AS_TIMESTAMPS} setting is lost.
     */
    @ParameterizedTest(name = "contentType discriminator: {1}")
    @MethodSource("contentV3Subtypes")
    void baseAttributeContentV3SubtypeKeepsItsDiscriminatorAndPayloadShape(String goldenSuffix, String contentTypeCode,
            BaseAttributeContentV3<?> content) {
        String golden = "attribute-content-v3-" + goldenSuffix;

        GoldenJson.assertMatchesGoldenAndRoundTrips(golden, mapper, content, BaseAttributeContentV3.class);

        assertDiscriminator(content, "contentType", contentTypeCode);
    }

    private static Stream<Arguments> contentV3Subtypes() {
        return Stream
                .of(Arguments.of("boolean", "boolean", new BooleanAttributeContentV3("ref-boolean", Boolean.TRUE)),
                        Arguments
                                .of("codeblock", "codeblock",
                                        new CodeBlockAttributeContentV3("ref-codeblock",
                                                new CodeBlockAttributeContentData(ProgrammingLanguageEnum.JAVA,
                                                        "cmV0dXJuIDA7"))),
                        Arguments.of("date", "date", new DateAttributeContentV3(LocalDate.of(2026, Month.JANUARY, 15))),
                        Arguments
                                .of("datetime", "datetime",
                                        new DateTimeAttributeContentV3("ref-datetime", FIXED_INSTANT)),
                        Arguments.of("file", "file", fileContent()),
                        Arguments.of("float", "float", new FloatAttributeContentV3("ref-float", 1.5f)),
                        Arguments.of("integer", "integer", new IntegerAttributeContentV3("ref-integer", 42)),
                        Arguments
                                .of("object", "object",
                                        new ObjectAttributeContentV3("ref-object", "opaque-serializable")),
                        Arguments.of("string", "string", new StringAttributeContentV3("ref-string", "a string value")),
                        Arguments.of("text", "text", new TextAttributeContentV3("ref-text", "a longer block of text")),
                        Arguments.of("time", "time", new TimeAttributeContentV3(LocalTime.of(9, 30))),
                        Arguments.of("resource", "resource", resourceContent()));
    }

    private static FileAttributeContentV3 fileContent() {
        FileAttributeContentData data = new FileAttributeContentData();
        data.setContent("ZmlsZS1ib2R5");
        data.setFileName("bundle.pem");
        data.setMimeType("application/x-pem-file");
        return new FileAttributeContentV3("ref-file", data);
    }

    private static ResourceObjectContent resourceContent() {
        ResourceSimpleContentData data = new ResourceSimpleContentData(AttributeResource.AUTHORITY,
                "6f1a4d3c-0000-4000-8000-000000000001", "Issuing Authority", null);
        return new ResourceObjectContent("ref-resource", data);
    }

    /**
     * One golden per {@code ResourceObjectContentData} subtype. Four discriminator values (AUTHORITY, ENTITY, LOCATION,
     * CREDENTIAL) map to the same {@code ResourceSimpleContentData} class, so the emitted value comes from the
     * instance's {@code resource} field rather than from the subtype registration.
     */
    @ParameterizedTest(name = "resource discriminator: {1}")
    @MethodSource("resourceContentDataSubtypes")
    void resourceObjectContentDataSubtypeKeepsItsDiscriminator(String goldenSuffix, String resourceCode,
            ResourceObjectContentData data) {
        String golden = "resource-content-data-" + goldenSuffix;

        GoldenJson.assertMatchesGoldenAndRoundTrips(golden, mapper, data, ResourceObjectContentData.class);

        assertDiscriminator(data, "resource", resourceCode);
    }

    private static Stream<Arguments> resourceContentDataSubtypes() {
        return Stream
                .of(Arguments
                        .of("authority", "authorities",
                                simpleResource(AttributeResource.AUTHORITY, "6f1a4d3c-0000-4000-8000-000000000001",
                                        "Issuing Authority")),
                        Arguments
                                .of("entity", "entities",
                                        simpleResource(AttributeResource.ENTITY, "6f1a4d3c-0000-4000-8000-000000000002",
                                                "Entity Instance")),
                        Arguments
                                .of("location", "locations",
                                        simpleResource(AttributeResource.LOCATION,
                                                "6f1a4d3c-0000-4000-8000-000000000003", "Primary Location")),
                        Arguments
                                .of("credential", "credentials",
                                        simpleResource(AttributeResource.CREDENTIAL,
                                                "6f1a4d3c-0000-4000-8000-000000000004", "Connector Credential")),
                        Arguments.of("certificate", "certificates", certificateResource()),
                        // Populated content is a leak shape, covered by SecretContainmentGoldenTest.
                        Arguments
                                .of("secret", "secrets", new ResourceSecretContentData(
                                        "6f1a4d3c-0000-4000-8000-000000000006", "Vault Secret", null)));
    }

    /** The uuid is passed in rather than derived, so goldens survive {@code AttributeResource} gaining constants. */
    private static ResourceSimpleContentData simpleResource(AttributeResource resource, String uuid, String name) {
        return new ResourceSimpleContentData(resource, uuid, name, null);
    }

    private static ResourceCertificateContentData certificateResource() {
        ResourceCertificateContentData data = new ResourceCertificateContentData();
        data.setUuid("6f1a4d3c-0000-4000-8000-000000000005");
        data.setName("TLS Server Certificate");
        return data;
    }

    /**
     * One golden per {@code BaseAttributeV2} subtype. The {@code type} discriminator carries a {@code defaultImpl} of
     * {@code DataAttributeV2}, so a lost discriminator loses the attribute's identity deep inside the platform rather
     * than failing at the parse boundary.
     */
    @ParameterizedTest(name = "type discriminator: {0}")
    @MethodSource("attributeV2Subtypes")
    void baseAttributeV2SubtypeKeepsItsDiscriminator(String attributeTypeCode, Object attribute) {
        String golden = "attribute-v2-" + attributeTypeCode.toLowerCase();

        GoldenJson.assertMatchesGolden(golden, mapper, attribute);

        assertDiscriminator(attribute, "type", attributeTypeCode);
        assertResolvesBackToItsOwnSubtype(attribute);
    }

    /**
     * Reads the attribute back and requires the original class, since the failure mode above is a read-side one.
     * <p>
     * The base type is {@code BaseAttribute}, not {@code BaseAttributeV2}: the latter's {@code @JsonSubTypes} names
     * classes that do not extend it, so reading through it fails with an unresolvable type id. The live read path is
     * {@code BaseAttributeDeserializer}, which switches on {@code version} and {@code type} by hand.
     */
    private void assertResolvesBackToItsOwnSubtype(Object attribute) {
        try {
            String serialized = mapper.writeValueAsString(attribute);
            Object reread = mapper.readValue(serialized, BaseAttribute.class);

            assertThat(reread)
                    .describedAs("%s did not resolve back to its own subtype; BaseAttributeDeserializer switches on "
                            + "'version' and 'type' by hand, so either changing shape yields the wrong class rather "
                            + "than an error", attribute.getClass().getSimpleName())
                    .isInstanceOf(attribute.getClass());
        } catch (Exception e) {
            throw new IllegalStateException("Attribute did not survive a polymorphic round trip", e);
        }
    }

    private static Stream<Arguments> attributeV2Subtypes() {
        DataAttributeV2 data = new DataAttributeV2();
        data.setUuid("1b7c9e20-0000-4000-8000-000000000001");
        data.setName("dataAttribute");
        data.setDescription("A data attribute");
        data.setType(AttributeType.DATA);

        GroupAttributeV2 group = new GroupAttributeV2();
        group.setUuid("1b7c9e20-0000-4000-8000-000000000002");
        group.setName("groupAttribute");
        group.setDescription("A group attribute");

        InfoAttributeV2 info = new InfoAttributeV2();
        info.setUuid("1b7c9e20-0000-4000-8000-000000000003");
        info.setName("infoAttribute");
        info.setDescription("An info attribute");

        MetadataAttributeV2 metadata = new MetadataAttributeV2();
        metadata.setUuid("1b7c9e20-0000-4000-8000-000000000004");
        metadata.setName("metadataAttribute");
        metadata.setDescription("A metadata attribute");

        CustomAttributeV2 custom = new CustomAttributeV2();
        custom.setUuid("1b7c9e20-0000-4000-8000-000000000005");
        custom.setName("customAttribute");
        custom.setDescription("A custom attribute");

        return Stream
                .of(Arguments.of(AttributeType.DATA.getCode(), data),
                        Arguments.of(AttributeType.GROUP.getCode(), group),
                        Arguments.of(AttributeType.INFO.getCode(), info),
                        Arguments.of(AttributeType.META.getCode(), metadata),
                        Arguments.of(AttributeType.CUSTOM.getCode(), custom));
    }

    /**
     * {@code BaseAttribute} declares {@code @JsonSerialize(using = BaseAttributeSerializer.class)} and every subclass
     * re-declares a bare {@code @JsonSerialize}, cancelling the inherited {@code using}.
     * <p>
     * That cancellation binds to the <i>declared</i> type, so an uncancelling supertype still reaches the hand-written
     * serializer — see {@code JsonColumnGoldenTest}. Under the concrete class the bean serializer must win, and field
     * order is where the two differ most visibly.
     */
    @Test
    void concreteAttributesUseTheBeanSerializerNotTheHandWrittenOne() {
        DataAttributeV2 sparse = new DataAttributeV2();
        sparse.setName("sparseAttribute");
        sparse.setType(AttributeType.DATA);
        sparse.setContentType(AttributeContentType.STRING);

        GoldenJson.assertMatchesGolden("attribute-v2-bean-serializer-output", mapper, sparse);

        JsonNode tree = mapper.valueToTree(sparse);
        assertThat(tree.has("description"))
                .describedAs("the bean serializer honours NON_NULL; the hand-written one would emit an explicit null")
                .isFalse();
        assertThat(tree.fieldNames())
                .toIterable()
                .describedAs("the hand-written serializer leads with 'type' and 'version', the bean serializer "
                        + "follows declaration order")
                .startsWith("name", "version", "type");
    }

    /** One golden per {@code BaseAttributeV3} subtype, the v3 counterpart of the hierarchy above. */
    @ParameterizedTest(name = "type discriminator: {0}")
    @MethodSource("attributeV3Subtypes")
    void baseAttributeV3SubtypeKeepsItsDiscriminator(String attributeTypeCode, Object attribute) {
        String golden = "attribute-v3-" + attributeTypeCode.toLowerCase();

        GoldenJson.assertMatchesGolden(golden, mapper, attribute);

        assertDiscriminator(attribute, "type", attributeTypeCode);
        assertResolvesBackToItsOwnSubtype(attribute);
    }

    /**
     * Only {@code GroupAttributeV3} and {@code InfoAttributeV3} extend {@code BaseAttributeV3}; the other three
     * registered subtypes descend from {@code BaseAttribute} instead, so reading through {@code BaseAttributeV3} would
     * fail for them.
     */
    private static Stream<Arguments> attributeV3Subtypes() {
        DataAttributeV3 data = new DataAttributeV3();
        data.setUuid("2c9e5f11-0000-4000-8000-000000000001");
        data.setName("dataAttribute");
        data.setDescription("A v3 data attribute");
        data.setType(AttributeType.DATA);
        data.setContentType(AttributeContentType.STRING);
        data.setContent(List.of(new StringAttributeContentV3("ref-data", "a v3 data value")));

        GroupAttributeV3 group = new GroupAttributeV3();
        group.setUuid("2c9e5f11-0000-4000-8000-000000000002");
        group.setName("groupAttribute");
        group.setDescription("A v3 group attribute");
        group.setType(AttributeType.GROUP);

        InfoAttributeV3 info = new InfoAttributeV3();
        info.setUuid("2c9e5f11-0000-4000-8000-000000000003");
        info.setName("infoAttribute");
        info.setDescription("A v3 info attribute");
        info.setType(AttributeType.INFO);
        info.setContentType(AttributeContentType.STRING);
        info.setContent(List.of(new StringAttributeContentV3("ref-info", "a v3 info value")));

        MetadataAttributeV3 metadata = new MetadataAttributeV3();
        metadata.setUuid("2c9e5f11-0000-4000-8000-000000000004");
        metadata.setName("metadataAttribute");
        metadata.setDescription("A v3 metadata attribute");
        metadata.setType(AttributeType.META);
        metadata.setContentType(AttributeContentType.STRING);
        metadata.setContent(List.of(new StringAttributeContentV3("ref-meta", "a v3 metadata value")));

        CustomAttributeV3 custom = new CustomAttributeV3();
        custom.setUuid("2c9e5f11-0000-4000-8000-000000000005");
        custom.setName("customAttribute");
        custom.setDescription("A v3 custom attribute");
        custom.setType(AttributeType.CUSTOM);
        custom.setContentType(AttributeContentType.STRING);
        custom.setContent(List.of(new StringAttributeContentV3("ref-custom", "a v3 custom value")));

        return Stream
                .of(Arguments.of(AttributeType.DATA.getCode(), data),
                        Arguments.of(AttributeType.GROUP.getCode(), group),
                        Arguments.of(AttributeType.INFO.getCode(), info),
                        Arguments.of(AttributeType.META.getCode(), metadata),
                        Arguments.of(AttributeType.CUSTOM.getCode(), custom));
    }

    /**
     * One golden per {@code BaseAttributeConstraint} subtype. Each redeclares {@code data} at a concrete type, so the
     * discriminator is what tells a reader how to interpret it.
     */
    @ParameterizedTest(name = "type discriminator: {1}")
    @MethodSource("attributeConstraintSubtypes")
    void attributeConstraintSubtypeKeepsItsDiscriminator(String goldenSuffix, String constraintTypeCode,
            BaseAttributeConstraint<?> constraint) {
        String golden = "attribute-constraint-" + goldenSuffix;

        GoldenJson.assertMatchesGoldenAndRoundTrips(golden, mapper, constraint, BaseAttributeConstraint.class);

        assertDiscriminator(constraint, "type", constraintTypeCode);
    }

    private static Stream<Arguments> attributeConstraintSubtypes() {
        RangeAttributeConstraintData range = new RangeAttributeConstraintData();
        range.setFrom(1);
        range.setTo(64);

        DateTimeAttributeConstraintData dateTimeRange = new DateTimeAttributeConstraintData();
        dateTimeRange.setFrom(LocalDateTime.of(2026, Month.JANUARY, 15, 9, 30));
        dateTimeRange.setTo(LocalDateTime.of(2026, Month.APRIL, 15, 9, 30));

        return Stream
                .of(Arguments
                        .of("regexp", AttributeConstraintType.REGEXP.getCode(),
                                new RegexpAttributeConstraint("Alphanumeric only", "Value must be alphanumeric",
                                        "^[a-zA-Z0-9]+$")),
                        Arguments
                                .of("range", AttributeConstraintType.RANGE.getCode(),
                                        new RangeAttributeConstraint("Key length bounds",
                                                "Value must be between 1 and 64", range)),
                        Arguments
                                .of("datetime", AttributeConstraintType.DATETIME.getCode(),
                                        new DateTimeAttributeConstraint("Validity window",
                                                "Value must fall inside the validity window", dateTimeRange)));
    }

    /**
     * One golden per {@code MappedField} subtype. Alone among these hierarchies it declares no {@code defaultImpl}, so
     * a document that loses {@code fieldType} fails rather than becoming another subtype.
     */
    @ParameterizedTest(name = "fieldType discriminator: {1}")
    @MethodSource("mappedFieldSubtypes")
    void mappedFieldSubtypeKeepsItsDiscriminator(String goldenSuffix, String fieldTypeCode, MappedField field) {
        String golden = "mapped-field-" + goldenSuffix;

        GoldenJson.assertMatchesGoldenAndRoundTrips(golden, mapper, field, MappedField.class);

        assertDiscriminator(field, "fieldType", fieldTypeCode);
    }

    private static Stream<Arguments> mappedFieldSubtypes() {
        RdnMappedField rdn = new RdnMappedField();
        rdn.setFieldType(FieldType.RDN);
        rdn.setOrder(1);
        rdn.setSource(FieldSource.CSR);
        rdn.setRdn("CN");

        SanMappedField san = new SanMappedField();
        san.setFieldType(FieldType.SAN);
        san.setOrder(2);
        san.setSource(FieldSource.CSR_THEN_PLATFORM);
        san.setGeneralNameType(GeneralNameType.DNS);

        ExtensionMappedField extension = new ExtensionMappedField();
        extension.setFieldType(FieldType.EXTENSION);
        extension.setOrder(3);
        extension.setSource(FieldSource.PLATFORM);
        extension.setExtensionOid("2.5.29.17");
        extension.setCriticalOverridable(true);

        return Stream
                .of(Arguments.of("rdn", FieldType.RDN.getCode(), rdn),
                        Arguments.of("san", FieldType.SAN.getCode(), san),
                        Arguments.of("extension", FieldType.EXTENSION.getCode(), extension));
    }

    /** A {@code MappedField} without its discriminator has no default to fall back to and must be rejected. */
    @Test
    void mappedFieldWithoutItsDiscriminatorIsRejectedRatherThanDefaulted() {
        assertThatExceptionOfType(JsonProcessingException.class)
                .describedAs("MappedField declares no defaultImpl, so a document missing 'fieldType' must fail rather "
                        + "than resolve to an arbitrary subtype")
                .isThrownBy(() -> mapper.readValue("{\"order\":1,\"rdn\":\"CN\"}", MappedField.class));
    }

    /**
     * One golden per {@code ConnectInfo} subtype. The discriminator is the connector protocol {@code version}, so a
     * shape change here makes the platform read a v1 connector's capabilities as a v2's.
     */
    @ParameterizedTest(name = "version discriminator: {1}")
    @MethodSource("connectInfoSubtypes")
    void connectInfoSubtypeKeepsItsDiscriminator(String goldenSuffix, String versionCode, ConnectInfo connectInfo) {
        String golden = "connect-info-" + goldenSuffix;

        GoldenJson.assertMatchesGoldenAndRoundTrips(golden, mapper, connectInfo, ConnectInfo.class);

        assertDiscriminator(connectInfo, "version", versionCode);
    }

    private static Stream<Arguments> connectInfoSubtypes() {
        ConnectInfoV1 v1 = new ConnectInfoV1();
        v1.setConnectorUuid(UUID.fromString("9d3b7c58-0000-4000-8000-000000000001"));

        ConnectorInfo connector = new ConnectorInfo();
        connector.setId("authority-connector");
        connector.setName("Authority Connector");
        connector.setVersion("2.0.0");
        connector.setDescription("A v2 connector");

        ConnectInfoV2 v2 = new ConnectInfoV2();
        v2.setConnectorUuid(UUID.fromString("9d3b7c58-0000-4000-8000-000000000002"));
        v2.setConnector(connector);
        v2.setInterfaces(List.of(new ConnectorInterfaceInfo(ConnectorInterface.AUTHORITY, "2.0.0", List.of())));

        return Stream
                .of(Arguments.of("v1", ConnectorVersion.V1.getCode(), v1),
                        Arguments.of("v2", ConnectorVersion.V2.getCode(), v2));
    }

    /**
     * {@code KeyData.value} is the platform's only {@code As.EXTERNAL_PROPERTY} hierarchy: the {@code format}
     * discriminator sits beside the typed member rather than inside it.
     */
    @ParameterizedTest(name = "format discriminator: {1}")
    @MethodSource("keyDataFormats")
    void keyDataKeepsItsExternalPropertyDiscriminatorBesideTheValue(String goldenSuffix, String formatCode,
            KeyData keyData) {
        String golden = "key-data-" + goldenSuffix;

        GoldenJson.assertMatchesGoldenAndRoundTrips(golden, mapper, keyData, KeyData.class);

        JsonNode tree = mapper.valueToTree(keyData);
        assertThat(tree.path("format").asText())
                .describedAs("the format discriminator must stay a sibling of 'value'")
                .isEqualTo(formatCode);
        assertThat(tree.path("value").has("format"))
                .describedAs("an EXTERNAL_PROPERTY discriminator must not appear inside the typed value; moving it "
                        + "there changes the wire contract for every connector exchanging keys")
                .isFalse();
    }

    private static Stream<Arguments> keyDataFormats() {
        return Stream
                .of(Arguments
                        .of("raw", KeyFormat.RAW.getCode(),
                                keyData(KeyType.SECRET_KEY, KeyAlgorithm.RSA, KeyFormat.RAW,
                                        new RawKeyValue("cmF3LWtleS1ieXRlcw=="), 2048)),
                        Arguments
                                .of("spki", KeyFormat.SPKI.getCode(),
                                        keyData(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, KeyFormat.SPKI,
                                                new SpkiKeyValue("c3BraS1rZXktYnl0ZXM="), 2048)),
                        Arguments
                                .of("prki", KeyFormat.PRKI.getCode(),
                                        keyData(KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, KeyFormat.PRKI,
                                                new PrkiKeyValue("cHJraS1rZXktYnl0ZXM="), 256)),
                        Arguments
                                .of("eprki", KeyFormat.EPRKI.getCode(),
                                        keyData(KeyType.PRIVATE_KEY, KeyAlgorithm.ECDSA, KeyFormat.EPRKI,
                                                new EprkiKeyValue("ZXBya2kta2V5LWJ5dGVz"), 256)),
                        Arguments
                                .of("custom", KeyFormat.CUSTOM.getCode(), keyData(KeyType.SECRET_KEY, KeyAlgorithm.RSA,
                                        KeyFormat.CUSTOM, customKeyValue(), 2048)));
    }

    /**
     * The only subtype whose payload is a map rather than a scalar, so it pins how an {@code EXTERNAL_PROPERTY} value
     * serializes when the typed member is not a single-property object.
     */
    private static KeyValue customKeyValue() {
        HashMap<String, String> values = new HashMap<>();
        values.put("externalId", "hsm-slot-3");
        values.put("handler", "pkcs11");
        return new CustomKeyValue(values);
    }

    private static KeyData keyData(KeyType type, KeyAlgorithm algorithm, KeyFormat format, KeyValue value, int length) {
        KeyData keyData = new KeyData();
        keyData.setType(type);
        keyData.setAlgorithm(algorithm);
        keyData.setFormat(format);
        keyData.setValue(value);
        keyData.setLength(length);
        return keyData;
    }

    /** A present {@code value} with no {@code format} beside it is rejected whatever the mapper is configured to do. */
    @Test
    void keyDataValueWithoutItsExternalDiscriminatorIsRejected() {
        assertThatExceptionOfType(JsonProcessingException.class)
                .describedAs("a present key value with no 'format' beside it must fail rather than bind to an "
                        + "arbitrary key encoding")
                .isThrownBy(() -> mapper
                        .readValue("{\"type\":\"Public\",\"algorithm\":\"RSA\",\"length\":2048,"
                                + "\"value\":{\"value\":\"c3BraS1rZXktYnl0ZXM=\"}}", KeyData.class));
    }

    /**
     * A {@code format} with no {@code value} — a key stripped of its material — is accepted only because
     * {@code WebAppConfig} disables {@code FAIL_ON_MISSING_EXTERNAL_TYPE_ID_PROPERTY}. Jackson's default rejects it.
     */
    @Test
    void keyDataFormatWithoutItsValueIsAcceptedOnlyBecauseTheWireMapperOptsOut() throws Exception {
        String metadataOnly = "{\"type\":\"Public\",\"algorithm\":\"RSA\",\"length\":2048,"
                + "\"format\":\"SubjectPublicKeyInfo\"}";

        KeyData parsed = mapper.readValue(metadataOnly, KeyData.class);
        assertThat(parsed.getFormat())
                .describedAs("the wire mapper keeps the declared format even with no key material beside it")
                .isEqualTo(KeyFormat.SPKI);
        assertThat(parsed.getValue()).isNull();

        ObjectMapper jacksonDefault = new ObjectMapper()
                .enable(DeserializationFeature.FAIL_ON_MISSING_EXTERNAL_TYPE_ID_PROPERTY);
        assertThatExceptionOfType(JsonProcessingException.class)
                .describedAs("Jackson's default rejects it; re-enabling the feature during the migration would break "
                        + "every stripped-key payload the platform accepts today")
                .isThrownBy(() -> jacksonDefault.readValue(metadataOnly, KeyData.class));
    }

    /** Reads the tree rather than substring-matching, so placement is asserted too. */
    private void assertDiscriminator(Object value, String property, String expectedValue) {
        JsonNode tree = mapper.valueToTree(value);

        assertThat(tree.isObject())
                .describedAs("%s must serialize as a JSON object for its discriminator to be a property at all",
                        value.getClass().getSimpleName())
                .isTrue();
        assertThat(tree.has(property))
                .describedAs("%s lost its '%s' discriminator; consumers would fall back to the defaultImpl instead "
                        + "of failing", value.getClass().getSimpleName(), property)
                .isTrue();
        assertThat(tree.get(property).asText())
                .describedAs("%s emitted an unexpected '%s' discriminator value", value.getClass().getSimpleName(),
                        property)
                .isEqualTo(expectedValue);
    }
}
