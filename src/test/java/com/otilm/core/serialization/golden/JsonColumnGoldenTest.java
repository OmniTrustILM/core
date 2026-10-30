package com.otilm.core.serialization.golden;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.DateTimeAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.ActorRecord;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceRecord;
import com.otilm.api.model.core.logging.records.SourceRecord;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.dao.converter.ObjectToJsonConverter;
import com.otilm.core.model.compliance.ComplianceResultDto;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.scheme.SigningSchemeModel;
import com.otilm.core.model.signing.workflow.SigningWorkflow;
import com.otilm.core.signing.tsa.TimestampSigningRecordFactory;
import com.otilm.core.signing.tsa.messages.TspRequest;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.hibernate.type.descriptor.java.StringJavaType;
import org.hibernate.type.format.jackson.JacksonJsonFormatMapper;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the JSON written into the platform's {@code jsonb} columns. No schema migration guards them, so the JSON mapping
 * <i>is</i> the schema: rows written before a shape change keep the old shape.
 * <p>
 * Columns are <b>not</b> serialized by the wire mapper — see {@link GoldenMappers#hibernateJson()} — except for
 * {@link ObjectToJsonConverter} and the {@code String} columns whose payload a producer builds before Hibernate sees
 * it.
 */
class JsonColumnGoldenTest {

    private static final OffsetDateTime FIXED_TIMESTAMP = OffsetDateTime
            .of(2026, 1, 15, 9, 30, 0, 123_000_000, ZoneOffset.UTC);

    private final JacksonJsonFormatMapper columnMapper = GoldenMappers.hibernateJson();

    private final ObjectMapper webMapper = GoldenMappers.web();

    /**
     * Fails if someone points Hibernate at the wire mapper, which would rewrite the shape of every row written
     * afterwards while the rows already stored keep the old one.
     */
    @Test
    void columnMapperKeepsNullsThatTheWireMapperOmits() {
        ComplianceResultDto sparse = new ComplianceResultDto();
        sparse.setStatus(ComplianceStatus.OK);
        sparse.setTimestamp(FIXED_TIMESTAMP);

        assertThat(column(sparse, ComplianceResultDto.class))
                .describedAs("the column mapper keeps Jackson's default inclusion, so unset members are written")
                .contains("\"message\":null");
        assertThat(web(sparse))
                .describedAs("the wire mapper omits them; a column baselined against it would pin a shape production "
                        + "never writes")
                .doesNotContain("\"message\"");
    }

    /**
     * A Java 8 date reaches the column as text. This is the one column where it takes the mapper to get there: the
     * content object is the column root, and a root is written with its declared type, so the subclass
     * {@code @JsonFormat} is bypassed. Nested content — every {@code List<RequestAttribute>} and
     * {@code List<MetadataAttribute>} column — resolves per element against the runtime class and was already text.
     */
    @Test
    void columnMapperWritesJavaTimeValuesAsText() {
        DateTimeAttributeContentV3 datetime = new DateTimeAttributeContentV3("ref-datetime",
                ZonedDateTime.of(2026, 1, 15, 9, 30, 0, 123_000_000, ZoneOffset.UTC));

        assertThat(column(datetime, AttributeContent.class))
                .describedAs("a numeric or array date is unreadable and breaks the jsonb casts in search")
                .contains("\"data\":\"2026-01-15T09:30:00.123Z\"");
    }

    /**
     * The column mapper must carry the classpath modules. Stating the mapper takes over the registration Hibernate does
     * for itself, and a mapper without this module refuses the write outright rather than degrading.
     */
    @Test
    void columnMapperRegistersTheJavaTimeModule() {
        assertThat(GoldenMappers.jsonColumnMapper().getRegisteredModuleIds())
                .describedAs("without the JSR-310 module every Java 8 date fails to persist")
                .contains("jackson-datatype-jsr310");
    }

    /**
     * Backs {@code Certificate.complianceResult}, {@code Secret.complianceResult},
     * {@code CryptographicKeyItem.complianceResult} and {@code CertificateRequestEntity.complianceResult}. Its
     * {@code timestamp} carries an explicit {@code @JsonFormat} pattern, which outranks the mapper's date handling.
     */
    @Test
    void complianceResultColumnKeepsItsShapeAndRoundTrips() {
        ComplianceResultDto result = new ComplianceResultDto();
        result.setStatus(ComplianceStatus.OK);
        result.setTimestamp(FIXED_TIMESTAMP);
        result.setMessage("All rules satisfied");

        assertColumnGoldenAndRoundTrip("column-compliance-result", result, ComplianceResultDto.class);

        assertThat(column(result, ComplianceResultDto.class))
                .describedAs("the @JsonFormat pattern must keep winning over the mapper's date handling")
                .contains("\"timestamp\":\"2026-01-15T09:30:00.123Z\"");
    }

    /**
     * Backs {@code Certificate.pendingRevokeAttributes}, {@code Secret2SyncVaultProfile.secretAttributes},
     * {@code ComplianceProfileRule.attributes} and {@code ProtocolCertificateAssociations.customAttributes}. The
     * {@code defaultImpl} of {@code RequestAttributeV2} means a stored V3 attribute that lost its {@code version}
     * discriminator comes back as V2 rather than failing, quietly downgrading persisted data.
     */
    @Test
    void requestAttributeListColumnKeepsItsShapeAndRoundTrips() {
        List<RequestAttribute> attributes = List
                .of(new RequestAttributeV3(UUID.fromString("3a8f61d2-0000-4000-8000-000000000001"), "revokeReason",
                        AttributeContentType.STRING,
                        List.of(new StringAttributeContentV3("ref-reason", "keyCompromise"))));

        assertColumnGoldenAndRoundTrip("column-request-attributes", attributes,
                new TypeReference<List<RequestAttribute>>() {
                }.getType());
    }

    /**
     * Backs {@code DiscoveryCertificate.meta}, declared {@code List<MetadataAttribute>}. That abstract intermediate
     * does not cancel {@code BaseAttribute}'s {@code @JsonSerialize(using = BaseAttributeSerializer.class)}, so the
     * column goes through the hand-written serializer, which drops {@code schemaVersion} and writes a
     * {@code properties} null.
     */
    @Test
    void metadataAttributeListColumnKeepsItsShapeAndRoundTrips() {
        MetadataAttributeV3 metadata = new MetadataAttributeV3();
        metadata.setUuid("3a8f61d2-0000-4000-8000-000000000002");
        metadata.setName("discoverySource");
        metadata.setDescription("Where the certificate was discovered");
        metadata.setType(AttributeType.META);
        metadata.setContentType(AttributeContentType.STRING);
        metadata.setContent(List.of(new StringAttributeContentV3("ref-source", "network-scan")));

        assertColumnGoldenAndRoundTrip("column-metadata-attributes", List.of(metadata),
                new TypeReference<List<MetadataAttribute>>() {
                }.getType());
    }

    /** Backs {@code AttributeContentItem.json}, the per-item content storage behind every custom attribute value. */
    @Test
    void attributeContentItemColumnKeepsItsShapeAndRoundTrips() {
        BaseAttributeContentV3<String> content = new StringAttributeContentV3("ref-item", "stored content value");

        assertColumnGoldenAndRoundTrip("column-attribute-content-item", content, AttributeContent.class);
    }

    /**
     * Pins the branch in {@code AttributeContentDeserializer}, which picks the v2 or v3 content model purely from
     * whether {@code contentType} is present. A stored v3 content that lost it silently comes back as v2.
     */
    @Test
    void attributeContentDeserializerStillPicksTheContentModelFromContentTypePresence() {
        String withContentType = column(new StringAttributeContentV3("ref-item", "v3 content"), AttributeContent.class);
        String withoutContentType = "{\"reference\":\"ref-item\",\"data\":\"v2 content\"}";

        assertThat(columnMapper.<AttributeContent>fromString(withContentType, AttributeContent.class))
                .describedAs("a present contentType selects the v3 content model")
                .isInstanceOf(BaseAttributeContentV3.class);
        assertThat(columnMapper.<AttributeContent>fromString(withoutContentType, AttributeContent.class))
                .describedAs("an absent contentType falls back to the v2 content model, silently downgrading a v3 "
                        + "value that lost it rather than rejecting it")
                .isInstanceOf(BaseAttributeContentV2.class);
    }

    /**
     * {@link ObjectToJsonConverter} backs {@code Approval.objectData}, {@code ScheduledJob.objectData},
     * {@code ConditionItem.value} and {@code ExecutionItem.data}, and is the one column path using the wire mapper.
     * <p>
     * It reads back as {@code Serializable}, so no target type guides deserialization and the value returns as a map.
     * Jackson 3 changes default binding in this exact area.
     */
    @Test
    void objectToJsonConverterKeepsItsUntypedColumnShapeAcrossTheSerializableReadBack() {
        ObjectToJsonConverter converter = new ObjectToJsonConverter();
        ReflectionTestUtils.setField(converter, "objectMapper", webMapper);

        ComplianceResultDto stored = new ComplianceResultDto();
        stored.setStatus(ComplianceStatus.NOK);
        stored.setTimestamp(FIXED_TIMESTAMP);
        stored.setMessage("Rule violated");

        String persisted = converter.convertToDatabaseColumn(stored);
        Object readBack = converter.convertToEntityAttribute(persisted);

        GoldenJson.assertMatchesGolden("column-object-converter-untyped", webMapper, readBack);

        assertThat(readBack)
                .describedAs("the converter reads back as Serializable with no target type, so the concrete class is "
                        + "lost by design")
                .isInstanceOf(Map.class);
        assertThat(converter.convertToDatabaseColumn(readBack))
                .describedAs("a stored value must survive a load-and-save cycle byte-identically")
                .isEqualTo(persisted);
    }

    /**
     * Backs {@code AuditLog.logRecord}. A {@code record} rather than a bean, so Jackson binds through the canonical
     * constructor, and its {@code operationData} is a bare {@code Serializable} with no target type.
     */
    @Test
    void auditLogRecordColumnKeepsItsShapeAndRoundTrips() {
        LogRecord logRecord = LogRecord
                .builder()
                .version("1.0")
                .audited(true)
                .module(Module.CERTIFICATES)
                .actor(ActorRecord
                        .builder()
                        .type(ActorType.USER)
                        .authMethod(AuthMethod.CERTIFICATE)
                        .uuid(UUID.fromString("5e2d8b41-0000-4000-8000-000000000001"))
                        .name("operator")
                        .build())
                .source(SourceRecord
                        .builder()
                        .method("POST")
                        .path("/v1/certificates")
                        .contentType("application/json")
                        .ipAddress("192.0.2.10")
                        .userAgent("platform-test")
                        .build())
                .resource(new ResourceRecord(Resource.CERTIFICATE,
                        UUID.fromString("5e2d8b41-0000-4000-8000-000000000002"), "issued certificate"))
                .operation(Operation.ISSUE)
                .operationResult(OperationResult.SUCCESS)
                .message("Certificate issued")
                .timestamp(FIXED_TIMESTAMP)
                .build();

        assertColumnGoldenAndRoundTrip("column-log-record", logRecord, LogRecord.class);

        assertThat(column(logRecord, LogRecord.class))
                .describedAs("the record's @JsonFormat pattern must keep winning over the mapper's date handling")
                .contains("\"timestamp\":\"2026-01-15T09:30:00.123Z\"");
    }

    /**
     * Backs {@code AttributeDefinition.definition}, declared {@code BaseAttribute}. The declared supertype does not
     * cancel {@code BaseAttribute}'s {@code @JsonSerialize(using = BaseAttributeSerializer.class)}, so every stored
     * definition goes through the hand-written serializer.
     */
    @Test
    void attributeDefinitionColumnKeepsItsShapeAndRoundTrips() {
        DataAttributeV3 definition = new DataAttributeV3();
        definition.setUuid("3a8f61d2-0000-4000-8000-000000000003");
        definition.setName("keyUsage");
        definition.setDescription("Key usage requested for the certificate");
        definition.setType(AttributeType.DATA);
        definition.setContentType(AttributeContentType.STRING);
        definition.setContent(List.of(new StringAttributeContentV3("ref-usage", "digitalSignature")));

        assertColumnGoldenAndRoundTrip("column-attribute-definition", definition, BaseAttribute.class);
    }

    /**
     * Backs {@code SigningRecord.requestMetadataJson} and {@code SigningRecordOutbox.requestMetadataJson}. Both are
     * declared {@code String}, so Hibernate stores what {@link TimestampSigningRecordFactory} built with the wire
     * mapper.
     */
    @Test
    void signingRecordMetadataColumnKeepsTheShapeTheWireMapperGivesItAndIsStoredVerbatim() {
        String metadata = tspRequestMetadataJson(Optional.of("1.3.6.1.4.1.4146.2.1"), Optional.of(BigInteger.TEN));

        GoldenJson.assertCanonicalizedJsonMatchesGolden("column-signing-record-metadata", metadata);

        assertThat(metadata)
                .describedAs("the hash algorithm is written with Enum.name(), not the platform code, so the column "
                        + "holds 'SHA_256' rather than the 'SHA-256' every wire payload carries")
                .contains("\"hashAlgorithm\":\"SHA_256\"");
        assertThat(tspRequestMetadataJson(Optional.empty(), Optional.empty()))
                .describedAs("the wire mapper's NON_NULL inclusion drops an absent policy and nonce entirely; a "
                        + "mapper writing explicit nulls here would change the shape of every row written afterwards")
                .doesNotContain("policy", "nonce");
    }

    /**
     * Hibernate's format mapper short-circuits the {@code String} java type. Reintroducing a Jackson round trip here
     * would double-encode every payload into a JSON string literal.
     */
    @Test
    void stringJsonColumnsAreBoundAndReadBackWithoutAnyJacksonStep() {
        String metadata = tspRequestMetadataJson(Optional.of("1.3.6.1.4.1.4146.2.1"), Optional.of(BigInteger.TEN));

        String bound = columnMapper.toString(metadata, StringJavaType.INSTANCE, null);

        assertThat(bound)
                .describedAs("Hibernate must hand the driver the exact bytes the producer built")
                .isEqualTo(metadata);
        assertThat(columnMapper.<String>fromString(bound, StringJavaType.INSTANCE, null))
                .describedAs("and read them back unchanged, so a stored row survives a load-and-save cycle")
                .isEqualTo(metadata);
    }

    /** Goes through the production assembly path, so a renamed metadata key fails here too. */
    private String tspRequestMetadataJson(Optional<String> policy, Optional<BigInteger> nonce) {
        SigningProfileModel<SigningWorkflow, SigningSchemeModel> profile = new SigningProfileModel<>(
                UUID.fromString("7b1c4e90-0000-4000-8000-000000000001"), "TSA Profile", "Timestamping profile", 3, true,
                List.of(SigningProtocol.TSP), null, null, null, null);
        TspRequest request = new TspRequest(DigestAlgorithm.SHA_256, new byte[]{1, 2, 3}, policy, nonce, false, null);

        return new TimestampSigningRecordFactory(webMapper)
                .source(profile, request, new BigInteger("48879"), FIXED_TIMESTAMP.toInstant(), new byte[]{4, 5},
                        SigningProtocol.TSP)
                .build()
                .getRequestMetadataJson();
    }

    /** Compares a column payload against its golden and requires it to survive a load-and-save cycle. */
    private void assertColumnGoldenAndRoundTrip(String goldenName, Object value, Type declaredType) {
        String serialized = column(value, declaredType);
        GoldenJson.assertCanonicalizedJsonMatchesGolden(goldenName, serialized);

        assertThat(GoldenJson.canonicalize(column(columnMapper.fromString(serialized, declaredType), declaredType)))
                .describedAs("round-tripping column golden '%s.json' as %s changed its JSON shape, so a stored row "
                        + "would mutate on every load-and-save", goldenName, declaredType.getTypeName())
                .isEqualTo(GoldenJson.canonicalize(serialized));
    }

    /**
     * @param declaredType the entity field's declared type, which is what Hibernate hands the format mapper. The
     * runtime class would resolve polymorphic type information against a subtype and pin a shape production never
     * writes.
     */
    private String column(Object value, Type declaredType) {
        return columnMapper.toString(value, declaredType);
    }

    private String web(Object value) {
        try {
            return webMapper.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException("Could not serialize through the wire mapper", e);
        }
    }
}
