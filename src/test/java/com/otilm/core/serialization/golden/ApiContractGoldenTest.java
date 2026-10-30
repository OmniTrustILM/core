package com.otilm.core.serialization.golden;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV2;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.common.UuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.certificate.CertificateDto;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the mapper-level rules shaping every REST DTO — null omission, date rendering, and the polymorphic attribute
 * types — against representative carriers rather than field by field.
 * <p>
 * Core defines almost no DTOs of its own; the contract layer is the published {@code interfaces} artifact, consumed by
 * ~40 connector repositories that will still be on Spring Boot 3.5 when core moves to 4.1.
 */
class ApiContractGoldenTest {

    private final ObjectMapper mapper = GoldenMappers.web();

    /**
     * {@code NON_NULL} inclusion decides whether an unset field arrives as an absent key or an explicit {@code null},
     * which connectors and the FE distinguish.
     */
    @Test
    void wireMapperOmitsNullFieldsRatherThanRenderingThemExplicitly() {
        CertificateDto sparse = new CertificateDto();
        sparse.setUuid("d41f8c9b-0000-4000-8000-000000000001");
        sparse.setCommonName("host.example.com");

        GoldenJson.assertMatchesGolden("api-null-inclusion", mapper, sparse);

        JsonNode tree = mapper.valueToTree(sparse);
        assertThat(tree.has("notBefore"))
                .describedAs("an unset field must stay absent rather than render as an explicit null")
                .isFalse();
    }

    /** With {@code WRITE_DATES_AS_TIMESTAMPS} disabled, dates render as ISO-8601 strings across every response. */
    @Test
    void wireMapperRendersDatesAsIsoStringsRatherThanNumericTimestamps() {
        CertificateDto certificate = new CertificateDto();
        certificate.setUuid("d41f8c9b-0000-4000-8000-000000000002");
        certificate.setCommonName("host.example.com");
        certificate.setNotBefore(Date.from(Instant.parse("2026-01-15T09:30:00Z")));
        certificate.setNotAfter(Date.from(Instant.parse("2026-04-15T09:30:00Z")));

        GoldenJson.assertMatchesGolden("api-date-rendering", mapper, certificate);

        JsonNode tree = mapper.valueToTree(certificate);
        assertThat(tree.path("notBefore").isNumber())
                .describedAs("dates must not regress to numeric timestamps")
                .isFalse();
        assertThat(tree.path("notBefore").asText())
                .describedAs("dates are an ISO-8601 string contract")
                .startsWith("2026-01-15T09:30:00");
    }

    /**
     * The v2 and v3 attribute schemas coexist in live responses, so both arms of the {@code version} discriminator are
     * pinned. Confusing them renders in the FE as an attribute with no content.
     */
    @Test
    void responseAttributeV3KeepsItsVersionDiscriminatorAndContentShape() {
        ResponseAttributeV3 attribute = new ResponseAttributeV3();
        attribute.setUuid(UUID.fromString("d41f8c9b-0000-4000-8000-000000000003"));
        attribute.setName("commonName");
        attribute.setLabel("Common Name");
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3("ref-cn", "host.example.com")));

        GoldenJson
                .assertMatchesGoldenAndRoundTrips("api-response-attribute-v3", mapper, attribute,
                        ResponseAttribute.class);

        assertThat(mapper.valueToTree(attribute).path("version").asText()).isEqualTo(AttributeVersion.V3.getCode());
    }

    @Test
    void responseAttributeV2KeepsItsVersionDiscriminatorAndContentShape() {
        ResponseAttributeV2 attribute = new ResponseAttributeV2();
        attribute.setUuid(UUID.fromString("d41f8c9b-0000-4000-8000-000000000004"));
        attribute.setName("commonName");
        attribute.setLabel("Common Name");
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new BaseAttributeContentV2<>("ref-cn", "host.example.com")));

        GoldenJson
                .assertMatchesGoldenAndRoundTrips("api-response-attribute-v2", mapper, attribute,
                        ResponseAttribute.class);

        assertThat(mapper.valueToTree(attribute).path("version").asText()).isEqualTo(AttributeVersion.V2.getCode());
    }

    /** The platform's most-returned response body: the identifier of a just-created object. */
    @Test
    void uuidResponseKeepsItsShape() {
        GoldenJson
                .assertMatchesGoldenAndRoundTrips("api-uuid-response", mapper,
                        new UuidDto("d41f8c9b-0000-4000-8000-000000000005"), UuidDto.class);
    }
}
