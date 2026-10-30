package com.otilm.core.serialization.golden;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.attribute.ResponseAttributeV2;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.CredentialAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.CredentialAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the redaction performed by {@code ResponseAttributeSerializer}, the platform's primary secret redaction. It is
 * declared on the {@code ResponseAttributeV2.content} <i>field</i>, so it is live on every v2 response attribute.
 * <p>
 * It nulls the {@code data} of secret content keyed on the attribute's {@code contentType}: {@code SECRET} strips
 * directly, {@code CREDENTIAL} descends into the credential's own attributes, everything else passes through. A secret
 * is therefore kept off the wire by a string comparison in hand-written Jackson 2 code.
 */
class ResponseAttributeRedactionGoldenTest {

    private static final String SECRET_VALUE = "s3cr3t-must-never-reach-the-wire";

    private final ObjectMapper mapper = GoldenMappers.web();

    /**
     * The {@code SECRET} branch. Two steps produce the outcome and only the first is the redaction: the serializer
     * nulls the {@code data}, then {@code @JsonInclude(NON_NULL)} removes the key. The content entry survives so
     * consumers still learn a secret attribute exists.
     */
    @Test
    void secretContentIsRedactedOutOfTheWireEntirely() {
        ResponseAttributeV2 attribute = responseAttribute(AttributeContentType.SECRET, new SecretAttributeContentV2(
                "ref-secret", new SecretAttributeContentData(SECRET_VALUE, ProtectionLevel.ENCRYPTED)));

        GoldenJson.assertMatchesGolden("redaction-response-attribute-secret", mapper, attribute);

        assertThat(serialized(attribute))
                .describedAs("the secret value must not appear anywhere in the serialized response")
                .doesNotContain(SECRET_VALUE);

        JsonNode content = mapper.valueToTree(attribute).path("content").get(0);
        assertThat(content.path("data").isMissingNode())
                .describedAs("the secret's data must be gone from the wire, not merely emptied")
                .isTrue();
        assertThat(content.path("reference").asText())
                .describedAs("the content entry itself must survive so consumers still see the attribute exists")
                .isEqualTo("ref-secret");
    }

    /**
     * The {@code CREDENTIAL} branch, where the secret nests inside the credential's own attribute list. A rewrite
     * handling the flat case but missing the nesting would leak.
     */
    @Test
    void secretsNestedInsideCredentialContentAreAlsoRedacted() {
        DataAttributeV2 nestedSecret = new DataAttributeV2();
        nestedSecret.setUuid("7e3b1f80-0000-4000-8000-000000000002");
        nestedSecret.setName("password");
        nestedSecret.setType(AttributeType.DATA);
        nestedSecret.setContentType(AttributeContentType.SECRET);
        nestedSecret
                .setContent(List
                        .of(new SecretAttributeContentV2("ref-nested-secret",
                                new SecretAttributeContentData(SECRET_VALUE, ProtectionLevel.ENCRYPTED))));

        CredentialAttributeContentData credentialData = new CredentialAttributeContentData();
        credentialData.setUuid("7e3b1f80-0000-4000-8000-000000000003");
        credentialData.setName("Connector Credential");
        credentialData.setKind("Basic");
        credentialData.setAttributes(List.of(nestedSecret));

        ResponseAttributeV2 attribute = responseAttribute(AttributeContentType.CREDENTIAL,
                new CredentialAttributeContentV2("ref-credential", credentialData));

        GoldenJson.assertMatchesGolden("redaction-response-attribute-credential", mapper, attribute);

        assertThat(serialized(attribute))
                .describedAs("a secret nested inside credential content must be redacted too")
                .doesNotContain(SECRET_VALUE);
    }

    /**
     * The negative control for the two above: without it they would still pass if the serializer degenerated into
     * nulling every content regardless of type.
     */
    @Test
    void nonSecretContentPassesThroughUnredacted() {
        ResponseAttributeV2 attribute = responseAttribute(AttributeContentType.STRING,
                new BaseAttributeContentV2<>("ref-string", "an ordinary public value"));

        GoldenJson.assertMatchesGolden("redaction-response-attribute-passthrough", mapper, attribute);

        JsonNode data = mapper.valueToTree(attribute).path("content").get(0).path("data");
        assertThat(data.asText())
                .describedAs("ordinary content must reach the wire intact; redacting everything would be data loss")
                .isEqualTo("an ordinary public value");
    }

    /**
     * The serializer reads the enclosing attribute's {@code contentType} through
     * {@code JsonGenerator.getCurrentValue()}. If the upgrade broke that back-reference, every attribute — including
     * secret-bearing ones — would take this unredacted branch.
     */
    @Test
    void aNullContentTypeTakesTheUnredactedBranchWhichIsWhyTheBackReferenceMatters() {
        ResponseAttributeV2 attribute = responseAttribute(null,
                new BaseAttributeContentV2<>("ref-untyped", "value with no declared content type"));

        GoldenJson.assertMatchesGolden("redaction-response-attribute-null-content-type", mapper, attribute);
    }

    private static ResponseAttributeV2 responseAttribute(AttributeContentType contentType,
            BaseAttributeContentV2<?> content) {
        ResponseAttributeV2 attribute = new ResponseAttributeV2();
        attribute.setUuid(UUID.fromString("7e3b1f80-0000-4000-8000-000000000001"));
        attribute.setName("credentialAttribute");
        attribute.setLabel("Credential");
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(contentType);
        attribute.setContent(List.of(content));
        return attribute;
    }

    private String serialized(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (Exception e) {
            throw new IllegalStateException("Could not serialize response attribute", e);
        }
    }
}
