package com.otilm.core.serialization.golden;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.CredentialAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.CredentialAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.connector.secrets.content.KeyStoreSecretContent;
import com.otilm.api.model.connector.secrets.content.KeyStoreType;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.OutboundSecretLeakException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Pins the serialized shapes {@link OutboundSecretContainment} depends on, and proves the guard still rejects each of
 * them. Here a Jackson shape change is a security regression, because both of the guard's checks are shape-coupled:
 * <ul>
 * <li>the value-echo check compares string leaves of {@code valueToTree(response)} against recorded secret values, so a
 * secret rendered differently degrades the check into a no-op that still passes;</li>
 * <li>the recording path strips the {@code type}, {@code username} and {@code keyStoreType} keys by exact name, so a
 * discriminator rename would leave the discriminator value recorded as if it were a secret.</li>
 * </ul>
 */
class SecretContainmentGoldenTest {

    private static final String SECRET_VALUE = "s3cr3t-material-expanded-server-side";

    private static final Set<String> RECORDED_SECRET = Set.of(SECRET_VALUE);

    private static final Set<String> NOTHING_RECORDED = Set.of();

    private final ObjectMapper mapper = GoldenMappers.web();

    /** Shares the goldens' mapper; a second instance would let the two drift apart silently. */
    private final OutboundSecretContainment containment = new OutboundSecretContainment(mapper);

    @Test
    void populatedResourceSecretContentDataKeepsItsShapeAndIsRefused() {
        ResourceSecretContentData data = populatedResourceSecret();

        GoldenJson.assertMatchesGolden("containment-resource-secret-content-data", mapper, data);

        assertThatExceptionOfType(OutboundSecretLeakException.class)
                .describedAs("a populated ResourceSecretContentData must never reach the FE")
                .isThrownBy(() -> containment.assertNoExpandedSecretOutbound(data, NOTHING_RECORDED));
    }

    @Test
    void credentialAttributeContentKeepsItsShapeAndIsRefused() {
        CredentialAttributeContentData credentialData = new CredentialAttributeContentData();
        credentialData.setUuid("9c2e5a71-0000-4000-8000-000000000002");
        credentialData.setName("Connector Credential");
        credentialData.setKind("Basic");
        CredentialAttributeContentV2 content = new CredentialAttributeContentV2("ref-credential", credentialData);

        GoldenJson.assertMatchesGolden("containment-credential-attribute-content-v2", mapper, content);

        assertThatExceptionOfType(OutboundSecretLeakException.class)
                .describedAs("a CredentialAttributeContentV2 must be refused by type alone")
                .isThrownBy(() -> containment.assertNoExpandedSecretOutbound(content, NOTHING_RECORDED));
    }

    /**
     * {@code SecretAttributeContentV2} redeclares the {@code data} field its parent already declares, and a
     * field/accessor visibility change is what turns a shadowed property into a duplicated or dropped key.
     */
    @Test
    void secretAttributeContentKeepsItsShadowedDataPropertyAndIsRefused() {
        SecretAttributeContentV2 content = new SecretAttributeContentV2("ref-secret",
                new SecretAttributeContentData(SECRET_VALUE, ProtectionLevel.ENCRYPTED));

        GoldenJson.assertMatchesGolden("containment-secret-attribute-content-v2", mapper, content);

        JsonNode tree = mapper.valueToTree(content);
        assertThat(tree.path("data").path("secret").asText())
                .describedAs("the shadowed 'data' property must still serialize the secret exactly once, at one path; "
                        + "if it moves, the value-echo scan keeps passing while inspecting nothing")
                .isEqualTo(SECRET_VALUE);

        assertThatExceptionOfType(OutboundSecretLeakException.class)
                .isThrownBy(() -> containment.assertNoExpandedSecretOutbound(content, NOTHING_RECORDED));
    }

    @Test
    void populatedSecretAttributeContentDataIsRefused() {
        SecretAttributeContentData data = new SecretAttributeContentData(SECRET_VALUE, ProtectionLevel.ENCRYPTED);

        GoldenJson.assertMatchesGolden("containment-secret-attribute-content-data", mapper, data);

        assertThatExceptionOfType(OutboundSecretLeakException.class)
                .isThrownBy(() -> containment.assertNoExpandedSecretOutbound(data, NOTHING_RECORDED));
    }

    /** A plain string content whose value happens to be a secret expanded earlier in the call. */
    @Test
    void valueEchoCheckStillSeesASecretHiddenInAnOtherwiseInnocentResponse() {
        AttributeCallbackResponseDto response = echoingCallbackResponse();

        GoldenJson.assertMatchesGolden("containment-callback-response-echoing-secret", mapper, response);

        assertThatExceptionOfType(OutboundSecretLeakException.class)
                .describedAs("the response carries no secret-typed shape, so only the value-echo scan can catch it")
                .isThrownBy(() -> containment.assertNoExpandedSecretOutbound(response, RECORDED_SECRET));
    }

    /** Without this control the echo test above could pass merely because the guard rejects every response. */
    @Test
    void anEquivalentResponseWithoutTheSecretIsAllowedThrough() {
        assertThatCode(() -> containment.assertNoExpandedSecretOutbound(benignCallbackResponse(), RECORDED_SECRET))
                .describedAs("a response with no secret must pass, otherwise the echo test proves nothing")
                .doesNotThrowAnyException();
    }

    /**
     * The recorder strips {@code type}, {@code username} and {@code keyStoreType} by exact name. A rename would record
     * the discriminator value as a secret and refuse every later response mentioning it.
     */
    @Test
    void recordingCapturesSecretLeavesButNotTheLowEntropyDiscriminatorAndUsername() {
        Set<String> recorded = new HashSet<>();

        containment.recordExpandedSecretsFromRequest(List.of(resolvedSecretAttribute()), recorded);

        assertThat(recorded)
                .describedAs("the password is the secret leaf that must be recorded for echo detection")
                .contains("basic-auth-password")
                .describedAs("the type discriminator and username are low-entropy and must stay unrecorded")
                .doesNotContain("basicAuth", "BASIC_AUTH", "connector-user");
    }

    /**
     * {@link KeyStoreSecretContent} is the only subtype carrying {@code keyStoreType}, and both of its secret leaves
     * must survive the strip.
     */
    @Test
    void recordingCapturesBothKeyStoreSecretLeavesButNotItsTypeTag() {
        Set<String> recorded = new HashSet<>();

        containment.recordExpandedSecretsFromRequest(List.of(resolvedKeyStoreSecretAttribute()), recorded);

        assertThat(recorded)
                .describedAs("both key-store secret leaves must be recorded for echo detection")
                .contains("a2V5LXN0b3JlLWJ5dGVz", "key-store-password")
                .describedAs("the type discriminator and the key-store type tag are low-entropy and must stay "
                        + "unrecorded, otherwise every later response naming the key-store format is refused")
                .doesNotContain("keyStore", "KEY_STORE", "PKCS12");
    }

    private static RequestAttribute resolvedSecretAttribute() {
        return new RequestAttributeV3(UUID.fromString("9c2e5a71-0000-4000-8000-000000000003"), "vaultSecret",
                AttributeContentType.RESOURCE,
                List.of(new ResourceObjectContent("ref-secret-resource", populatedResourceSecret())));
    }

    private static RequestAttribute resolvedKeyStoreSecretAttribute() {
        ResourceSecretContentData data = new ResourceSecretContentData("9c2e5a71-0000-4000-8000-000000000005",
                "Key Store Secret",
                new KeyStoreSecretContent(KeyStoreType.PKCS12, "a2V5LXN0b3JlLWJ5dGVz", "key-store-password"));

        return new RequestAttributeV3(UUID.fromString("9c2e5a71-0000-4000-8000-000000000006"), "keyStoreSecret",
                AttributeContentType.RESOURCE, List.of(new ResourceObjectContent("ref-key-store-resource", data)));
    }

    /**
     * {@code SecretAttributeContentV2} exposes no {@code contentType}, so a serialized secret reads back as a plain
     * {@code BaseAttributeContentV2} that every {@code instanceof} in the structural check misses. The value-echo scan
     * is therefore the only containment net for a secret arriving over the wire.
     */
    @Test
    void aSecretArrivingAsJsonIsCaughtByValueEchoBecauseTheStructuralCheckCannotSeeIt() throws Exception {
        String fromConnector = mapper
                .writeValueAsString(new SecretAttributeContentV2("ref-secret",
                        new SecretAttributeContentData(SECRET_VALUE, ProtectionLevel.ENCRYPTED)));

        Object deserialized = mapper.readValue(fromConnector, AttributeContent.class);

        assertThat(deserialized)
                .describedAs("a serialized secret content carries no contentType, so it reads back as the plain v2 "
                        + "content type the structural check cannot recognize")
                .isInstanceOf(BaseAttributeContentV2.class)
                .isNotInstanceOf(SecretAttributeContentV2.class);

        assertThatCode(() -> containment.assertNoExpandedSecretOutbound(deserialized, NOTHING_RECORDED))
                .describedAs("with no recorded secret values nothing is left to catch it — the gap the value-echo "
                        + "check exists to cover")
                .doesNotThrowAnyException();

        assertThatExceptionOfType(OutboundSecretLeakException.class)
                .describedAs("once the value is recorded, the echo scan catches it despite the lost type")
                .isThrownBy(() -> containment.assertNoExpandedSecretOutbound(deserialized, RECORDED_SECRET));
    }

    /**
     * {@code AttributeCallbackResponseDto.attributes} is declared as {@code List<BaseAttribute>}, so reading it
     * exercises the hand-written {@code BaseAttributeDeserializer} on the exact field the guard walks.
     */
    @Test
    void valueEchoCheckStillFiresOnAResponseThatWasDeserializedFromJson() throws Exception {
        String fromConnector = mapper.writeValueAsString(echoingAttributesResponse());

        AttributeCallbackResponseDto deserialized = mapper.readValue(fromConnector, AttributeCallbackResponseDto.class);

        assertThat(deserialized.getAttributes())
                .describedAs("the hand-written deserializer must resolve the concrete attribute class, otherwise the "
                        + "guard walks a shape that never carried the secret")
                .singleElement()
                .isInstanceOf(DataAttributeV3.class);

        assertThatExceptionOfType(OutboundSecretLeakException.class)
                .describedAs("the echoed secret must still be found after a full serialize/deserialize cycle")
                .isThrownBy(() -> containment.assertNoExpandedSecretOutbound(deserialized, RECORDED_SECRET));

        assertThatCode(() -> containment
                .assertNoExpandedSecretOutbound(mapper
                        .readValue(mapper.writeValueAsString(benignAttributesResponse()),
                                AttributeCallbackResponseDto.class),
                        RECORDED_SECRET))
                .describedAs("and the matching benign response must still pass, so the check above is not firing "
                        + "indiscriminately on anything round-tripped")
                .doesNotThrowAnyException();
    }

    private static ResourceSecretContentData populatedResourceSecret() {
        return new ResourceSecretContentData("9c2e5a71-0000-4000-8000-000000000001", "Vault Secret",
                new BasicAuthSecretContent("connector-user", "basic-auth-password"));
    }

    private static AttributeCallbackResponseDto echoingCallbackResponse() {
        AttributeCallbackResponseDto response = new AttributeCallbackResponseDto();
        response.setContent(List.of(stringContent(SECRET_VALUE)));
        return response;
    }

    private static AttributeCallbackResponseDto benignCallbackResponse() {
        AttributeCallbackResponseDto response = new AttributeCallbackResponseDto();
        response.setContent(List.of(stringContent("a perfectly ordinary dropdown option")));
        return response;
    }

    /** Sets only the {@code attributes} arm: the DTO's contract allows exactly one. */
    private static AttributeCallbackResponseDto echoingAttributesResponse() {
        return attributesResponse(SECRET_VALUE);
    }

    private static AttributeCallbackResponseDto benignAttributesResponse() {
        return attributesResponse("a perfectly ordinary dropdown option");
    }

    private static AttributeCallbackResponseDto attributesResponse(String value) {
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setUuid("9c2e5a71-0000-4000-8000-000000000004");
        attribute.setName("injectedOption");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(stringContent(value)));

        AttributeCallbackResponseDto response = new AttributeCallbackResponseDto();
        response.setAttributes(List.of(attribute));
        return response;
    }

    private static BaseAttributeContentV3<?> stringContent(String value) {
        return new StringAttributeContentV3("ref-option", value);
    }
}
