package com.otilm.core.attribute.engine;

import com.otilm.api.model.client.attribute.ResponseAttributeV2;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.common.attribute.common.content.data.CredentialAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.CredentialAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.connector.secrets.content.ApiKeySecretContent;
import com.otilm.api.model.core.auth.AttributeResource;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** D19 (widened) outbound containment: value-echo + structural secret-shape rejection. */
class OutboundSecretContainmentTest {

    private final OutboundSecretContainment containment = new OutboundSecretContainment();

    @Test
    void recordsAndRejectsValueEchoOfExpandedSecret() {
        Set<String> expandedSecrets = new HashSet<>();
        ApiKeySecretContent secret = new ApiKeySecretContent("super-secret-token-123");
        ResourceSecretContentData blob = new ResourceSecretContentData("u", "n", secret);

        containment.recordExpandedSecrets(blob, expandedSecrets);
        assertTrue(expandedSecrets.contains("super-secret-token-123"),
                "expanded secret scalar values must be recorded for the outbound echo check");

        Object response = Map.of("attributes", List.of(Map.of("value", "super-secret-token-123")));
        assertThrows(OutboundSecretLeakException.class,
                () -> containment.assertNoExpandedSecretOutbound(response, expandedSecrets));
    }

    @Test
    void recordsAndRejectsEchoOfCredentialBlobSecret() {
        // O1: a credential/authority blob is a ResourceSimpleContentData whose secret surfaces as a
        // SecretAttributeContentV2 nested in its attributes — the previous ResourceSecretContentData-only
        // recording missed it, so a connector echoing the secret as a plain scalar slipped past the value gate.
        Set<String> expandedSecrets = new HashSet<>();
        SecretAttributeContentV2 secretContent =
                new SecretAttributeContentV2("ref", new SecretAttributeContentData("cred-secret-xyz"));
        ResponseAttributeV2 secretAttr = new ResponseAttributeV2();
        secretAttr.setName("apiKey");
        secretAttr.setContent(List.of(secretContent));
        ResourceSimpleContentData credentialBlob = new ResourceSimpleContentData(AttributeResource.CREDENTIAL);
        credentialBlob.setAttributes(List.of(secretAttr));

        containment.recordExpandedSecrets(credentialBlob, expandedSecrets);

        // Only the secret scalar is recorded — not the attribute name, the content reference, or any metadata.
        assertEquals(Set.of("cred-secret-xyz"), expandedSecrets);

        // Connector echoes the secret back as a plain scalar -> rejected by the value-echo check.
        Object response = Map.of("content", List.of(Map.of("data", "cred-secret-xyz")));
        assertThrows(OutboundSecretLeakException.class,
                () -> containment.assertNoExpandedSecretOutbound(response, expandedSecrets));
    }

    @Test
    void rejectsSecretShapeNestedInMetadataAttributeOfResponse() {
        // The response 'attributes' arm is List<BaseAttribute> — a secret nested in a MetadataAttribute (NOT a
        // DataAttribute) must still be reached by the structural walk via the universal BaseAttribute.getContent().
        SecretAttributeContentV2 secret = new SecretAttributeContentV2("ref", new SecretAttributeContentData("meta-secret"));
        MetadataAttributeV2 meta = new MetadataAttributeV2();
        meta.setName("m");
        meta.setContentType(AttributeContentType.SECRET);
        meta.setContent(List.of(secret));
        AttributeCallbackResponseDto response = new AttributeCallbackResponseDto();
        response.setAttributes(List.of(meta));

        assertThrows(OutboundSecretLeakException.class,
                () -> containment.assertNoExpandedSecretOutbound(response, new HashSet<>()));
    }

    @Test
    void doesNotRecordSecretTypeDiscriminator() {
        // Recording a SecretContent must capture its secret value, NOT the @JsonTypeInfo "type" discriminator
        // ("apiKey"), which would false-positive the value-echo check on benign responses containing that token.
        Set<String> expandedSecrets = new HashSet<>();
        containment.recordExpandedSecrets(
                new ResourceSecretContentData("u", "n", new ApiKeySecretContent("the-key-value")), expandedSecrets);
        assertEquals(Set.of("the-key-value"), expandedSecrets);
    }

    @Test
    void rejectsSecretShapeNestedInResponseDtoWrapper() {
        // The real FE-bound payload is an AttributeCallbackResponseDto, not a bare collection. A secret shape
        // nested under content -> ResourceObjectContent -> ResourceSecretContentData must still be rejected
        // structurally even with no recorded values (the previous structural check did not descend DTO wrappers).
        ResourceObjectContent content = new ResourceObjectContent();
        content.setData(new ResourceSecretContentData("u", "n", new ApiKeySecretContent("nested-secret")));
        AttributeCallbackResponseDto response = new AttributeCallbackResponseDto();
        response.setContent(List.of(content));

        assertThrows(OutboundSecretLeakException.class,
                () -> containment.assertNoExpandedSecretOutbound(response, new HashSet<>()));
    }

    @Test
    void allowsResponseThatDoesNotEchoSecret() {
        Set<String> expandedSecrets = new HashSet<>(Set.of("super-secret-token-123"));
        Object response = Map.of("attributes", List.of(Map.of("value", "harmless-public-value")));
        assertDoesNotThrow(() -> containment.assertNoExpandedSecretOutbound(response, expandedSecrets));
    }

    @Test
    void rejectsPopulatedResourceSecretContentDataStructurally() {
        ApiKeySecretContent secret = new ApiKeySecretContent("anything");
        ResourceSecretContentData populated = new ResourceSecretContentData("u", "n", secret);

        // no expandedSecrets needed — the structural check fires on the secret-bearing shape itself
        assertThrows(OutboundSecretLeakException.class,
                () -> containment.assertNoExpandedSecretOutbound(List.of(populated), new HashSet<>()));
    }

    @Test
    void allowsEmptyResourceSecretContentData() {
        ResourceSecretContentData empty = new ResourceSecretContentData();
        assertDoesNotThrow(() -> containment.assertNoExpandedSecretOutbound(List.of(empty), new HashSet<>()),
                "a SECRET reference with no inline content is a bare reference, not a leak");
    }

    @Test
    void rejectsCredentialAttributeContentV2Structurally() {
        CredentialAttributeContentData data = new CredentialAttributeContentData();
        data.setName("cred");
        CredentialAttributeContentV2 expanded = new CredentialAttributeContentV2("ref", data);

        assertThrows(OutboundSecretLeakException.class,
                () -> containment.assertNoExpandedSecretOutbound(Map.of("body", List.of(expanded)), new HashSet<>()));
    }

    @Test
    void allowsPlainResourceSimpleContentData() {
        ResourceSimpleContentData simple = new ResourceSimpleContentData(AttributeResource.AUTHORITY);
        assertDoesNotThrow(() -> containment.assertNoExpandedSecretOutbound(List.of(simple), new HashSet<>()));
    }
}
