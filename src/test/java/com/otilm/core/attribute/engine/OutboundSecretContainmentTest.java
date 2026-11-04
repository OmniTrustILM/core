package com.otilm.core.attribute.engine;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttributeV2;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.CodeBlockAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.CredentialAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.FileAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.ProgrammingLanguageEnum;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.CredentialAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.IntegerAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.connector.secrets.content.ApiKeySecretContent;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.core.attribute.engine.records.ObjectAttributeContent;
import java.io.Serializable;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** D19 (widened) outbound containment: value-echo + structural secret-shape rejection. */
class OutboundSecretContainmentTest {

    private static final String SEALED = "sealed-by-the-attribute-engine";

    private final OutboundSecretContainment containment = new OutboundSecretContainment(
            new com.fasterxml.jackson.databind.ObjectMapper());

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
    void recordsExpandedSecretsFromResolvedRequestAttributes() {
        // The operation path records from the resolved request attributes it is about to send the connector (not from
        // a content blob): a resolved SECRET reference carries a ResourceObjectContent -> ResourceSecretContentData.
        ResourceObjectContent secretContent = new ResourceObjectContent();
        secretContent.setData(new ResourceSecretContentData("u", "n", new ApiKeySecretContent("s3cr3t-token")));
        RequestAttribute resolved = new RequestAttributeV3(UUID.randomUUID(), "oauthClient",
                AttributeContentType.RESOURCE, List.<BaseAttributeContentV3<?>>of(secretContent));

        Set<String> expandedSecrets = new HashSet<>();
        containment.recordExpandedSecretsFromRequest(List.of(resolved), expandedSecrets);

        assertEquals(Set.of("s3cr3t-token"), expandedSecrets,
                "the secret value in a resolved request attribute must be recorded for the outbound echo check");
        Object echoResponse = Map.of("attributes", List.of(Map.of("default", "s3cr3t-token")));
        assertThrows(OutboundSecretLeakException.class,
                () -> containment.assertNoExpandedSecretOutbound(echoResponse, expandedSecrets));
    }

    @Test
    void recordsTheSecret_ofASecretStoredEncrypted() {
        // given
        var tokenPassword = "correct-horse-battery-staple";
        var resolved = List
                .of(resolvedAttribute("token-password",
                        decryptedContent(new SecretAttributeContentData(tokenPassword))));
        Set<String> expandedSecrets = new HashSet<>();

        // when
        containment.recordExpandedSecretsFromRequest(resolved, expandedSecrets);

        // then
        assertThat(expandedSecrets).containsExactly(tokenPassword);
    }

    @Test
    void recordsTheSecretInACredential_storedEncrypted() {
        // given
        var credentialPassword = "correct-horse-battery-staple";
        DataAttributeV2 password = new DataAttributeV2();
        password.setName("password");
        password.setContentType(AttributeContentType.SECRET);
        password
                .setContent(List
                        .of(new SecretAttributeContentV2(null, new SecretAttributeContentData(credentialPassword))));
        CredentialAttributeContentData credential = new CredentialAttributeContentData();
        credential.setName("hsm-login");
        credential.setAttributes(List.of(password));
        var resolved = List.of(resolvedAttribute("token-login", decryptedContent(credential)));
        Set<String> expandedSecrets = new HashSet<>();

        // when
        containment.recordExpandedSecretsFromRequest(resolved, expandedSecrets);

        // then
        assertThat(expandedSecrets).containsExactly(credentialPassword);
    }

    @Test
    void recordsTheTextValue_ofACredentialAttributeStoredEncrypted() {
        // given
        var credentialPin = "4815162342";
        var resolved = List
                .of(resolvedAttribute("token-login",
                        credentialHolding(credentialAttribute("pin", ProtectionLevel.ENCRYPTED, credentialPin))));
        Set<String> expandedSecrets = new HashSet<>();

        // when
        containment.recordExpandedSecretsFromRequest(resolved, expandedSecrets);

        // then
        assertThat(expandedSecrets).containsExactly(credentialPin);
    }

    @Test
    void leavesOutTheValue_ofACredentialAttributeStoredInPlain() {
        // given
        var resolved = List
                .of(resolvedAttribute("token-login",
                        credentialHolding(credentialAttribute("user", ProtectionLevel.NONE, "hsm-operator"))));
        Set<String> expandedSecrets = new HashSet<>();

        // when
        containment.recordExpandedSecretsFromRequest(resolved, expandedSecrets);

        // then
        assertThat(expandedSecrets).isEmpty();
    }

    @Test
    void recordsTheTextValue_ofAnAttributeStoredEncrypted() {
        // given
        var tokenPin = "4815162342";
        var pinRow = storedRow("token-pin", SEALED);
        var resolved = List.of(resolvedFrom(pinRow, new StringAttributeContentV2(tokenPin)));
        Set<String> expandedSecrets = new HashSet<>();

        // when
        containment.recordProtectedValuesFromRequest(List.of(pinRow), resolved, expandedSecrets);

        // then
        assertThat(expandedSecrets).containsExactly(tokenPin);
    }

    @Test
    void recordsOnlyTheEncryptedRowsValue_whenTwoDefinitionsShareAName() {
        // given
        var tokenPin = "4815162342";
        var publicAlgorithm = "SHA256withRSA";
        var encryptedRow = storedRow("token-setting", SEALED);
        var plainNamesake = storedRow("token-setting", null);
        var resolved = List
                .of(resolvedFrom(encryptedRow, new StringAttributeContentV2(tokenPin)),
                        resolvedFrom(plainNamesake, new StringAttributeContentV2(publicAlgorithm)));
        Set<String> expandedSecrets = new HashSet<>();

        // when
        containment.recordProtectedValuesFromRequest(List.of(encryptedRow, plainNamesake), resolved, expandedSecrets);

        // then
        assertThat(expandedSecrets).containsExactly(tokenPin);
    }

    @Test
    void recordsTheFileBody_ofAFileStoredEncrypted() {
        // given
        var keystoreBody = "MIIKPAIBAzCCCfYGCSqGSIb3DQEHAaCC";
        var keystoreRow = storedRow("token-keystore", SEALED);
        var resolved = List
                .of(resolvedFrom(keystoreRow,
                        decryptedContent(fileData(keystoreBody, "token.p12", "application/x-pkcs12"))));
        Set<String> expandedSecrets = new HashSet<>();

        // when
        containment.recordProtectedValuesFromRequest(List.of(keystoreRow), resolved, expandedSecrets);

        // then
        assertThat(expandedSecrets).containsExactly(keystoreBody);
    }

    @Test
    void recordsTheCode_ofACodeBlockStoredEncrypted() {
        // given
        var unlockScript = "ZWNobyAkVE9LRU5fUElO";
        var scriptRow = storedRow("unlock-script", SEALED);
        var resolved = List
                .of(resolvedFrom(scriptRow, decryptedContent(
                        new CodeBlockAttributeContentData(ProgrammingLanguageEnum.BASH, unlockScript))));
        Set<String> expandedSecrets = new HashSet<>();

        // when
        containment.recordProtectedValuesFromRequest(List.of(scriptRow), resolved, expandedSecrets);

        // then
        assertThat(expandedSecrets).containsExactly(unlockScript);
    }

    @Test
    void leavesOutTheValue_ofAnAttributeStoredInPlain() {
        // given
        var labelRow = storedRow("token-label", null);
        var resolved = List.of(resolvedFrom(labelRow, new StringAttributeContentV2("primary")));
        Set<String> expandedSecrets = new HashSet<>();

        // when
        containment.recordProtectedValuesFromRequest(List.of(labelRow), resolved, expandedSecrets);

        // then
        assertThat(expandedSecrets).isEmpty();
    }

    @Test
    void leavesOutANumber_storedEncrypted() {
        // given
        var slotRow = storedRow("slot", SEALED);
        var resolved = List.of(resolvedFrom(slotRow, new IntegerAttributeContentV2(1)));
        Set<String> expandedSecrets = new HashSet<>();

        // when
        containment.recordProtectedValuesFromRequest(List.of(slotRow), resolved, expandedSecrets);

        // then
        assertThat(expandedSecrets).isEmpty();
    }

    @Test
    void recordsAndRejectsEchoOfCredentialBlobSecret() {
        // O1: a credential/authority blob is a ResourceSimpleContentData whose secret surfaces as a
        // SecretAttributeContentV2 nested in its attributes — the previous ResourceSecretContentData-only
        // recording missed it, so a connector echoing the secret as a plain scalar slipped past the value gate.
        Set<String> expandedSecrets = new HashSet<>();
        SecretAttributeContentV2 secretContent = new SecretAttributeContentV2("ref",
                new SecretAttributeContentData("cred-secret-xyz"));
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
        SecretAttributeContentV2 secret = new SecretAttributeContentV2("ref",
                new SecretAttributeContentData("meta-secret"));
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
        containment
                .recordExpandedSecrets(
                        new ResourceSecretContentData("u", "n", new ApiKeySecretContent("the-key-value")),
                        expandedSecrets);
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

    /**
     * A secret an earlier call sent is known by its digest only, and an answer that echoes it is refused all the same.
     */
    @Test
    void rejectsEchoOfASecretKnownByItsDigest() {
        List<String> sentSecretDigests = OutboundSecretContainment.digestsOf(Set.of("sent-earlier-secret"));
        Set<String> noSecretOfThisCall = Set.of();
        Object echoing = Map.of("metadata", List.of(Map.of("value", "sent-earlier-secret")));
        Object harmless = Map.of("metadata", List.of(Map.of("value", "handle")));

        assertThrows(OutboundSecretLeakException.class,
                () -> containment.assertNoExpandedSecretOutbound(echoing, noSecretOfThisCall, sentSecretDigests));
        assertDoesNotThrow(
                () -> containment.assertNoExpandedSecretOutbound(harmless, noSecretOfThisCall, sentSecretDigests));
        assertFalse(sentSecretDigests.contains("sent-earlier-secret"), "a digest must not be the secret itself");
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

    @Test
    void recordsNestedCredentialSecretThroughAllWrappers() {
        // Deeply nested: ResourceSimpleContentData -> ResponseAttribute -> CredentialAttributeContentV2 ->
        // CredentialAttributeContentData -> DataAttributeV2 -> SecretAttributeContentV2 -> SecretAttributeContentData.
        // recordExpandedSecrets walks the whole graph (no early throw) so every wrapper-descent branch is exercised.
        DataAttributeV2 inner = new DataAttributeV2();
        inner.setName("pw");
        inner.setContentType(AttributeContentType.SECRET);
        inner.setContent(List.of(new SecretAttributeContentV2("r", new SecretAttributeContentData("deep-secret"))));
        CredentialAttributeContentData cad = new CredentialAttributeContentData();
        cad.setName("cred");
        cad.setAttributes(List.of(inner));
        ResponseAttributeV2 ra = new ResponseAttributeV2();
        ra.setName("credAttr");
        ra.setContent(List.of(new CredentialAttributeContentV2("r", cad)));
        ResourceSimpleContentData blob = new ResourceSimpleContentData(AttributeResource.CREDENTIAL);
        blob.setAttributes(List.of(ra));

        Set<String> expandedSecrets = new HashSet<>();
        containment.recordExpandedSecrets(blob, expandedSecrets);
        assertTrue(expandedSecrets.contains("deep-secret"),
                "a secret nested through credential/data wrappers must be recorded");
    }

    @Test
    void allowsArrayOfHarmlessContent() {
        Object[] response = new Object[]{new ResourceSimpleContentData(AttributeResource.AUTHORITY)};
        assertDoesNotThrow(() -> containment.assertNoExpandedSecretOutbound(response, new HashSet<>()));
    }

    @Test
    void rejectsBarePopulatedSecretAttributeContentData() {
        Object response = List.of(new SecretAttributeContentData("bare-secret"));
        assertThrows(OutboundSecretLeakException.class,
                () -> containment.assertNoExpandedSecretOutbound(response, new HashSet<>()));
    }

    @Test
    void nullResponseAndNullExpandedSetAreNoOps() {
        assertDoesNotThrow(() -> containment.assertNoExpandedSecretOutbound(null, new HashSet<>()));
        // null sink must short-circuit without NPE
        assertDoesNotThrow(() -> containment
                .recordExpandedSecrets(new ResourceSecretContentData("u", "n", new ApiKeySecretContent("x")), null));
    }

    @Test
    void doesNotRecordResourceSecretContentDataWithNullContent() {
        Set<String> expandedSecrets = new HashSet<>();
        containment.recordExpandedSecrets(new ResourceSecretContentData(), expandedSecrets);
        assertTrue(expandedSecrets.isEmpty(), "a bare secret reference (no inline content) records nothing");
    }

    @Test
    void recordsSecretFieldButNotLowEntropyIdentifier() {
        // Basic-auth: password is the secret, username is a low-entropy identifier. Recording the username as an
        // echo needle would false-positive a benign response that legitimately echoes the username.
        Set<String> expandedSecrets = new HashSet<>();
        containment
                .recordExpandedSecrets(new ResourceSecretContentData("u", "n",
                        new com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent("alice", "s3cr3t-pw")),
                        expandedSecrets);
        assertTrue(expandedSecrets.contains("s3cr3t-pw"), "the password is the secret and must be recorded");
        assertEquals(Set.of("s3cr3t-pw"), expandedSecrets, "the username must NOT be recorded as an echo needle");
    }

    @Test
    void structuralCheckFailsClosedWhenResponseTooDeeplyNested() {
        // A secret-bearing shape buried beyond MAX_WALK_DEPTH must be REFUSED (fail-closed), not waved through.
        Object deep = new ResourceSecretContentData("u", "n", new ApiKeySecretContent("buried-secret"));
        for (int i = 0; i < 13; i++) {
            deep = List.of(deep);
        }
        final Object payload = deep;
        assertThrows(OutboundSecretLeakException.class,
                () -> containment.assertNoExpandedSecretOutbound(payload, new HashSet<>()));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ObjectAttributeContent storedRow(String name, String encryptedContent) {
        return new ObjectAttributeContent(UUID.randomUUID(), name, name, AttributeType.DATA,
                AttributeContentType.STRING, new StringAttributeContentV2(), 2, encryptedContent);
    }

    /** Decryption returns a protected row's data in a base content, whatever the content type. */
    private static BaseAttributeContentV2<Serializable> decryptedContent(Serializable data) {
        return new BaseAttributeContentV2<>(null, data);
    }

    /** A credential attribute as its expansion returns it, decrypted whatever its protection level. */
    private static DataAttributeV2 credentialAttribute(String name, ProtectionLevel protectionLevel, String value) {
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setProtectionLevel(protectionLevel);
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setProperties(properties);
        attribute.setContent(List.of(decryptedContent(value)));
        return attribute;
    }

    private static CredentialAttributeContentV2 credentialHolding(DataAttributeV2 attribute) {
        CredentialAttributeContentData credential = new CredentialAttributeContentData();
        credential.setName("hsm-login");
        credential.setAttributes(List.of(attribute));
        return new CredentialAttributeContentV2("hsm-login", credential);
    }

    private static FileAttributeContentData fileData(String content, String fileName, String mimeType) {
        FileAttributeContentData data = new FileAttributeContentData();
        data.setContent(content);
        data.setFileName(fileName);
        data.setMimeType(mimeType);
        return data;
    }

    /** The attribute that resolving a stored row sends, which keeps the row's definition UUID and name. */
    private static RequestAttribute resolvedFrom(ObjectAttributeContent row, BaseAttributeContentV2<?> content) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(row.uuid());
        attribute.setName(row.name());
        attribute.setContent(List.of(content));
        return attribute;
    }

    private static RequestAttribute resolvedAttribute(String name, BaseAttributeContentV2<?> content) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setName(name);
        attribute.setContent(List.of(content));
        return attribute;
    }
}
