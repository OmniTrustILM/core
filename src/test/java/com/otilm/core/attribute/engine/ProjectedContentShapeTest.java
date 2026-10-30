package com.otilm.core.attribute.engine;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.CredentialAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.FileAttributeContentData;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceCertificateContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.connector.secrets.content.ApiKeySecretContent;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The shape one attribute value is projected in. A list cell renders a single line, so a content type whose value can
 * carry more than the cell shows must not be serialized whole into a listing: some because they can carry secret or
 * unbounded material, one because of its size.
 */
class ProjectedContentShapeTest {

    private static final ObjectMapper MAPPER = ObjectMapperFactory.attributeContent();

    private static <T extends Serializable> BaseAttributeContentV3<T> content(AttributeContentType contentType,
            String reference, T data) {
        BaseAttributeContentV3<T> value = new BaseAttributeContentV3<>();
        value.setContentType(contentType);
        value.setReference(reference);
        value.setData(data);
        return value;
    }

    /**
     * A value as it comes back from storage under the version 2 contract: the persisted json carries no
     * {@code contentType} for the polymorphic reader to key on, so the reader binds an unresolved type variable and the
     * data arrives as a map rather than as its content class.
     */
    private static BaseAttributeContentV3<Serializable> versionTwoContent(AttributeContentType contentType,
            String reference, Map<String, Object> data) {
        return content(contentType, reference, new LinkedHashMap<>(data));
    }

    private static String projectedJson(BaseAttributeContentV3<?> value, AttributeContentType contentType)
            throws JsonProcessingException {
        return MAPPER.writeValueAsString(AttributeColumnProjector.toProjectedValue(value, contentType));
    }

    @Test
    void credentialContentIsProjectedAsItsReferenceAlone() {
        CredentialAttributeContentData credential = new CredentialAttributeContentData();
        credential.setUuid("f0e3c0a4-0000-0000-0000-000000000001");
        credential.setName("vault-token");
        credential.setAttributes(List.of());

        BaseAttributeContentV3<?> projected = AttributeColumnProjector
                .toProjectedValue(content(AttributeContentType.CREDENTIAL, "vault-token", credential),
                        AttributeContentType.CREDENTIAL);

        // The nested attribute list can carry secret-bearing content, and the cell shows the reference.
        Assertions.assertNull(projected.getData());
        Assertions.assertEquals("vault-token", projected.getReference());
        Assertions.assertEquals(AttributeContentType.CREDENTIAL, projected.getContentType());
    }

    @Test
    void objectContentIsProjectedAsItsReferenceAlone() {
        // Object data has no declared shape at all, and the cell shows the reference.
        BaseAttributeContentV3<?> projected = AttributeColumnProjector
                .toProjectedValue(content(AttributeContentType.OBJECT, "pipeline-42",
                        new LinkedHashMap<>(Map.of("apiToken", "s3cr3t"))), AttributeContentType.OBJECT);

        Assertions.assertNull(projected.getData());
        Assertions.assertEquals("pipeline-42", projected.getReference());
    }

    @Test
    void fileContentIsProjectedWithoutItsBody() {
        FileAttributeContentData file = new FileAttributeContentData();
        file.setFileName("chain.pem");
        file.setMimeType("application/x-pem-file");
        file.setContent("dGhlIHdob2xlIGZpbGUgYm9keQ==");

        BaseAttributeContentV3<?> projected = AttributeColumnProjector
                .toProjectedValue(content(AttributeContentType.FILE, "chain.pem", file), AttributeContentType.FILE);

        FileAttributeContentData data = (FileAttributeContentData) projected.getData();
        Assertions.assertEquals("chain.pem", data.getFileName());
        Assertions.assertEquals("application/x-pem-file", data.getMimeType());
        // A page of rows would otherwise serialize the body of every file it lists, which no cell shows.
        Assertions.assertNull(data.getContent());
    }

    @Test
    void aVersionTwoFileValueIsProjectedWithoutItsBody() throws JsonProcessingException {
        // The typed content class never arrives on this path, so a reduction that only recognised it would carry the
        // whole body through.
        String json = projectedJson(versionTwoContent(AttributeContentType.FILE, "chain.pem",
                Map
                        .of("fileName", "chain.pem", "mimeType", "application/x-pem-file", "content",
                                "dGhlIHdob2xlIGZpbGUgYm9keQ==")),
                AttributeContentType.FILE);

        Assertions.assertTrue(json.contains("chain.pem"), json);
        Assertions.assertTrue(json.contains("application/x-pem-file"), json);
        Assertions.assertFalse(json.contains("dGhlIHdob2xlIGZpbGUgYm9keQ=="), json);
    }

    @Test
    void aFileValueOfAnUnrecognisedShapeCarriesNoData() {
        BaseAttributeContentV3<?> projected = AttributeColumnProjector
                .toProjectedValue(content(AttributeContentType.FILE, "chain.pem", "not file data"),
                        AttributeContentType.FILE);

        // Dropped rather than passed on: an unrecognised shape cannot be shown to hold nothing but a name and a type.
        Assertions.assertNull(projected.getData());
        Assertions.assertEquals("chain.pem", projected.getReference());
    }

    @Test
    void aResourceCertificateIsProjectedWithoutItsBody() throws JsonProcessingException {
        ResourceCertificateContentData certificate = new ResourceCertificateContentData(
                "f0e3c0a4-0000-0000-0000-000000000002", "issuing-ca", CertificateType.X509, "MIIB...whole body");

        String json = projectedJson(content(AttributeContentType.RESOURCE, "issuing-ca", certificate),
                AttributeContentType.RESOURCE);

        Assertions.assertTrue(json.contains("issuing-ca"), json);
        Assertions.assertTrue(json.contains("f0e3c0a4-0000-0000-0000-000000000002"), json);
        Assertions.assertFalse(json.contains("MIIB...whole body"), json);
    }

    @Test
    void aResourceSecretIsProjectedWithoutItsContent() throws JsonProcessingException {
        ResourceSecretContentData secret = new ResourceSecretContentData("f0e3c0a4-0000-0000-0000-000000000003",
                "db-password", new ApiKeySecretContent("the-api-key"));

        String json = projectedJson(content(AttributeContentType.RESOURCE, "db-password", secret),
                AttributeContentType.RESOURCE);

        Assertions.assertTrue(json.contains("db-password"), json);
        Assertions.assertFalse(json.contains("the-api-key"), json);
        Assertions.assertFalse(json.contains("\"content\""), json);
    }

    @Test
    void aResourceObjectIsProjectedWithoutItsNestedAttributes() throws JsonProcessingException {
        ResourceSimpleContentData authority = new ResourceSimpleContentData(AttributeResource.AUTHORITY,
                "f0e3c0a4-0000-0000-0000-000000000004", "main-authority", List.of());

        String json = projectedJson(content(AttributeContentType.RESOURCE, "main-authority", authority),
                AttributeContentType.RESOURCE);

        Assertions.assertTrue(json.contains("main-authority"), json);
        Assertions.assertTrue(json.contains(AttributeResource.AUTHORITY.getCode()), json);
        Assertions.assertFalse(json.contains("\"attributes\""), json);
    }

    @Test
    void aResourceValueKeepsTheIdentityFieldsTheCellRenders() {
        ResourceCertificateContentData certificate = new ResourceCertificateContentData(
                "f0e3c0a4-0000-0000-0000-000000000005", "issuing-ca", CertificateType.X509, "MIIB...whole body");

        ResourceObjectContentData projected = (ResourceObjectContentData) AttributeColumnProjector
                .toProjectedValue(content(AttributeContentType.RESOURCE, "issuing-ca", certificate),
                        AttributeContentType.RESOURCE)
                .getData();

        // The cell links to the object, labelled by its name - which needs all three and nothing else.
        Assertions.assertEquals(AttributeResource.CERTIFICATE, projected.getResource());
        Assertions.assertEquals("f0e3c0a4-0000-0000-0000-000000000005", projected.getUuid());
        Assertions.assertEquals("issuing-ca", projected.getName());
    }

    @Test
    void aVersionTwoResourceValueIsProjectedAsItsIdentityAlone() throws JsonProcessingException {
        String json = projectedJson(versionTwoContent(AttributeContentType.RESOURCE, "issuing-ca",
                Map
                        .of("resource", "certificates", "uuid", "f0e3c0a4-0000-0000-0000-000000000006", "name",
                                "issuing-ca", "content", "MIIB...whole body")),
                AttributeContentType.RESOURCE);

        Assertions.assertTrue(json.contains("issuing-ca"), json);
        Assertions.assertFalse(json.contains("MIIB...whole body"), json);
    }

    @ParameterizedTest
    @EnumSource(value = AttributeContentType.class, mode = EnumSource.Mode.EXCLUDE,
            names = {"CREDENTIAL", "FILE", "OBJECT", "RESOURCE"})
    void everyOtherContentTypeIsProjectedUnchanged(AttributeContentType contentType) {
        BaseAttributeContentV3<String> value = content(contentType, "reference", "data");

        Assertions.assertSame(value, AttributeColumnProjector.toProjectedValue(value, contentType));
    }
}
