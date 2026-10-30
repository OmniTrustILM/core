package com.otilm.core.mapper.notifications;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.attribute.ResponseAttributeV2;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.metadata.MetadataResponseDto;
import com.otilm.api.model.client.metadata.ResponseMetadata;
import com.otilm.api.model.client.metadata.ResponseMetadataV3;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.connector.notification.NotificationAssociationDto;
import com.otilm.api.model.connector.notification.NotificationAttributeDto;
import com.otilm.api.model.connector.notification.NotificationEventObjectDataDto;
import com.otilm.api.model.connector.notification.NotificationMetadataGroupDto;
import com.otilm.api.model.connector.notification.NotificationObjectContentDto;
import com.otilm.api.model.core.auth.Resource;
import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NotificationObjectDataMapperTest {

    private static final UUID UUID_1 = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID UUID_2 = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID UUID_3 = UUID.fromString("00000000-0000-0000-0000-000000000003");

    // --- custom attributes ---

    @Test
    void scalarTypesContributeRawData() {
        Map<String, NotificationAttributeDto> mapped = NotificationObjectDataMapper
                .mapCustomAttributes(
                        List
                                .of(custom(UUID_1, "department", AttributeContentType.STRING, content("E-Commerce")),
                                        custom(UUID_2, "port", AttributeContentType.INTEGER, content(443)),
                                        custom(UUID_3, "active", AttributeContentType.BOOLEAN, content(Boolean.TRUE))),
                        Set.of());

        assertEquals(List.of("E-Commerce"), mapped.get("department").getValues());
        assertEquals(List.of(443), mapped.get("port").getValues());
        assertEquals(List.of(Boolean.TRUE), mapped.get("active").getValues());
        assertEquals("Label department", mapped.get("department").getLabel());
        assertEquals(AttributeContentType.STRING, mapped.get("department").getContentType());
    }

    @Test
    void secretBearingTypesAreUnconditionallyExcluded() {
        Map<String, NotificationAttributeDto> mapped = NotificationObjectDataMapper
                .mapCustomAttributes(
                        List
                                .of(custom(UUID_1, "apiKey", AttributeContentType.SECRET, content("s3cret")),
                                        custom(UUID_2, "creds", AttributeContentType.CREDENTIAL, content("token")),
                                        custom(UUID_3, "plain", AttributeContentType.STRING, content("visible"))),
                        Set.of());

        assertEquals(Set.of("plain"), mapped.keySet());
    }

    @Test
    void excludedDefinitionsAreFilteredOut() {
        Map<String, NotificationAttributeDto> mapped = NotificationObjectDataMapper
                .mapCustomAttributes(List
                        .of(custom(UUID_1, "protected", AttributeContentType.STRING, content("decrypted-secret")),
                                custom(UUID_2, "plain", AttributeContentType.STRING, content("visible"))),
                        Set.of(UUID_1));

        assertEquals(Set.of("plain"), mapped.keySet());
    }

    @Test
    void complexTypesContributeReferenceOnlyAndReferencelessEntriesAreOmitted() {
        BaseAttributeContentV3<Serializable> withReference = new BaseAttributeContentV3<>("P1 - 24x7 pager",
                (Serializable) Map.of("nested", "structure"));
        BaseAttributeContentV3<Serializable> withoutReference = new BaseAttributeContentV3<>(null,
                (Serializable) Map.of("other", "structure"));
        BaseAttributeContentV3<Serializable> blankReference = new BaseAttributeContentV3<>("  ",
                (Serializable) Map.of("third", "structure"));

        Map<String, NotificationAttributeDto> mapped = NotificationObjectDataMapper
                .mapCustomAttributes(List
                        .of(customWithContent(UUID_1, "escalation", AttributeContentType.OBJECT,
                                List.of(withReference, withoutReference, blankReference)),
                                customWithContent(UUID_2, "emptyObject", AttributeContentType.OBJECT,
                                        List.of(withoutReference))),
                        Set.of());

        assertEquals(List.of("P1 - 24x7 pager"), mapped.get("escalation").getValues());
        assertFalse(mapped.containsKey("emptyObject"), "an attribute with no extractable values is omitted");
    }

    @Test
    void duplicateCustomNameFirstWinsInUuidOrder() {
        Map<String, NotificationAttributeDto> mapped = NotificationObjectDataMapper
                .mapCustomAttributes(
                        List
                                .of(custom(UUID_2, "department", AttributeContentType.STRING, content("second")),
                                        custom(UUID_1, "department", AttributeContentType.STRING, content("first"))),
                        Set.of());

        assertEquals(List.of("first"), mapped.get("department").getValues(),
                "the definition with the lowest attribute UUID wins deterministically");
    }

    @Test
    void v2ContentExtractsLikeV3() {
        BaseAttributeContentV2<String> v2Content = new BaseAttributeContentV2<>();
        v2Content.setData("legacy-value");
        ResponseAttributeV2 attribute = new ResponseAttributeV2();
        attribute.setUuid(UUID_1);
        attribute.setName("legacy");
        attribute.setLabel("Legacy");
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(v2Content));

        Map<String, NotificationAttributeDto> mapped = NotificationObjectDataMapper
                .mapCustomAttributes(List.of(attribute), Set.of());

        assertEquals(List.of("legacy-value"), mapped.get("legacy").getValues());
    }

    @Test
    void longStringValuesAreTruncatedWithSuffix() {
        String longValue = "x".repeat(NotificationObjectDataMapper.MAX_VALUE_LENGTH + 100);
        Map<String, NotificationAttributeDto> mapped = NotificationObjectDataMapper
                .mapCustomAttributes(List
                        .of(custom(UUID_1, "big", AttributeContentType.TEXT, content(longValue)),
                                custom(UUID_2, "number", AttributeContentType.INTEGER, content(42))),
                        Set.of());

        String truncated = (String) mapped.get("big").getValues().getFirst();
        assertEquals(
                NotificationObjectDataMapper.MAX_VALUE_LENGTH + NotificationObjectDataMapper.TRUNCATION_SUFFIX.length(),
                truncated.length());
        assertTrue(truncated.endsWith(NotificationObjectDataMapper.TRUNCATION_SUFFIX));
        assertEquals(42, mapped.get("number").getValues().getFirst(), "non-string scalars are never truncated");
    }

    @Test
    void nullAndEmptyInputsYieldEmptyOutputs() {
        assertTrue(NotificationObjectDataMapper.mapCustomAttributes(null, Set.of()).isEmpty());
        assertTrue(NotificationObjectDataMapper.mapCustomAttributes(List.of(), Set.of()).isEmpty());
        assertTrue(NotificationObjectDataMapper.mapMetadata(null, Set.of()).isEmpty());
        assertTrue(NotificationObjectDataMapper.mapMetadata(List.of(), Set.of()).isEmpty());
    }

    // --- metadata ---

    @Test
    void metadataKeepsConnectorAndSourceTypeGrouping() {
        MetadataResponseDto discoveryGroup = group("Network-Discovery", Resource.DISCOVERY,
                meta(UUID_1, "discoverySource", AttributeContentType.STRING, List.of(content("10.20.30.0/24")),
                        List.of(source(UUID_2, "weekly-sweep"))));
        MetadataResponseDto authorityGroup = group("ACME-Server", Resource.AUTHORITY,
                meta(UUID_3, "discoverySource", AttributeContentType.STRING, List.of(content("acme-directory")),
                        List.of(source(UUID_1, "acme-prod-ca"))));

        List<NotificationMetadataGroupDto> mapped = NotificationObjectDataMapper
                .mapMetadata(List.of(discoveryGroup, authorityGroup), Set.of());

        assertEquals(2, mapped.size());
        assertEquals("Network-Discovery", mapped.get(0).getConnectorName());
        assertEquals(Resource.DISCOVERY, mapped.get(0).getSourceObjectType());
        assertEquals(List.of("10.20.30.0/24"), mapped.get(0).getAttributes().get("discoverySource").getValues());
        assertEquals("ACME-Server", mapped.get(1).getConnectorName());
        assertEquals(List.of("acme-directory"), mapped.get(1).getAttributes().get("discoverySource").getValues());
    }

    @Test
    void sameNameMetadataInOneGroupMergesValuesAndSources() {
        // The same connector re-declared the attribute over time: two definition UUIDs, one name.
        MetadataResponseDto group = group("Network-Discovery", Resource.DISCOVERY,
                meta(UUID_2, "port", AttributeContentType.INTEGER, List.of(content(443), content(8443)),
                        List.of(source(UUID_1, "sweep-a"))),
                meta(UUID_1, "port", AttributeContentType.INTEGER, List.of(content(443)),
                        List.of(source(UUID_3, "sweep-b"))));

        List<NotificationMetadataGroupDto> mapped = NotificationObjectDataMapper.mapMetadata(List.of(group), Set.of());

        NotificationAttributeDto merged = mapped.getFirst().getAttributes().get("port");
        assertEquals(List.of(443, 8443), merged.getValues(),
                "values are the deduplicated union in attribute-UUID order");
        assertEquals(2, merged.getSourceObjects().size(), "source objects are the union of contributors");
        assertEquals("sweep-b", merged.getSourceObjects().getFirst().getName(),
                "the lower attribute UUID contributes first");
    }

    @Test
    void conflictingContentTypeRedeclarationIsExcluded() {
        MetadataResponseDto group = group("Network-Discovery", Resource.DISCOVERY,
                meta(UUID_1, "port", AttributeContentType.INTEGER, List.of(content(443)), List.of()),
                meta(UUID_2, "port", AttributeContentType.STRING, List.of(content("https")), List.of()));

        List<NotificationMetadataGroupDto> mapped = NotificationObjectDataMapper.mapMetadata(List.of(group), Set.of());

        NotificationAttributeDto merged = mapped.getFirst().getAttributes().get("port");
        assertEquals(AttributeContentType.INTEGER, merged.getContentType());
        assertEquals(List.of(443), merged.getValues(), "the conflicting re-declaration contributes nothing");
    }

    @Test
    void metadataGroupWithOnlyExcludedItemsIsOmitted() {
        MetadataResponseDto group = group("Vault", Resource.CREDENTIAL,
                meta(UUID_1, "apiKey", AttributeContentType.SECRET, List.of(content("s3cret")), List.of()));

        assertTrue(NotificationObjectDataMapper.mapMetadata(List.of(group), Set.of()).isEmpty());
    }

    // --- total cap ---

    @Test
    void totalCapDropsCategoriesInDeterministicOrder() {
        ObjectMapper wireMapper = new ObjectMapper();
        NotificationEventObjectDataDto objectData = boundedFixture(200_000, 200_000, 200_000);

        NotificationObjectDataMapper.applyTotalCap(objectData, wireMapper);

        assertNull(objectData.getMetadata(), "metadata drops first");
        assertNull(objectData.getCustomAttributes(), "custom attributes drop second");
        assertNull(objectData.getContent(), "object content drops third");
        assertNotNull(objectData.getAssociations(), "associations survive when the rest sufficed");
        assertNotNull(objectData.getSubject(), "the subject is never dropped");
    }

    @Test
    void totalCapKeepsEverythingThatFits() {
        ObjectMapper wireMapper = new ObjectMapper();
        NotificationEventObjectDataDto objectData = boundedFixture(100, 100, 100);

        NotificationObjectDataMapper.applyTotalCap(objectData, wireMapper);

        assertNotNull(objectData.getMetadata());
        assertNotNull(objectData.getCustomAttributes());
        assertNotNull(objectData.getContent());
        assertNotNull(objectData.getAssociations());
    }

    // --- fixtures ---

    private static BaseAttributeContentV3<?> content(Serializable data) {
        return new BaseAttributeContentV3<>(null, data);
    }

    private static ResponseAttributeV3 custom(UUID uuid, String name, AttributeContentType contentType,
            BaseAttributeContentV3<?> content) {
        return customWithContent(uuid, name, contentType, List.of(content));
    }

    private static ResponseAttributeV3 customWithContent(UUID uuid, String name, AttributeContentType contentType,
            List<BaseAttributeContentV3<?>> content) {
        ResponseAttributeV3 attribute = new ResponseAttributeV3();
        attribute.setUuid(uuid);
        attribute.setName(name);
        attribute.setLabel("Label " + name);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(contentType);
        attribute.setContent(content);
        return attribute;
    }

    private static ResponseMetadataV3 meta(UUID uuid, String name, AttributeContentType contentType,
            List<BaseAttributeContentV3<?>> content, List<NameAndUuidDto> sources) {
        return new ResponseMetadataV3(sources, uuid, name, "Label " + name, AttributeType.META, contentType, content);
    }

    private static MetadataResponseDto group(String connectorName, Resource sourceType, ResponseMetadata... items) {
        MetadataResponseDto group = new MetadataResponseDto();
        group.setConnectorName(connectorName);
        group.setSourceObjectType(sourceType);
        group.setItems(List.of(items));
        return group;
    }

    private static NameAndUuidDto source(UUID uuid, String name) {
        return new NameAndUuidDto(uuid.toString(), name);
    }

    private static NotificationEventObjectDataDto boundedFixture(int metadataBytes, int customBytes, int contentBytes) {
        NotificationEventObjectDataDto objectData = new NotificationEventObjectDataDto();

        NotificationAssociationDto subject = new NotificationAssociationDto();
        subject.setResource(Resource.CERTIFICATE);
        subject.setUuid(UUID_1.toString());
        subject.setName("shop.acme.example");
        objectData.setSubject(subject);
        objectData.setAssociations(List.of(subject));

        NotificationAttributeDto customAttribute = new NotificationAttributeDto();
        customAttribute.setName("big");
        customAttribute.setContentType(AttributeContentType.TEXT);
        customAttribute.setValues(List.of("c".repeat(customBytes)));
        objectData.setCustomAttributes(Map.of("big", customAttribute));

        NotificationAttributeDto metadataAttribute = new NotificationAttributeDto();
        metadataAttribute.setName("bulk");
        metadataAttribute.setContentType(AttributeContentType.TEXT);
        metadataAttribute.setValues(List.of("m".repeat(metadataBytes)));
        NotificationMetadataGroupDto metadataGroup = new NotificationMetadataGroupDto();
        metadataGroup.setConnectorName("Bulk-Connector");
        metadataGroup.setSourceObjectType(Resource.DISCOVERY);
        metadataGroup.setAttributes(Map.of("bulk", metadataAttribute));
        objectData.setMetadata(List.of(metadataGroup));

        NotificationObjectContentDto content = new NotificationObjectContentDto();
        content.setFormat("X509_DER_BASE64");
        content.setData("d".repeat(contentBytes));
        objectData.setContent(content);

        return objectData;
    }
}
