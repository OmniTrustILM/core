package com.otilm.core.integration.search;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.SearchColumnRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.cryptography.CryptographicKeyResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyItemListDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Projection of attribute-sourced columns into the key listing, which is the one listing whose entries do not own their
 * attributes: several items share one key, so a key's own attributes hang off the key while its metadata hangs off each
 * individual item. The two therefore resolve from different uuids, and a value belonging to one item must not land on
 * its siblings.
 */
class KeyAttributeColumnProjectionITest extends BaseSpringBootTest {

    private static final String ENVIRONMENT = "environment";
    private static final String SLOT = "slot";

    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;

    @Autowired
    private CryptographicKeySeeder keySeeder;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private AttributeEngine attributeEngine;

    private Connector connector;
    private CryptographicKey key;
    private CryptographicKeyItem privateKeyItem;
    private CryptographicKeyItem publicKeyItem;

    @BeforeEach
    void loadData() throws Exception {
        connector = new Connector();
        connector.setName("key-projection-connector");
        connector.setUrl("http://localhost:0/key-projection");
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.saveAndFlush(connector);

        TokenInstanceReference tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setName("key-projection-token");
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReference.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstanceReference);

        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("key-projection-profile");
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setTokenInstanceName("key-projection-token");
        tokenProfile.setEnabled(true);
        tokenProfileRepository.saveAndFlush(tokenProfile);

        key = keySeeder
                .seedKey("projected-key", tokenProfile, tokenInstanceReference,
                        KeyItemSpec.signingPrivateKey(KeyAlgorithm.RSA),
                        KeyItemSpec.verifyingPublicKey(KeyAlgorithm.RSA));

        List<CryptographicKeyItem> items = key
                .getItems()
                .stream()
                .sorted(Comparator.comparing(item -> item.getType().getCode()))
                .toList();
        privateKeyItem = items.getFirst();
        publicKeyItem = items.getLast();

        UUID environmentUuid = registerCustomAttribute();
        // A key's own custom attributes hang off the key, so both listed items carry them.
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(),
                        List.of(customContent(environmentUuid, "production")));

        // Metadata hangs off each item, so each carries only its own.
        storeSlotMetadata(privateKeyItem.getUuid(), "slot-1");
        storeSlotMetadata(publicKeyItem.getUuid(), "slot-2");
    }

    private UUID registerCustomAttribute() throws Exception {
        CustomAttributeV3 attribute = new CustomAttributeV3();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(ENVIRONMENT);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(AttributeContentType.TEXT);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Environment");
        attribute.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(attribute, List.of(Resource.CRYPTOGRAPHIC_KEY));
        return UUID.fromString(attribute.getUuid());
    }

    private static RequestAttributeV3 customContent(UUID uuid, String value) {
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(uuid);
        requestAttribute.setName(ENVIRONMENT);
        List<BaseAttributeContentV3<?>> content = new ArrayList<>();
        content.add(new TextAttributeContentV3(null, value));
        requestAttribute.setContent(content);
        return requestAttribute;
    }

    private void storeSlotMetadata(UUID keyItemUuid, String value) throws AttributeException {
        MetadataAttributeV3 meta = new MetadataAttributeV3();
        meta.setUuid(UUID.randomUUID().toString());
        meta.setName(SLOT);
        meta.setType(AttributeType.META);
        meta.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Slot");
        properties.setVisible(true);
        properties.setGlobal(false);
        meta.setProperties(properties);
        meta.setContent(List.of(new StringAttributeContentV3(value)));
        attributeEngine
                .updateMetadataAttribute(meta,
                        ObjectAttributeContentInfo
                                .builder(Resource.CRYPTOGRAPHIC_KEY, keyItemUuid)
                                .connector(connector.getUuid())
                                .build());
    }

    private static String fieldIdentifier(String attributeName, AttributeContentType contentType) {
        return attributeName + "|" + contentType.name();
    }

    private List<KeyItemListDto> list() {
        SearchRequestDto request = new SearchRequestDto();
        request
                .setColumns(List
                        .of(new SearchColumnRequestDto(FilterFieldSource.CUSTOM,
                                fieldIdentifier(ENVIRONMENT, AttributeContentType.TEXT)),
                                new SearchColumnRequestDto(FilterFieldSource.META,
                                        fieldIdentifier(SLOT, AttributeContentType.STRING))));
        CryptographicKeyResponseDto response = cryptographicKeyService
                .listCryptographicKeys(SecurityFilter.create(), request);
        return response.getCryptographicKeys();
    }

    private KeyItemListDto entry(List<KeyItemListDto> items, CryptographicKeyItem keyItem) {
        return items
                .stream()
                .filter(item -> item.getUuid().equals(keyItem.getUuid().toString()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Key item %s is not on the page".formatted(keyItem.getUuid())));
    }

    private static Object value(KeyItemListDto item, FilterFieldSource source, String fieldIdentifier) {
        Map<String, List<BaseAttributeContentV3<?>>> bySource = item.getAttributeValues().get(source);
        Assertions.assertNotNull(bySource, "no %s values on %s".formatted(source, item.getUuid()));
        List<BaseAttributeContentV3<?>> values = bySource.get(fieldIdentifier);
        Assertions.assertNotNull(values, "no %s values on %s".formatted(fieldIdentifier, item.getUuid()));
        Assertions.assertEquals(1, values.size());
        return values.getFirst().getData();
    }

    @Test
    void aKeysOwnAttributeIsProjectedOntoEveryItemThatSharesIt() {
        List<KeyItemListDto> items = list();

        String environment = fieldIdentifier(ENVIRONMENT, AttributeContentType.TEXT);
        Assertions
                .assertEquals("production", value(entry(items, privateKeyItem), FilterFieldSource.CUSTOM, environment));
        Assertions
                .assertEquals("production", value(entry(items, publicKeyItem), FilterFieldSource.CUSTOM, environment));
    }

    @Test
    void eachItemsMetadataIsProjectedOntoThatItemAlone() {
        List<KeyItemListDto> items = list();

        // Resolved from the item uuid rather than the key's: a value belonging to one item must not land on a sibling
        // that shares the key with it.
        String slot = fieldIdentifier(SLOT, AttributeContentType.STRING);
        Assertions.assertEquals("slot-1", value(entry(items, privateKeyItem), FilterFieldSource.META, slot));
        Assertions.assertEquals("slot-2", value(entry(items, publicKeyItem), FilterFieldSource.META, slot));
    }

    @Test
    void bothSourcesLandOnTheSameEntry() {
        // The two sources resolve from different uuids, so they are collected in two passes; the second must add to
        // what the first found rather than replace it.
        KeyItemListDto item = entry(list(), privateKeyItem);

        Assertions
                .assertEquals("production",
                        value(item, FilterFieldSource.CUSTOM, fieldIdentifier(ENVIRONMENT, AttributeContentType.TEXT)));
        Assertions
                .assertEquals("slot-1",
                        value(item, FilterFieldSource.META, fieldIdentifier(SLOT, AttributeContentType.STRING)));
    }
}
