package com.otilm.core.integration.search;

import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyItemDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
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
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Ordering the key listing by an attribute: a key's custom attributes hang off the key, so both of its items take its
 * key; metadata hangs off each item, so each item takes its own.
 */
class KeyAttributeSortITest extends BaseSpringBootTest {

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
    private CryptographicKey production;
    private CryptographicKey staging;

    @BeforeEach
    void loadData() throws Exception {
        connector = new Connector();
        connector.setName("key-sort-connector");
        connector.setUrl("http://localhost:0/key-sort");
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.saveAndFlush(connector);

        TokenInstanceReference tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setName("key-sort-token");
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReference.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstanceReference);

        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("key-sort-profile");
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setTokenInstanceName("key-sort-token");
        tokenProfile.setEnabled(true);
        tokenProfileRepository.saveAndFlush(tokenProfile);

        // Seeded so the value order is the reverse of the creation order: the listing falls back to newest first, so
        // a sort that never reached the query lists the staging key first.
        production = keySeeder
                .seedKey("production-key", tokenProfile, tokenInstanceReference,
                        KeyItemSpec.signingPrivateKey(KeyAlgorithm.RSA),
                        KeyItemSpec.verifyingPublicKey(KeyAlgorithm.RSA));
        staging = keySeeder
                .seedKey("staging-key", tokenProfile, tokenInstanceReference,
                        KeyItemSpec.signingPrivateKey(KeyAlgorithm.RSA),
                        KeyItemSpec.verifyingPublicKey(KeyAlgorithm.RSA));

        UUID environment = registerEnvironment();
        storeEnvironment(environment, production, "production");
        storeEnvironment(environment, staging, "staging");
    }

    /** Custom attributes are the key's: both of a key's items sort together, by the key's value. */
    @Test
    void itemsSortByTheirKeysCustomAttribute() {
        List<String> keys = list(FilterFieldSource.CUSTOM, ENVIRONMENT + "|" + AttributeContentType.TEXT.name())
                .stream()
                .map(KeyItemDto::getKeyWrapperUuid)
                .toList();

        Assertions
                .assertEquals(List
                        .of(production.getUuid().toString(), production.getUuid().toString(),
                                staging.getUuid().toString(), staging.getUuid().toString()),
                        keys);
    }

    /** Metadata is the item's: the items of one key can sort apart. */
    @Test
    void itemsSortByTheirOwnMetadata() throws Exception {
        List<CryptographicKeyItem> productionItems = production
                .getItems()
                .stream()
                .sorted(Comparator.comparing(item -> item.getType().getCode()))
                .toList();
        storeSlot(productionItems.getFirst(), "slot-9");
        storeSlot(productionItems.getLast(), "slot-1");
        for (CryptographicKeyItem item : staging.getItems()) {
            storeSlot(item, "slot-5");
        }

        List<String> items = list(FilterFieldSource.META, SLOT + "|" + AttributeContentType.STRING.name())
                .stream()
                .map(KeyItemDto::getUuid)
                .toList();

        Assertions.assertEquals(productionItems.getLast().getUuid().toString(), items.getFirst());
        Assertions.assertEquals(productionItems.getFirst().getUuid().toString(), items.getLast());
    }

    private UUID registerEnvironment() throws Exception {
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

    private void storeEnvironment(UUID definition, CryptographicKey key, String value) throws Exception {
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(definition);
        requestAttribute.setName(ENVIRONMENT);
        requestAttribute.setContent(List.of(new TextAttributeContentV3(null, value)));
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(),
                        List.of(requestAttribute));
    }

    private void storeSlot(CryptographicKeyItem item, String value) throws Exception {
        MetadataAttributeV3 meta = new MetadataAttributeV3();
        // One definition for every item: the metadata write resolves the definition by its uuid.
        meta.setUuid(UUID.nameUUIDFromBytes(SLOT.getBytes()).toString());
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
                                .builder(Resource.CRYPTOGRAPHIC_KEY, item.getUuid())
                                .connector(connector.getUuid())
                                .build());
    }

    private List<KeyItemDto> list(FilterFieldSource source, String fieldIdentifier) {
        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        request.setSort(new SearchSortRequestDto(source, fieldIdentifier, SortDirection.ASC));
        return cryptographicKeyService.listCryptographicKeys(SecurityFilter.create(), request).getCryptographicKeys();
    }
}
