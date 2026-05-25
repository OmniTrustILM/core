package com.czertainly.core.service;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.cryptography.key.BulkCompromiseKeyItemRequestDto;
import com.czertainly.api.model.client.cryptography.key.BulkKeyItemUsageRequestDto;
import com.czertainly.api.model.client.cryptography.key.EditKeyItemDto;
import com.czertainly.api.model.client.cryptography.key.EditKeyRequestDto;
import com.czertainly.api.model.client.cryptography.key.KeyCompromiseReason;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyFormat;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.core.config.cache.CacheConfig;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.messaging.jms.producers.NotificationProducer;
import com.czertainly.core.model.crypto.CryptographicKeyItemModel;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests verifying that the cryptographic key item cache is correctly populated on lookup
 * and evicted after mutations that change the key item's observable state.
 */
class CryptographicKeyItemCacheTest extends BaseSpringBootTest {

    @Autowired
    private CryptographicKeyService cryptographicKeyService;

    @Autowired
    private TokenProfileService tokenProfileService;

    @Autowired
    private CacheManager cacheManager;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;

    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    @MockitoBean
    private NotificationProducer notificationProducer;

    private CryptographicKey key;
    private CryptographicKeyItem keyItem;

    @BeforeEach
    void setUp() {
        Cache cache = cacheManager.getCache(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE);
        if (cache != null) {
            cache.clear();
        }

        Connector connector = new Connector();
        connector.setUrl("http://localhost:18888");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.saveAndFlush(connector);

        TokenInstanceReference tokenInstanceRef = new TokenInstanceReference();
        tokenInstanceRef.setName("testToken");
        tokenInstanceRef.setTokenInstanceUuid(UUID.randomUUID().toString());
        tokenInstanceRef.setConnector(connector);
        tokenInstanceRef.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstanceRef);

        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("testProfile");
        tokenProfile.setTokenInstanceReference(tokenInstanceRef);
        tokenProfile.setDescription("test");
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceName("testInstance");
        tokenProfileRepository.saveAndFlush(tokenProfile);

        key = new CryptographicKey();
        key.setName("testKey");
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenInstanceRef);
        key = cryptographicKeyRepository.saveAndFlush(key);

        keyItem = new CryptographicKeyItem();
        keyItem.setName("testKeyItem");
        keyItem.setKey(key);
        keyItem.setKeyUuid(key.getUuid());
        keyItem.setType(KeyType.PRIVATE_KEY);
        keyItem.setState(KeyState.ACTIVE);
        keyItem.setEnabled(true);
        keyItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        keyItem.setLength(2048);
        keyItem.setFormat(KeyFormat.PRKI);
        keyItem.setKeyData("testKeyData");
        keyItem = cryptographicKeyItemRepository.saveAndFlush(keyItem);
        keyItem.setKeyReferenceUuid(keyItem.getUuid());
        keyItem = cryptographicKeyItemRepository.saveAndFlush(keyItem);

        key.setItems(Set.of(keyItem));
        key = cryptographicKeyRepository.saveAndFlush(key);
    }

    @Test
    void firstLookupPopulatesCache() throws NotFoundException {
        Cache cache = cacheManager.getCache(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE);

        // given - cache is cold for this key item
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNull();

        // when
        cryptographicKeyService.getKeyItemModel(keyItem.getUuid());

        // then - the model is stored in the cache keyed by key item UUID
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNotNull();
    }

    @Test
    void secondLookupReturnsCachedInstance() throws NotFoundException {
        // given - populate cache on first call
        CryptographicKeyItemModel first = cryptographicKeyService.getKeyItemModel(keyItem.getUuid());

        // when - second call for the same key item
        CryptographicKeyItemModel second = cryptographicKeyService.getKeyItemModel(keyItem.getUuid());

        // then - the same Java object is returned, proving no second DB round-trip was made
        assertThat(second).isSameAs(first);
    }

    @Test
    void cacheIsEvictedAfterDisablingKeyItem() throws NotFoundException {
        // given - cache is warm
        cryptographicKeyService.getKeyItemModel(keyItem.getUuid());
        Cache cache = cacheManager.getCache(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE);
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNotNull();

        // when - key item is disabled; the service evicts the entry after the transaction commits
        cryptographicKeyService.disableKeyItems(List.of(keyItem.getUuid().toString()));

        // then - stale entry is gone; the next lookup will re-fetch from the database
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNull();
    }

    @Test
    void cacheIsEvictedAfterEditingKeyItem() throws NotFoundException {
        // given - cache is warm
        cryptographicKeyService.getKeyItemModel(keyItem.getUuid());
        Cache cache = cacheManager.getCache(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE);
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNotNull();

        // when - key item name is updated
        EditKeyItemDto editRequest = new EditKeyItemDto();
        editRequest.setName("renamed-key-item");
        cryptographicKeyService.editKeyItem(SecuredUUID.fromUUID(key.getUuid()), keyItem.getUuid(), editRequest);

        // then - stale entry is gone
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNull();
    }

    @Test
    void cacheIsEvictedAfterCompromisingKeyItem() throws NotFoundException {
        // given - cache is warm
        cryptographicKeyService.getKeyItemModel(keyItem.getUuid());
        Cache cache = cacheManager.getCache(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE);
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNotNull();

        // when - key item is marked as compromised
        BulkCompromiseKeyItemRequestDto request = new BulkCompromiseKeyItemRequestDto(
                KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE, List.of(keyItem.getUuid()));
        cryptographicKeyService.compromiseKeyItems(request);

        // then - cached snapshot (still ACTIVE) is purged so signers no longer use the compromised key
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNull();
    }

    @Test
    void cacheIsEvictedAfterUpdatingKeyItemUsages() throws NotFoundException {
        // given - cache is warm
        cryptographicKeyService.getKeyItemModel(keyItem.getUuid());
        Cache cache = cacheManager.getCache(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE);
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNotNull();

        // when - key item usages are restricted (SIGN removed)
        BulkKeyItemUsageRequestDto request = new BulkKeyItemUsageRequestDto(
                List.of(KeyUsage.DECRYPT), List.of(keyItem.getUuid()));
        cryptographicKeyService.updateKeyItemUsages(request);

        // then - cached usage list is purged so SIGN is denied on next lookup
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNull();
    }

    @Test
    void cacheIsEvictedAfterDestroyingKeyItem() throws NotFoundException, ConnectorException {
        // given - key item state allows destruction without contacting the connector
        keyItem.setState(KeyState.PRE_ACTIVE);
        cryptographicKeyItemRepository.saveAndFlush(keyItem);
        TokenInstanceReference tokenInstanceRef = tokenInstanceReferenceRepository
                .findByUuid(key.getTokenInstanceReferenceUuid()).orElseThrow();
        tokenInstanceRef.setStatus(TokenInstanceStatus.DEACTIVATED);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstanceRef);

        cryptographicKeyService.getKeyItemModel(keyItem.getUuid());
        Cache cache = cacheManager.getCache(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE);
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNotNull();

        // when - key item is destroyed (state transitions to DESTROYED)
        cryptographicKeyService.destroyKeyItems(List.of(keyItem.getUuid().toString()));

        // then - cache entry is gone
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNull();
    }

    @Test
    void editingKeyEvictsAllItemsInThatKey() throws NotFoundException, AttributeException {
        // given - the key has two items, both cached
        CryptographicKeyItem secondItem = new CryptographicKeyItem();
        secondItem.setName("testKeyItemPublic");
        secondItem.setKey(key);
        secondItem.setKeyUuid(key.getUuid());
        secondItem.setType(KeyType.PUBLIC_KEY);
        secondItem.setState(KeyState.ACTIVE);
        secondItem.setEnabled(true);
        secondItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        secondItem.setLength(2048);
        secondItem.setFormat(KeyFormat.SPKI);
        secondItem.setKeyData("testPublicKeyData");
        secondItem = cryptographicKeyItemRepository.saveAndFlush(secondItem);
        secondItem.setKeyReferenceUuid(secondItem.getUuid());
        secondItem = cryptographicKeyItemRepository.saveAndFlush(secondItem);

        key.setItems(new HashSet<>(Set.of(keyItem, secondItem)));
        key = cryptographicKeyRepository.saveAndFlush(key);

        cryptographicKeyService.getKeyItemModel(keyItem.getUuid());
        cryptographicKeyService.getKeyItemModel(secondItem.getUuid());
        Cache cache = cacheManager.getCache(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE);
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNotNull();
        assertThat(cache.get(secondItem.getUuid(), CryptographicKeyItemModel.class)).isNotNull();

        // when - the parent key is edited (renamed)
        EditKeyRequestDto request = new EditKeyRequestDto();
        request.setName("renamed-key");
        cryptographicKeyService.editKey(key.getSecuredUuid(), request);

        // then - both items' cache entries are evicted (the editKey() cascading evict path)
        assertThat(cache.get(keyItem.getUuid(), CryptographicKeyItemModel.class)).isNull();
        assertThat(cache.get(secondItem.getUuid(), CryptographicKeyItemModel.class)).isNull();
    }
}
