package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.BulkCompromiseKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.BulkKeyItemUsageRequestDto;
import com.otilm.api.model.client.cryptography.key.BulkKeyUsageRequestDto;
import com.otilm.api.model.client.cryptography.key.CompromiseKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.client.cryptography.key.UpdateKeyUsageRequestDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyBasicModel;
import com.otilm.core.model.crypto.ImmutableCryptographicKeyFullModel;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceImplValidationTest {

    private final CryptographicKeyRepository keyRepository = mock(CryptographicKeyRepository.class);
    private final CryptographicKeyItemRepository itemRepository = mock(CryptographicKeyItemRepository.class);
    private final CryptographicKeyEventHistoryService history = mock(CryptographicKeyEventHistoryService.class);
    private final CacheEvictor cacheEvictor = mock(CacheEvictor.class);
    private final CryptographicKeyServiceImpl service = new CryptographicKeyServiceImpl();
    private final CryptographicKey key = aCryptographicKey().build();
    private final CryptographicKeyItem privateItem = item(KeyType.PRIVATE_KEY);
    private final CryptographicKeyItem publicItem = item(KeyType.PUBLIC_KEY);

    @BeforeEach
    void setUp() {
        CryptographicKeyWriter writer = new CryptographicKeyWriter(keyRepository, itemRepository, null, null, null,
                null, null, null, history, null);
        service.setCryptographicKeyRepository(keyRepository);
        service.setCryptographicKeyItemRepository(itemRepository);
        service.setCryptographicKeyWriter(writer);
        service.setCacheEvictor(cacheEvictor);
        key.setUuid(UUID.randomUUID());
        privateItem.setKey(key);
        publicItem.setKey(key);
        key.setItems(Set.of(privateItem, publicItem));
        when(keyRepository.findFullModelByUuid(key.getUuid()))
                .thenReturn(Optional.of(ImmutableCryptographicKeyFullModel.from(key)));
        when(keyRepository.findBasicModelByUuid(key.getUuid()))
                .thenReturn(Optional.of(ImmutableCryptographicKeyBasicModel.from(key)));
        when(itemRepository.findBasicModelsByUuidIn(itemUuids()))
                .thenReturn(List
                        .of(CryptographicKeyItemBasicModel.from(privateItem),
                                CryptographicKeyItemBasicModel.from(publicItem)));
        when(itemRepository.findForUpdateByUuid(privateItem.getUuid())).thenReturn(Optional.of(privateItem));
        when(itemRepository.findForUpdateByUuid(publicItem.getUuid())).thenReturn(Optional.of(publicItem));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void compromise_reportsLockedStateAndPartialSuccess_whenAnItemIsInvalid(boolean bulk) {
        // given
        KeyState invalidState = KeyState.DESTROYED;
        privateItem.setState(invalidState);
        String expectedSummary = "Successfully compromised key items in this batch: 1.";

        // when
        Executable compromise = () -> compromise(bulk);

        // then
        ValidationException failure = assertThrows(ValidationException.class, compromise);
        assertThat(failure.getErrors()).hasSize(1);
        assertThat(failure.getMessage())
                .contains(privateItem.getUuid().toString(), invalidState.getLabel(), KeyState.PRE_ACTIVE.getLabel(),
                        KeyState.ACTIVE.getLabel(), KeyState.DEACTIVATED.getLabel(), expectedSummary);
        assertThat(privateItem.getState()).isEqualTo(invalidState);
        assertThat(publicItem.getState()).isEqualTo(KeyState.COMPROMISED);
        verify(cacheEvictor, never()).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, privateItem.getUuid());
        verify(cacheEvictor).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, publicItem.getUuid());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void compromise_reportsMissingItemAndContinues(boolean bulk) {
        // given
        when(itemRepository.findForUpdateByUuid(privateItem.getUuid())).thenReturn(Optional.empty());
        String expectedReason = "Key item %s was not found.".formatted(privateItem.getUuid());
        String expectedSummary = "Successfully compromised key items in this batch: 1.";

        // when
        Executable compromise = () -> compromise(bulk);

        // then
        ValidationException failure = assertThrows(ValidationException.class, compromise);
        assertThat(failure.getErrors()).hasSize(1);
        assertThat(failure.getMessage()).contains(expectedReason, expectedSummary);
        assertThat(publicItem.getState()).isEqualTo(KeyState.COMPROMISED);
    }

    @ParameterizedTest
    @EnumSource(UsageTarget.class)
    void updateUsages_reportsUnsupportedUsagesAndPartialSuccess(UsageTarget target) {
        // given
        KeyUsage requestedUsage = KeyUsage.VERIFY;
        String expectedReason = "Unsupported usages of key %s: %s."
                .formatted(privateItem.getUuid(), requestedUsage.getCode());
        String expectedSummary = "Successfully updated key items in this batch: 1.";

        // when
        Executable update = () -> updateUsages(target, requestedUsage);

        // then
        ValidationException failure = assertThrows(ValidationException.class, update);
        assertThat(failure.getErrors()).hasSize(1);
        assertThat(failure.getMessage()).contains(expectedReason, expectedSummary);
        assertThat(privateItem.getUsage()).isEmpty();
        assertThat(publicItem.getUsage()).containsExactly(requestedUsage);
        verify(cacheEvictor, never()).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, privateItem.getUuid());
        verify(cacheEvictor).evict(CacheConfig.CRYPTOGRAPHIC_KEY_ITEM_CACHE, publicItem.getUuid());
    }

    @ParameterizedTest
    @EnumSource(UsageTarget.class)
    void updateUsages_reportsMissingItemAndContinues(UsageTarget target) {
        // given
        when(itemRepository.findForUpdateByUuid(privateItem.getUuid())).thenReturn(Optional.empty());
        KeyUsage requestedUsage = KeyUsage.VERIFY;
        String expectedReason = "Key item %s was not found.".formatted(privateItem.getUuid());

        // when
        Executable update = () -> updateUsages(target, requestedUsage);

        // then
        ValidationException failure = assertThrows(ValidationException.class, update);
        assertThat(failure.getErrors()).hasSize(1);
        assertThat(failure.getMessage()).contains(expectedReason);
        assertThat(publicItem.getUsage()).containsExactly(requestedUsage);
    }

    @ParameterizedTest
    @EnumSource(UsageTarget.class)
    void updateUsages_reportsInternalFailureWithoutExposingDetails(UsageTarget target) {
        // given
        String internalDetail = "SQL constraint secret_key_table";
        when(itemRepository.findForUpdateByUuid(privateItem.getUuid()))
                .thenThrow(new IllegalStateException(internalDetail));
        KeyUsage requestedUsage = KeyUsage.VERIFY;
        String expectedSummary = "Successfully updated key items in this batch: 1.";

        // when
        Executable update = () -> updateUsages(target, requestedUsage);

        // then
        ValidationException failure = assertThrows(ValidationException.class, update);
        assertThat(failure.getErrors()).hasSize(1);
        assertThat(failure.getMessage())
                .contains(privateItem.getUuid().toString(), "internal error", expectedSummary)
                .doesNotContain(internalDetail);
        assertThat(publicItem.getUsage()).containsExactly(requestedUsage);
    }

    private void compromise(boolean bulk) throws Exception {
        KeyCompromiseReason reason = KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE;
        if (bulk) {
            service.compromiseKey(new BulkCompromiseKeyRequestDto(reason, List.of(key.getUuid())));
        } else {
            service.compromiseKey(key.getUuid(), new CompromiseKeyRequestDto(reason, itemUuids()));
        }
    }

    private void updateUsages(UsageTarget target, KeyUsage usage) throws Exception {
        switch (target) {
            case KEY -> {
                UpdateKeyUsageRequestDto request = new UpdateKeyUsageRequestDto();
                request.setUuids(itemUuids());
                request.setUsage(List.of(usage));
                service.updateKeyUsages(key.getUuid(), request);
            }
            case KEYS -> {
                BulkKeyUsageRequestDto request = new BulkKeyUsageRequestDto();
                request.setUuids(List.of(key.getUuid()));
                request.setUsage(List.of(usage));
                service.updateKeyUsages(request);
            }
            case ITEMS -> {
                BulkKeyItemUsageRequestDto request = new BulkKeyItemUsageRequestDto();
                request.setUuids(itemUuids());
                request.setUsage(List.of(usage));
                service.updateKeyItemUsages(request);
            }
        }
    }

    private List<UUID> itemUuids() {
        return List.of(privateItem.getUuid(), publicItem.getUuid());
    }

    private CryptographicKeyItem item(KeyType type) {
        CryptographicKeyItem item = aKeyItem().withType(type).withState(KeyState.ACTIVE).build();
        item.setUuid(UUID.randomUUID());
        item.setKeyReferenceUuid(UUID.randomUUID());
        item.setKeyAlgorithm(KeyAlgorithm.RSA);
        item.setUsage(List.of());
        return item;
    }

    private enum UsageTarget {
        KEY,
        KEYS,
        ITEMS
    }
}
