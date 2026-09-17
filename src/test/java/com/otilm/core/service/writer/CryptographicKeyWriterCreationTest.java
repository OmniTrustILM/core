package com.otilm.core.service.writer;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.model.crypto.ImmutableTokenInstanceBasicModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileBasicModel;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CryptographicKeyWriterCreationTest {

    @Mock
    private CryptographicKeyRepository keys;
    @Mock
    private CryptographicKeyItemRepository items;
    @Mock
    private AttributeEngine attributes;
    @Mock
    private CryptographicKeyEventHistoryService history;
    @Mock
    private CertificateInternalService certificates;
    @InjectMocks
    private CryptographicKeyWriter writer;

    private ImmutableTokenInstanceBasicModel token;

    @BeforeEach
    void setUp() {
        token = new ImmutableTokenInstanceBasicModel(UUID.randomUUID(), UUID.randomUUID().toString(), "token",
                TokenInstanceStatus.ACTIVATED, null, UUID.randomUUID(), "provider", null, 0);
        CryptographicKey savedKey = aCryptographicKey().withName("created-key").build();
        savedKey.setUuid(UUID.randomUUID());
        when(keys.save(any())).thenReturn(savedKey);
        when(items.save(any())).thenAnswer(invocation -> {
            CryptographicKeyItem savedItem = invocation.getArgument(0);
            savedItem.setUuid(UUID.randomUUID());
            return savedItem;
        });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("permittedInitialUsages")
    void createKeyWithItems_appliesProfileUsagesAllowedForEachItem(KeyType type, KeyAlgorithm algorithm,
            List<KeyUsage> requestedUsages, Set<KeyUsage> expectedUsages) throws AttributeException {
        // given
        ImmutableTokenProfileBasicModel profile = profile(requestedUsages);
        ProviderKeyItem providerItem = providerItem(type, algorithm);
        KeyRequestDto request = keyRequest();
        boolean discovered = false;
        boolean initiallyEnabled = true;

        // when
        writer.createKeyWithItems(request, profile, token, List.of(providerItem), discovered, initiallyEnabled);

        // then
        assertThat(savedItem().getUsage()).containsExactlyInAnyOrderElementsOf(expectedUsages);
    }

    @Test
    void createKeyWithItems_leavesUsagesEmpty_whenDiscoveredWithoutProfile() throws AttributeException {
        // given
        TokenProfileBasicModel absentProfile = null;
        ProviderKeyItem discoveredItem = providerItem();
        KeyRequestDto request = keyRequest();
        boolean discovered = true;
        boolean initiallyEnabled = false;

        // when
        writer.createKeyWithItems(request, absentProfile, token, List.of(discoveredItem), discovered, initiallyEnabled);

        // then
        assertThat(savedItem().getUsage()).isEmpty();
    }

    private CryptographicKeyItem savedItem() {
        ArgumentCaptor<CryptographicKeyItem> savedItem = ArgumentCaptor.forClass(CryptographicKeyItem.class);
        verify(items).save(savedItem.capture());
        return savedItem.getValue();
    }

    private ImmutableTokenProfileBasicModel profile(List<KeyUsage> usages) {
        return new ImmutableTokenProfileBasicModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(), true,
                usages);
    }

    private static KeyRequestDto keyRequest() {
        KeyRequestDto request = new KeyRequestDto();
        request.setName("created-key");
        return request;
    }

    private static ProviderKeyItem providerItem() {
        return providerItem(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA);
    }

    private static ProviderKeyItem providerItem(KeyType type, KeyAlgorithm algorithm) {
        RemoteKeyReference reference = new RemoteKeyReference.UuidReference(UUID.randomUUID());
        int keyLength = algorithm == KeyAlgorithm.ECDSA ? 256 : 2048;
        return new ProviderKeyItem("provider-item", type, algorithm, keyLength, reference, null, List.of());
    }

    private static Stream<Arguments> permittedInitialUsages() {
        List<KeyUsage> signingUsages = List.of(KeyUsage.SIGN, KeyUsage.VERIFY);
        List<KeyUsage> signingAndCipherUsages = List
                .of(KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        return Stream
                .of(arguments(named("private key keeps signing", KeyType.PRIVATE_KEY), KeyAlgorithm.RSA, signingUsages,
                        Set.of(KeyUsage.SIGN)),
                        arguments(named("public key keeps verification", KeyType.PUBLIC_KEY), KeyAlgorithm.RSA,
                                signingUsages, Set.of(KeyUsage.VERIFY)),
                        arguments(named("secret key keeps both requested usages", KeyType.SECRET_KEY),
                                KeyAlgorithm.UNKNOWN, signingUsages, Set.of(KeyUsage.SIGN, KeyUsage.VERIFY)),
                        arguments(named("ECDSA private key excludes cipher usages", KeyType.PRIVATE_KEY),
                                KeyAlgorithm.ECDSA, signingAndCipherUsages, Set.of(KeyUsage.SIGN)),
                        arguments(named("ECDSA public key excludes cipher usages", KeyType.PUBLIC_KEY),
                                KeyAlgorithm.ECDSA, signingAndCipherUsages, Set.of(KeyUsage.VERIFY)));
    }
}
