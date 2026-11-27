package com.otilm.core.service.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.service.handler.DataDigestSigningCapability.Support;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures.activeSigningPrivateKey;
import static com.otilm.core.util.builders.TokenInstanceFullModelBuilder.aTokenSnapshot;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DataDigestSigningCapabilityTest {

    @Mock
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    private DataDigestSigningCapability capability;

    @BeforeEach
    void createCapability() {
        capability = new DataDigestSigningCapability(new ConnectorCapabilityService(),
                tokenInstanceReferenceRepository);
    }

    @Test
    void answersVersion1Provider_whenTheKeyItemHasNoConnectorInterface() throws Exception {
        // given
        var keyOnVersion1Provider = activeSigningPrivateKey(KeyAlgorithm.RSA);

        // when
        Support support = capability.of(keyOnVersion1Provider);

        // then
        assertThat(support).isEqualTo(Support.VERSION_1_PROVIDER);
        verifyNoInteractions(tokenInstanceReferenceRepository);
    }

    @Test
    void answersNotAdvertised_whenTheV2ProviderDoesNotAdvertiseDataDigestSigning() throws Exception {
        // given
        var keyItem = buildPrivateKeyOnV2Provider();
        var tokenWithoutTheFeature = aTokenSnapshot().withConnectorFeatures(FeatureFlag.STATELESS).build();
        when(tokenInstanceReferenceRepository.findFullModelByUuid(keyItem.tokenInstanceReferenceUuid()))
                .thenReturn(Optional.of(tokenWithoutTheFeature));

        // when
        Support support = capability.of(keyItem);

        // then
        assertThat(support).isEqualTo(Support.NOT_ADVERTISED);
    }

    @Test
    void answersSupported_whenTheV2ProviderAdvertisesDataDigestSigning() throws Exception {
        // given
        var keyItem = buildPrivateKeyOnV2Provider();
        var tokenAdvertisingTheFeature = aTokenSnapshot()
                .withConnectorFeatures(FeatureFlag.DATA_DIGEST_SIGNING)
                .build();
        when(tokenInstanceReferenceRepository.findFullModelByUuid(keyItem.tokenInstanceReferenceUuid()))
                .thenReturn(Optional.of(tokenAdvertisingTheFeature));

        // when
        Support support = capability.of(keyItem);

        // then
        assertThat(support).isEqualTo(Support.SUPPORTED);
    }

    @Test
    void throwsNotFound_whenTheKeyItemsTokenInstanceNoLongerExists() {
        // given
        var keyItem = buildPrivateKeyOnV2Provider();
        when(tokenInstanceReferenceRepository.findFullModelByUuid(keyItem.tokenInstanceReferenceUuid()))
                .thenReturn(Optional.empty());

        // when
        ThrowingCallable answer = () -> capability.of(keyItem);

        // then
        assertThatThrownBy(answer)
                .isInstanceOf(NotFoundException.class)
                .hasMessageContaining(keyItem.tokenInstanceReferenceUuid().toString());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static CryptographicKeyItemOperationModel buildPrivateKeyOnV2Provider() {
        return new CryptographicKeyItemOperationModel(UUID.randomUUID(), true, KeyAlgorithm.RSA, KeyState.ACTIVE,
                KeyType.PRIVATE_KEY, List.of(KeyUsage.SIGN), null, new RemoteKeyReference.MetadataReference(List.of()),
                UUID.randomUUID(), null, UUID.randomUUID(), ConnectorInterface.CRYPTOGRAPHY, "v2", UUID.randomUUID(),
                UUID.randomUUID());
    }
}
