package com.otilm.core.service.handler;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeyListGatesTest {

    private final KeyImportGates keyImportGates = mock(KeyImportGates.class);
    private final KeyListGates gates = new KeyListGates(keyImportGates, new ConnectorCapabilityService());

    private static ImmutableTokenInstanceFullModel token(ImmutableConnectorInterface connectorInterface) {
        return new ImmutableTokenInstanceFullModel(UUID.randomUUID(), UUID.randomUUID().toString(), "token",
                TokenInstanceStatus.ACTIVATED, null, UUID.randomUUID(), "connector",
                connectorInterface == null ? null : connectorInterface.uuid(), connectorInterface, Set.of());
    }

    private static ImmutableConnectorInterface v2Declaring(FeatureFlag... features) {
        return new ImmutableConnectorInterface(UUID.randomUUID(), ConnectorInterface.CRYPTOGRAPHY, "v2",
                List.of(features));
    }

    private static TokenProfileFullModel profile(ImmutableTokenInstanceFullModel token, boolean enabled) {
        return new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(),
                enabled, List.of(), token, token.connectorUuid(), Map.of(), Map.of(), 0);
    }

    @Test
    void offersListingOnAConnectorThatListsKeys() {
        // given
        TokenProfileFullModel profile = profile(token(v2Declaring(FeatureFlag.KEY_LIST)), true);

        // when
        boolean available = gates.isAvailable(profile);

        // then
        assertThat(available).isTrue();
    }

    @Test
    void withholdsListingFromAConnectorLackingKeyListing() {
        // given
        TokenProfileFullModel v2WithoutListing = profile(token(v2Declaring(FeatureFlag.KEY_IMPORT)), true);
        TokenProfileFullModel v1 = profile(token(null), true);

        // when / then
        assertThat(gates.isAvailable(v2WithoutListing)).isFalse();
        assertThat(gates.isAvailable(v1)).isFalse();
    }

    @Test
    void refusesToListOnAConnectorLackingKeyListing() throws Exception {
        // given
        TokenProfileFullModel profile = profile(token(v2Declaring()), true);
        when(keyImportGates.requireAccess(profile.tokenInstanceReferenceUuid(), profile.uuid())).thenReturn(profile);

        // when / then
        assertThatThrownBy(() -> gates.requireListable(profile.tokenInstanceReferenceUuid(), profile.uuid()))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("cannot list the keys in its key storage");
    }

    @Test
    void refusesToListOnADisabledProfile() throws Exception {
        // given
        TokenProfileFullModel profile = profile(token(v2Declaring(FeatureFlag.KEY_LIST)), false);
        when(keyImportGates.requireAccess(profile.tokenInstanceReferenceUuid(), profile.uuid())).thenReturn(profile);

        // when / then
        assertThatThrownBy(() -> gates.requireListable(profile.tokenInstanceReferenceUuid(), profile.uuid()))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("is disabled");
    }
}
