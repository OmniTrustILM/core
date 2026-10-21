package com.otilm.core.model.crypto;

import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import java.util.List;
import java.util.Objects;

/**
 * A key with what its removal from the inventory decides on.
 *
 * @param key the key
 * @param tokenConnectorInterface the connector interface of the key's token, or null for a key in no token or a token
 * on a connector of the first version
 * @param items the key's items
 */
public record KeyRemovalCandidate(CryptographicKeyBasicModel key, ImmutableConnectorInterface tokenConnectorInterface,
        List<CryptographicKeyItemBasicModel> items) {

    public KeyRemovalCandidate {
        items = List.copyOf(items);
    }

    public static KeyRemovalCandidate from(CryptographicKey key) {
        Objects.requireNonNull(key, "Cryptographic key is required.");
        TokenInstanceReference token = key.getTokenInstanceReference();
        ImmutableConnectorInterface tokenConnectorInterface = token == null || token.getConnectorInterface() == null
                ? null
                : ImmutableConnectorInterface.from(token.getConnectorInterface());
        List<CryptographicKeyItemBasicModel> items = key
                .getItems()
                .stream()
                .map(CryptographicKeyItemBasicModel::from)
                .toList();
        return new KeyRemovalCandidate(ImmutableCryptographicKeyBasicModel.from(key), tokenConnectorInterface, items);
    }
}
