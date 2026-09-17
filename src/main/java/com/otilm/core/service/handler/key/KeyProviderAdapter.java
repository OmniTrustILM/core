package com.otilm.core.service.handler.key;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import java.util.List;

/**
 * Version boundary for synchronous key management. Persistence and authorization belong to Core services.
 */
public interface KeyProviderAdapter {

    /**
     * Lists provider items with their association identifiers for grouping by Core.
     */
    List<ProviderKeyItem> listKeys(TokenInstanceBasicModel tokenInstance) throws ConnectorException;

    /**
     * Destroys a remote key synchronously using its provider-owned reference.
     *
     * @param cryptographicKey key context for the operation
     * @param reference remote UUID for v1, or the key item's stored metadata handle for v2
     * @throws ConnectorException if destruction fails or synchronous completion is not confirmed
     * @throws IllegalArgumentException if the reference is missing or incompatible with the adapter
     */
    void destroyKeyItem(CryptographicKeyFullModel cryptographicKey, RemoteKeyReference reference)
            throws ConnectorException;

    /** Creates a secret key or key pair and returns its items for persistence by Core. */
    List<ProviderKeyItem> createKey(TokenProfileFullModel tokenProfile, KeyRequestType type,
            List<RequestAttribute> attributes, String keyName) throws ConnectorException;

    /** Lists the attribute schema for creating a secret key or key pair. */
    List<BaseAttribute> listCreateKeyAttributes(TokenProfileFullModel tokenProfile, KeyRequestType type)
            throws ConnectorException;

}
