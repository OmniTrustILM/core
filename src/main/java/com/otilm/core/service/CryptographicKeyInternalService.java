package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.model.crypto.CryptographicKeyItemModel;

import java.security.PublicKey;
import java.util.UUID;

public interface CryptographicKeyInternalService extends ResourceExtensionService {

    /**
     * Function to get the key based on the SHA-256 key fingerprint
     *
     * @param fingerprint SHA-256 fingerprint of the key
     * @return Cryptographic Key UUID
     */
    UUID findKeyByFingerprint(String fingerprint);

    /**
     * Get the key item of specified type based on the cryptographic key
     *
     * @param key     Cryptographic Key wrapper object
     * @param keyType Key type
     * @return Key Item
     */
    CryptographicKeyItem getKeyItemFromKey(CryptographicKey key, KeyType keyType);

    /**
     * Returns the cached model for a key item including its full connector chain.
     * The result is cached by key item UUID; cache is invalidated whenever the key item is mutated.
     */
    CryptographicKeyItemModel getKeyItemModel(UUID keyItemUuid) throws NotFoundException;

    /**
     * Upload public key of existing certificate
     *
     * @param name         Name of the cryptographic key
     * @param publicKey    Public Key to be uploaded
     * @param keyLength    Length of the Public Key
     * @param fingerprint  Unique fingerprint of the Public Key
     * @return UUID of the uploaded Cryptographic Key
     */
    UUID uploadCertificatePublicKey(String name, PublicKey publicKey, int keyLength, String fingerprint);
}
