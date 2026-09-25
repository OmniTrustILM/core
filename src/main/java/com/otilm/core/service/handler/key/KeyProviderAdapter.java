package com.otilm.core.service.handler.key;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
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

    /**
     * Creates a secret key or key pair and returns its items for persistence by Core.
     *
     * @param exportable whether the key may later be exported; only the v2 contract carries it, and the caller has
     * already refused the request when a connector without {@code KEY_EXPORT} was asked for an exportable key
     */
    List<ProviderKeyItem> createKey(TokenProfileFullModel tokenProfile, KeyRequestType type,
            List<RequestAttribute> attributes, String keyName, boolean exportable) throws ConnectorException;

    /** The key types the connector exports from the token profile, with the algorithms it accepts for each. */
    List<TransferableKeyType> listExportableKeyTypes(TokenProfileFullModel tokenProfile) throws ConnectorException;

    /** Lists the attribute schema for creating a secret key or key pair. */
    List<BaseAttribute> listCreateKeyAttributes(TokenProfileFullModel tokenProfile, KeyRequestType type)
            throws ConnectorException;

    EncryptDataResponseDto encryptData(OperationKeyContext context, CipherDataRequestDto request)
            throws ConnectorException;

    DecryptDataResponseDto decryptData(OperationKeyContext context, CipherDataRequestDto request)
            throws ConnectorException;

    SignDataResponseDto signData(OperationKeyContext context, SignDataRequestDto request) throws ConnectorException;

    /**
     * The signature algorithm the signing attributes select, read from the selection itself so it is known before
     * anything is signed.
     *
     * @param privateKeyItem the signing key item
     * @param publicKeyItem the matching public key item, which carries the parameter set of a PQC key
     * @param signatureAttributes the attributes the caller intends to sign with
     * @throws ValidationException when the signing attributes select no algorithm the key can sign with
     */
    ResolvedSignatureAlgorithm resolveSignatureAlgorithm(CryptographicKeyItemOperationModel privateKeyItem,
            CryptographicKeyItemOperationModel publicKeyItem, List<RequestAttribute> signatureAttributes);

    VerifyDataResponseDto verifyData(OperationKeyContext context, VerifyDataRequestDto request)
            throws ConnectorException;

    List<BaseAttribute> listEncryptAttributes(OperationKeyContext context) throws ConnectorException;

    List<BaseAttribute> listDecryptAttributes(OperationKeyContext context) throws ConnectorException;

    List<BaseAttribute> listSignAttributes(OperationKeyContext context) throws ConnectorException;

    List<BaseAttribute> listVerifyAttributes(OperationKeyContext context) throws ConnectorException;

    /** Lists the attribute schema for exporting the key item. */
    List<BaseAttribute> listExportKeyAttributes(OperationKeyContext context) throws ConnectorException;

    /**
     * Exports the key item as a DER-encoded PKCS#8 EncryptedPrivateKeyInfo protected under the passphrase, refusing an
     * answer that describes a key other than the one the platform holds. A failed export is reported in the platform's
     * words only, never the connector's.
     *
     * @param heldKey what the platform holds about the key, to check the answer against
     * @param attributes the export attributes the caller stated, validated against the connector's export schema
     * @throws ConnectorException if the connector fails to export the key, or exports something else
     * @throws ValidationException if the attributes do not follow the schema, or the connector refuses the export
     */
    byte[] exportKey(OperationKeyContext context, HeldKey heldKey, Passphrase passphrase,
            List<RequestAttribute> attributes) throws ConnectorException;

}
