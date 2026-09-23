package com.otilm.core.service.handler.key;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.otilm.api.interfaces.client.v1.KeyManagementSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.CipherRequestData;
import com.otilm.api.model.client.cryptography.operations.CipherResponseData;
import com.otilm.api.model.client.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignatureRequestData;
import com.otilm.api.model.client.cryptography.operations.SignatureResponseData;
import com.otilm.api.model.client.cryptography.operations.VerificationResponseData;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyData;
import com.otilm.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.EcdsaSignatureAttributes;
import com.otilm.core.attribute.RsaEncryptionAttributes;
import com.otilm.core.attribute.RsaSignatureAttributes;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.service.handler.LegacyOperationCodec;
import com.otilm.core.service.handler.OperationDataItem;
import com.otilm.core.service.handler.OperationResultItem;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.CryptographicHelper;
import com.otilm.core.util.CryptographyUtil;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;

/** Legacy cryptography-provider v1 key management. */
@Slf4j
public class KeyProviderV1Adapter implements KeyProviderAdapter, KeyCreationValidationCapability {

    private static final String UNSUPPORTED_KEY_ALGORITHM = "Cryptographic key algorithm not supported";

    private final ApiClientConnectorInfo connectorInfo;
    private final KeyManagementSyncApiClient keyManagementSyncApiClient;
    private final CryptographicOperationsSyncApiClient operationsApiClient;
    private final AttributeEngine attributeEngine;

    public KeyProviderV1Adapter(ConnectorApiFactory connectorApiFactory, ApiClientConnectorInfo connectorInfo,
            AttributeEngine attributeEngine) {
        this.connectorInfo = connectorInfo;
        this.attributeEngine = attributeEngine;
        this.keyManagementSyncApiClient = connectorApiFactory.getKeyManagementApiClient(connectorInfo);
        this.operationsApiClient = connectorApiFactory.getCryptographicOperationsApiClient(connectorInfo);
    }

    @Override
    public List<ProviderKeyItem> listKeys(TokenInstanceBasicModel tokenInstance) throws ConnectorException {
        List<KeyDataResponseDto> keys = keyManagementSyncApiClient
                .listKeys(connectorInfo, tokenInstance.tokenInstanceUuid());
        return keys.stream().map(this::toCreatedKeyItem).toList();
    }

    @Override
    public void destroyKeyItem(CryptographicKeyFullModel cryptographicKey, RemoteKeyReference reference)
            throws ConnectorException {
        if (!(reference instanceof RemoteKeyReference.UuidReference(UUID uuid)) || uuid == null) {
            throw new IllegalArgumentException("V1 key destruction requires a remote key UUID.");
        }
        try {
            keyManagementSyncApiClient
                    .destroyKey(connectorInfo, cryptographicKey.tokenInstance().tokenInstanceUuid(), uuid.toString());
        } catch (ConnectorEntityNotFoundException e) {
            log
                    .info("Key item '{}' was not found on the remote token; treating destruction as successful",
                            reference.toIdentifierString());
        } catch (ConnectorException e) {
            if (cryptographicKey.tokenInstance().status().equals(TokenInstanceStatus.DEACTIVATED)) {
                log
                        .warn("Key item '{}' could not be deleted. The associated Token '{}' is DEACTIVATED.",
                                reference.toIdentifierString(), cryptographicKey.tokenInstance().toIdentifierString());
            } else {
                throw e;
            }
        }
    }

    @Override
    public List<ProviderKeyItem> createKey(TokenProfileFullModel tokenProfile, KeyRequestType type,
            List<RequestAttribute> attributes, String keyName, boolean exportable) throws ConnectorException {
        CreateKeyRequestDto request = new CreateKeyRequestDto();
        request.setCreateKeyAttributes(attributes);
        request
                .setTokenProfileAttributes(attributeEngine
                        .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(Resource.TOKEN_PROFILE, tokenProfile.uuid())
                                .connector(tokenProfile.tokenInstance().connectorUuid())
                                .build()));

        if (type.equals(KeyRequestType.KEY_PAIR)) {
            return createKeyPair(tokenProfile.tokenInstance().tokenInstanceUuid(), request);
        }
        ProviderKeyItem secretKeyItem = createSecretKey(tokenProfile.tokenInstance().tokenInstanceUuid(), request);
        return List.of(secretKeyItem);
    }

    private List<ProviderKeyItem> createKeyPair(String tokenInstanceUuid, CreateKeyRequestDto request)
            throws ConnectorException {
        KeyPairDataResponseDto response = keyManagementSyncApiClient
                .createKeyPair(connectorInfo, tokenInstanceUuid, request);
        ProviderKeyItem publicKeyItem = toCreatedKeyItem(response.getPublicKeyData());
        ProviderKeyItem privateKeyItem = toCreatedKeyItem(response.getPrivateKeyData());
        log
                .info("A key pair has been created on remote device through connector {} ({}); Private key reference: {}; Public key reference: {}",
                        connectorInfo.getName(), connectorInfo.getUuid(),
                        privateKeyItem.reference().toIdentifierString(),
                        publicKeyItem.reference().toIdentifierString());
        return List.of(publicKeyItem, privateKeyItem);
    }

    private ProviderKeyItem createSecretKey(String tokenInstanceUuid, CreateKeyRequestDto request)
            throws ConnectorException {
        KeyDataResponseDto response = keyManagementSyncApiClient
                .createSecretKey(connectorInfo, tokenInstanceUuid, request);
        ProviderKeyItem secretKeyItem = toCreatedKeyItem(response);
        log
                .info("A secret key has been created on remote device through connector {} ({}); Key reference: {}",
                        connectorInfo.getName(), connectorInfo.getUuid(),
                        secretKeyItem.reference().toIdentifierString());
        return secretKeyItem;
    }

    private ProviderKeyItem toCreatedKeyItem(KeyDataResponseDto response) {
        KeyData data = response.getKeyData();
        String serializedValue = CryptographicHelper.serializeKeyValue(data.getFormat(), data.getValue());
        KeyMaterial material = new KeyMaterial(data.getFormat(), serializedValue);
        UUID referenceUuid = UUID.fromString(response.getUuid());
        RemoteKeyReference reference = new RemoteKeyReference.UuidReference(referenceUuid);
        return new ProviderKeyItem(response.getName(), data.getType(), data.getAlgorithm(), data.getLength(), reference,
                material, data.getMetadata(), response.getAssociation());
    }

    @Override
    public void validateCreateKeyAttributes(TokenInstanceBasicModel tokenInstance, KeyRequestType type,
            List<RequestAttribute> attributes) throws ConnectorException {
        if (type == KeyRequestType.KEY_PAIR) {
            keyManagementSyncApiClient
                    .validateCreateKeyPairAttributes(connectorInfo, tokenInstance.tokenInstanceUuid(), attributes);
        } else {
            keyManagementSyncApiClient
                    .validateCreateSecretKeyAttributes(connectorInfo, tokenInstance.tokenInstanceUuid(), attributes);
        }
    }

    @Override
    public List<BaseAttribute> listCreateKeyAttributes(TokenProfileFullModel tokenProfile, KeyRequestType type)
            throws ConnectorException {

        if (type.equals(KeyRequestType.KEY_PAIR)) {
            return keyManagementSyncApiClient
                    .listCreateKeyPairAttributes(connectorInfo, tokenProfile.tokenInstance().tokenInstanceUuid());
        } else {
            return keyManagementSyncApiClient
                    .listCreateSecretKeyAttributes(connectorInfo, tokenProfile.tokenInstance().tokenInstanceUuid());
        }
    }

    @Override
    public EncryptDataResponseDto encryptData(OperationKeyContext context, CipherDataRequestDto request)
            throws ConnectorException {
        CryptographicKeyItemOperationModel key = context.keyItem();
        var connectorRequest = LegacyOperationCodec
                .cipherRequest(cipherItems(request.getCipherData()), request.getCipherAttributes());
        var response = operationsApiClient
                .encryptData(connectorInfo, remoteTokenUuid(key), requireV1KeyReference(key), connectorRequest);
        EncryptDataResponseDto result = new EncryptDataResponseDto();
        if (response.getEncryptedData() != null) {
            result.setEncryptedData(toCipherResponse(LegacyOperationCodec.cipherResults(response.getEncryptedData())));
        }
        return result;
    }

    @Override
    public DecryptDataResponseDto decryptData(OperationKeyContext context, CipherDataRequestDto request)
            throws ConnectorException {
        CryptographicKeyItemOperationModel key = context.keyItem();
        var connectorRequest = LegacyOperationCodec
                .cipherRequest(cipherItems(request.getCipherData()), request.getCipherAttributes());
        var response = operationsApiClient
                .decryptData(connectorInfo, remoteTokenUuid(key), requireV1KeyReference(key), connectorRequest);
        DecryptDataResponseDto result = new DecryptDataResponseDto();
        if (response.getDecryptedData() != null) {
            result.setDecryptedData(toCipherResponse(LegacyOperationCodec.cipherResults(response.getDecryptedData())));
        }
        return result;
    }

    /** A legacy provider publishes no signing schema, so the answer comes from Core's own signature registry. */
    @Override
    public ResolvedSignatureAlgorithm resolveSignatureAlgorithm(OperationKeyContext context,
            CryptographicKeyItemOperationModel publicKeyItem, List<RequestAttribute> signatureAttributes) {
        String name = CryptographyUtil
                .resolveSignatureAlgorithmName(context.keyItem().keyAlgorithm(), signatureAttributes,
                        publicKeyItem.pqcParameterSpecName());
        SignatureAlgorithm platformAlgorithm;
        try {
            platformAlgorithm = SignatureAlgorithm.findByCode(name);
        } catch (ValidationException e) {
            platformAlgorithm = null;
        }
        return new ResolvedSignatureAlgorithm(name, platformAlgorithm);
    }

    @Override
    public SignDataResponseDto signData(OperationKeyContext context, SignDataRequestDto request)
            throws ConnectorException {
        CryptographicKeyItemOperationModel key = context.keyItem();
        validateSignatureAttributes(key.keyAlgorithm(), request.getSignatureAttributes());
        var connectorRequest = LegacyOperationCodec
                .signRequest(signatureItems(request.getData()), request.getSignatureAttributes());
        var response = operationsApiClient
                .signData(connectorInfo, remoteTokenUuid(key), requireV1KeyReference(key), connectorRequest);
        SignDataResponseDto result = new SignDataResponseDto();
        if (response.getSignatures() != null) {
            List<OperationResultItem> signatures = LegacyOperationCodec.signatureResults(response.getSignatures());
            result.setSignatures(signatures.stream().map(item -> {
                SignatureResponseData data = new SignatureResponseData();
                data.setData(item.data());
                data.setIdentifier(item.identifier());
                data.setDetails(item.details());
                return data;
            }).toList());
        }
        return result;
    }

    @Override
    public VerifyDataResponseDto verifyData(OperationKeyContext context, VerifyDataRequestDto request)
            throws ConnectorException {
        CryptographicKeyItemOperationModel key = context.keyItem();
        validateSignatureAttributes(key.keyAlgorithm(), request.getSignatureAttributes());
        var connectorRequest = LegacyOperationCodec
                .verifyRequest(request.getData() == null ? null : signatureItems(request.getData()),
                        signatureItems(request.getSignatures()), request.getSignatureAttributes());
        var response = operationsApiClient
                .verifyData(connectorInfo, remoteTokenUuid(key), requireV1KeyReference(key), connectorRequest);
        VerifyDataResponseDto result = new VerifyDataResponseDto();
        if (response.getVerifications() != null) {
            List<OperationResultItem> verifications = LegacyOperationCodec
                    .verificationResults(response.getVerifications());
            result.setVerifications(verifications.stream().map(item -> {
                VerificationResponseData data = new VerificationResponseData();
                data.setResult(Boolean.TRUE.equals(item.result()));
                data.setIdentifier(item.identifier());
                data.setDetails(item.details());
                return data;
            }).toList());
        }
        return result;
    }

    @Override
    public List<BaseAttribute> listEncryptAttributes(OperationKeyContext context) {
        return cipherAttributes(context.keyItem().keyAlgorithm());
    }

    @Override
    public List<BaseAttribute> listDecryptAttributes(OperationKeyContext context) {
        return cipherAttributes(context.keyItem().keyAlgorithm());
    }

    @Override
    public List<BaseAttribute> listSignAttributes(OperationKeyContext context) {
        return signatureAttributes(context.keyItem().keyAlgorithm());
    }

    @Override
    public List<BaseAttribute> listVerifyAttributes(OperationKeyContext context) {
        return signatureAttributes(context.keyItem().keyAlgorithm());
    }

    /** Core-internal cipher schema served for legacy providers, which publish none of their own. */
    public static List<BaseAttribute> cipherAttributes(KeyAlgorithm keyAlgorithm) {
        if (keyAlgorithm == KeyAlgorithm.RSA) {
            return RsaEncryptionAttributes.getRsaEncryptionAttributes();
        }
        throw new ValidationException(ValidationError.create(UNSUPPORTED_KEY_ALGORITHM));
    }

    /** Core-internal signature schema served for legacy providers, which publish none of their own. */
    public static List<BaseAttribute> signatureAttributes(KeyAlgorithm keyAlgorithm) {
        return switch (keyAlgorithm) {
            case RSA -> RsaSignatureAttributes.getRsaSignatureAttributes();
            case ECDSA -> EcdsaSignatureAttributes.getEcdsaSignatureAttributes();
            case FALCON, MLDSA, SLHDSA -> List.of();
            default -> throw new ValidationException(ValidationError.create(UNSUPPORTED_KEY_ALGORITHM));
        };
    }

    private static void validateSignatureAttributes(KeyAlgorithm keyAlgorithm, List<RequestAttribute> attributes) {
        if (attributes == null) {
            return;
        }
        switch (keyAlgorithm) {
            case RSA -> AttributeDefinitionUtils
                    .validateAttributes(RsaSignatureAttributes.getRsaSignatureAttributes(), attributes);
            case ECDSA -> AttributeDefinitionUtils
                    .validateAttributes(EcdsaSignatureAttributes.getEcdsaSignatureAttributes(), attributes);
            case FALCON, MLDSA, SLHDSA -> {
                // key-intrinsic algorithms carry no request attributes
            }
            default -> throw new ValidationException(ValidationError.create(UNSUPPORTED_KEY_ALGORITHM));
        }
    }

    private static String requireV1KeyReference(CryptographicKeyItemOperationModel key) throws ConnectorException {
        if (key.reference() instanceof RemoteKeyReference.UuidReference(UUID uuid) && uuid != null) {
            return uuid.toString();
        }
        throw new ConnectorException(
                "This cryptographic operation requires a v1 remote key UUID; metadata references are not supported.");
    }

    private static String remoteTokenUuid(CryptographicKeyItemOperationModel key) throws ConnectorException {
        if (key.tokenInstanceUuid() == null) {
            throw new ConnectorException("This cryptographic operation requires a v1 remote token UUID.");
        }
        return key.tokenInstanceUuid().toString();
    }

    private static List<OperationDataItem> cipherItems(List<CipherRequestData> items) {
        return items.stream().map(item -> new OperationDataItem(item.getData(), item.getIdentifier())).toList();
    }

    private static List<OperationDataItem> signatureItems(List<SignatureRequestData> items) {
        return items.stream().map(item -> new OperationDataItem(item.getData(), item.getIdentifier())).toList();
    }

    private static List<CipherResponseData> toCipherResponse(List<OperationResultItem> items) {
        return items.stream().map(item -> {
            CipherResponseData data = new CipherResponseData();
            data.setData(item.data());
            data.setIdentifier(item.identifier());
            data.setDetails(item.details());
            return data;
        }).toList();
    }
}
