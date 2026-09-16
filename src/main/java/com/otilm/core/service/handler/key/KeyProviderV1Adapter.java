package com.otilm.core.service.handler.key;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v1.KeyManagementSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.key.CreateKeyRequestDto;
import com.otilm.api.model.connector.cryptography.key.KeyData;
import com.otilm.api.model.connector.cryptography.key.KeyDataResponseDto;
import com.otilm.api.model.connector.cryptography.key.KeyPairDataResponseDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.util.CryptographicHelper;
import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;

/** Legacy cryptography-provider v1 key management. */
@Slf4j
public class KeyProviderV1Adapter implements KeyProviderAdapter, KeyCreationValidationCapability {

    private final ApiClientConnectorInfo connectorInfo;
    private final KeyManagementSyncApiClient keyManagementSyncApiClient;
    private final AttributeEngine attributeEngine;

    public KeyProviderV1Adapter(ConnectorApiFactory connectorApiFactory, ApiClientConnectorInfo connectorInfo,
            AttributeEngine attributeEngine) {
        this.connectorInfo = connectorInfo;
        this.attributeEngine = attributeEngine;
        this.keyManagementSyncApiClient = connectorApiFactory.getKeyManagementApiClient(connectorInfo);
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
            List<RequestAttribute> attributes, String keyName) throws ConnectorException {
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
}
