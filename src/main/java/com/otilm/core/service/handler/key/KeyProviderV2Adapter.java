package com.otilm.core.service.handler.key;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.interfaces.client.v2.KeySyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyOperationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataResponseV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.service.handler.OperationAttributeResolver;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;

/** Synchronous stateless cryptography-provider v2 key management. */
@Slf4j
public class KeyProviderV2Adapter implements KeyProviderAdapter {

    private final ApiClientConnectorInfo connectorInfo;
    private final KeySyncApiClient keyManagementSyncApiClient;
    private final AttributeEngine attributeEngine;
    private final OperationAttributeResolver operationAttributeResolver;
    private final OutboundSecretContainment outboundSecretContainment;

    public KeyProviderV2Adapter(ConnectorApiFactory connectorApiFactory, ApiClientConnectorInfo connectorInfo,
            AttributeEngine attributeEngine, OperationAttributeResolver operationAttributeResolver,
            OutboundSecretContainment outboundSecretContainment) {
        this.connectorInfo = connectorInfo;
        this.attributeEngine = attributeEngine;
        this.operationAttributeResolver = operationAttributeResolver;
        this.outboundSecretContainment = outboundSecretContainment;
        this.keyManagementSyncApiClient = connectorApiFactory.getKeyManagementApiClientV2(connectorInfo);
    }

    /** Placeholder until stateless provider key listing is implemented. */
    @Override
    public List<ProviderKeyItem> listKeys(TokenInstanceBasicModel tokenInstance) {
        return List.of();
    }

    @Override
    public void destroyKeyItem(CryptographicKeyFullModel cryptographicKey, RemoteKeyReference reference)
            throws ConnectorException {
        if (!(reference instanceof RemoteKeyReference.MetadataReference(List<MetadataAttribute> keyMeta))
                || keyMeta == null || keyMeta.isEmpty()) {
            throw new IllegalArgumentException("V2 key destruction requires a non-empty metadata handle.");
        }
        TokenProfileScopedRequestV2Dto scope = tokenProfileScopedRequest(cryptographicKey.tokenProfile());
        DestroyKeyRequestV2Dto request = new DestroyKeyRequestV2Dto();
        request.setTokenAttributes(scope.getTokenAttributes());
        request.setTokenProfileAttributes(scope.getTokenProfileAttributes());
        request.setKeyUsages(scope.getKeyUsages());
        request.setKeyMeta(keyMeta);
        request.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);

        try {
            ResponseEntity<KeyOperationResponseV2Dto> response = keyManagementSyncApiClient
                    .destroyKey(connectorInfo, request);
            KeyOperationResponseV2Dto body = response.getBody();
            if (response.getStatusCode().value() != 200 || body == null || body.getOperationMeta() != null) {
                throw new ConnectorException("Connector did not confirm synchronous key destruction.");
            }
        } catch (ConnectorEntityNotFoundException e) {
            log
                    .info("Key item '{}' for key {} was not found on the remote token; treating destruction as successful",
                            reference.toIdentifierString(), cryptographicKey.toIdentifierString());
        } catch (ConnectorException e) {
            if (TokenInstanceStatus.DEACTIVATED.equals(cryptographicKey.tokenInstance().status())) {
                log
                        .warn("Key item '{}' destruction failed; allowing local cleanup because Token '{}' is DEACTIVATED.",
                                reference.toIdentifierString(), cryptographicKey.tokenInstance().toIdentifierString());
            } else {
                throw e;
            }
        }
    }

    @Override
    public List<ProviderKeyItem> createKey(TokenProfileFullModel tokenProfile, KeyRequestType type,
            List<RequestAttribute> attributes, String keyName) throws ConnectorException {
        CreateKeyRequestV2Dto request = createKeyRequest(tokenProfile, type, attributes);
        ResponseEntity<KeyCreationResponseV2Dto> response = keyManagementSyncApiClient
                .createKey(connectorInfo, request);
        KeyCreationResponseV2Dto body = response.getBody();
        if (response.getStatusCode().value() != 200 || body == null || body.getKeyRequestType() != type) {
            throw new ConnectorException("Connector did not return the requested synchronous key creation result.");
        }

        if (body instanceof KeyPairDataResponseV2Dto keyPair) {
            List<ProviderKeyItem> keyItems = toCreatedKeyPair(keyPair, keyName);
            List<String> keyReferences = keyItems
                    .stream()
                    .map(ProviderKeyItem::reference)
                    .map(RemoteKeyReference::toIdentifierString)
                    .toList();
            log
                    .info("A key pair has been created for token profile {} through connector {}; Key references: {}",
                            tokenProfile.toIdentifierString(), connectorInfo.getUuid(), keyReferences);
            return keyItems;
        }
        if (body instanceof SecretKeyDataResponseV2Dto secretKey) {
            ProviderKeyItem secretKeyItem = toCreatedKeyItem(keyName, secretKey.getKeyData(), secretKey.getKeyMeta(),
                    null);
            log
                    .info("A secret key has been created for token profile {} through connector {}; Key reference: {}",
                            tokenProfile.toIdentifierString(), connectorInfo.getUuid(),
                            secretKeyItem.reference().toIdentifierString());
            return List.of(secretKeyItem);
        }
        throw new ConnectorException("Connector returned an unsupported key creation result.");
    }

    private CreateKeyRequestV2Dto createKeyRequest(TokenProfileFullModel tokenProfile, KeyRequestType type,
            List<RequestAttribute> attributes) throws ConnectorException {
        TokenProfileScopedRequestV2Dto scope = tokenProfileScopedRequest(tokenProfile);
        String keyCreationId = UUID.randomUUID().toString();
        CreateKeyRequestV2Dto request = new CreateKeyRequestV2Dto();
        request.setTokenAttributes(scope.getTokenAttributes());
        request.setTokenProfileAttributes(scope.getTokenProfileAttributes());
        request.setKeyUsages(scope.getKeyUsages());
        request.setKeyRequestType(type);
        request.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        request.setKeyCreationId(keyCreationId);
        request.setCreateKeyAttributes(attributes);
        return request;
    }

    private List<ProviderKeyItem> toCreatedKeyPair(KeyPairDataResponseV2Dto response, String keyName) {
        PublicKeyDataResponseV2Dto publicKey = response.getPublicKeyData();
        byte[] publicKeySpki = publicKey.getKeyData().getPublicKeySpki();
        String serializedPublicKeyValue = Base64.getEncoder().encodeToString(publicKeySpki);
        KeyMaterial publicKeyMaterial = new KeyMaterial(KeyFormat.SPKI, serializedPublicKeyValue);
        String publicKeyName = keyName + " public key";
        ProviderKeyItem publicKeyItem = toCreatedKeyItem(publicKeyName, publicKey.getKeyData(), publicKey.getKeyMeta(),
                publicKeyMaterial);

        PrivateKeyDataResponseV2Dto privateKey = response.getPrivateKeyData();
        String privateKeyName = keyName + " private key";
        ProviderKeyItem privateKeyItem = toCreatedKeyItem(privateKeyName, privateKey.getKeyData(),
                privateKey.getKeyMeta(), null);
        return List.of(publicKeyItem, privateKeyItem);
    }

    private ProviderKeyItem toCreatedKeyItem(String name, KeyDataV2Dto data, List<MetadataAttribute> keyMeta,
            KeyMaterial material) {
        KeyType type = switch (data.getType()) {
            case PUBLIC -> KeyType.PUBLIC_KEY;
            case PRIVATE -> KeyType.PRIVATE_KEY;
            case SECRET -> KeyType.SECRET_KEY;
        };
        RemoteKeyReference reference = new RemoteKeyReference.MetadataReference(keyMeta);
        return new ProviderKeyItem(name, type, data.getAlgorithm(), data.getLength(), reference, material,
                data.getMetadata());
    }

    @Override
    public List<BaseAttribute> listCreateKeyAttributes(TokenProfileFullModel tokenProfile, KeyRequestType type)
            throws ConnectorException {
        TokenProfileScopedRequestV2Dto tokenProfileScopedRequest = tokenProfileScopedRequest(tokenProfile);
        CreateKeyAttributesRequestV2Dto attributes = CreateKeyAttributesRequestV2Dto
                .fromTokenProfileScopedRequest(tokenProfileScopedRequest, type);
        Set<String> expandedSecrets = new HashSet<>();
        outboundSecretContainment.recordExpandedSecretsFromRequest(attributes.getTokenAttributes(), expandedSecrets);
        outboundSecretContainment
                .recordExpandedSecretsFromRequest(attributes.getTokenProfileAttributes(), expandedSecrets);
        List<BaseAttribute> definitions = keyManagementSyncApiClient.listCreateKeyAttributes(connectorInfo, attributes);
        outboundSecretContainment.assertNoExpandedSecretOutbound(definitions, expandedSecrets);
        return definitions;
    }

    private TokenProfileScopedRequestV2Dto tokenProfileScopedRequest(TokenProfileBasicModel tokenProfile)
            throws ConnectorException {
        UUID connectorUuid = UUID.fromString(connectorInfo.getUuid());
        List<RequestAttribute> storedTokenAttributes = attributeEngine
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.TOKEN, tokenProfile.tokenInstanceReferenceUuid())
                        .connector(connectorUuid)
                        .build());

        List<RequestAttribute> resolvedTokenAttributes = operationAttributeResolver
                .resolveForConnectorRequestAsSystem(connectorUuid, storedTokenAttributes);

        List<RequestAttribute> storedProfileAttributes = attributeEngine
                .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                        .builder(Resource.TOKEN_PROFILE, tokenProfile.uuid())
                        .connector(connectorUuid)
                        .build());
        List<RequestAttribute> resolvedTokenProfileAttributes = operationAttributeResolver
                .resolveForConnectorRequestAsSystem(connectorUuid, storedProfileAttributes);

        TokenProfileScopedRequestV2Dto request = new TokenProfileScopedRequestV2Dto();
        request.setTokenAttributes(resolvedTokenAttributes);
        request.setTokenProfileAttributes(resolvedTokenProfileAttributes);
        request.setKeyUsages(Set.copyOf(tokenProfile.usages()));
        return request;
    }

}
