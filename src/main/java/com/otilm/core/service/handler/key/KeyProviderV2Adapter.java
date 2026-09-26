package com.otilm.core.service.handler.key;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.CryptographicOperationsSyncApiClient;
import com.otilm.api.interfaces.client.v2.KeySyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
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
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.common.v2.OperationStatus;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.KeyScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.OperationResponseValidator;
import com.otilm.api.model.connector.cryptography.v2.OperationTrackingRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.TokenProfileScopedRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.CreateKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.DestroyKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ExportKeyResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyAttributesRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyResultRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyCreationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyExportableAttribute;
import com.otilm.api.model.connector.cryptography.v2.key.KeyOperationResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairOperationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyOperationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.TransferableKeyTypeV2Dto;
import com.otilm.api.model.connector.cryptography.v2.material.EncryptedKeyMaterialV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.CipherDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.SignatureAlgorithmAttribute;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.VerifyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.CipherDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.SignatureDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.operations.data.VerificationResponseItemV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.CryptographyV2ApiClients;
import com.otilm.core.key.normalization.NormalizedKey;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.KeyImportAttempt;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.function.Function;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/** Synchronous stateless cryptography-provider v2 key management. */
@Slf4j
public class KeyProviderV2Adapter implements KeyProviderAdapter {

    private static final String IMPORT_REFUSED = "The connector refused to import the key (%s).";
    private static final String IMPORT_FAILED = "The connector failed to import the key.";
    private static final String IMPORT_UNREPORTED = "The connector failed to report on the key import.";

    private final ApiClientConnectorInfo connectorInfo;
    private final KeySyncApiClient keyManagementSyncApiClient;
    private final AttributeEngine attributeEngine;
    private final OperationAttributeResolver operationAttributeResolver;
    private final OutboundSecretContainment outboundSecretContainment;
    private final CryptographicOperationsSyncApiClient operationsApiClient;
    private final ConnectorCapabilityService connectorCapabilityService;
    private final OperationResponseValidator responseValidator;

    public KeyProviderV2Adapter(CryptographyV2ApiClients apiClients, ApiClientConnectorInfo connectorInfo,
            AttributeEngine attributeEngine, OperationAttributeResolver operationAttributeResolver,
            OutboundSecretContainment outboundSecretContainment, ConnectorCapabilityService connectorCapabilityService,
            OperationResponseValidator responseValidator) {
        this.connectorInfo = connectorInfo;
        this.attributeEngine = attributeEngine;
        this.operationAttributeResolver = operationAttributeResolver;
        this.outboundSecretContainment = outboundSecretContainment;
        this.connectorCapabilityService = connectorCapabilityService;
        this.responseValidator = responseValidator;
        this.keyManagementSyncApiClient = apiClients.getKeyManagementApiClient(connectorInfo);
        this.operationsApiClient = apiClients.getCryptographicOperationsApiClient(connectorInfo);
    }

    @Override
    public List<ProviderKeyItem> listKeys(TokenInstanceBasicModel tokenInstance) {
        throw new UnsupportedOperationException("Stateless provider key listing is not implemented.");
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
            List<RequestAttribute> attributes, String keyName, boolean exportable) throws ConnectorException {
        CreateKeyRequestV2Dto request = createKeyRequest(tokenProfile, type, attributes, exportable);
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
            List<RequestAttribute> attributes, boolean exportable) throws ConnectorException {
        TokenProfileScopedRequestV2Dto scope = tokenProfileScopedRequest(tokenProfile);
        String keyCreationId = UUID.randomUUID().toString();
        CreateKeyRequestV2Dto request = new CreateKeyRequestV2Dto();
        request.setTokenAttributes(scope.getTokenAttributes());
        request.setTokenProfileAttributes(scope.getTokenProfileAttributes());
        request.setKeyRequestType(type);
        request.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        request.setKeyCreationId(keyCreationId);
        request.setCreateKeyAttributes(withExportableIntent(tokenProfile, attributes, exportable));
        return request;
    }

    /**
     * The create attributes with the contract-reserved exportable intent stated on them, for a connector that declares
     * key export. A connector that does not has no term for the attribute and receives none, whatever the caller
     * stated. The intent travels as an attribute so that a replay under the same {@code keyCreationId} carries
     * identical terms.
     */
    private List<RequestAttribute> withExportableIntent(TokenProfileFullModel tokenProfile,
            List<RequestAttribute> attributes, boolean exportable) {
        List<RequestAttribute> stated = new ArrayList<>(attributes == null ? List.of() : attributes);
        stated.removeIf(attribute -> KeyExportableAttribute.NAME.equals(attribute.getName()));
        if (!connectorCapabilityService
                .supports(tokenProfile.tokenInstance().connectorInterface(), FeatureFlag.KEY_EXPORT)) {
            return stated;
        }
        stated.add(KeyExportableAttribute.request(exportable));
        return stated;
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
    public List<TransferableKeyType> listExportableKeyTypes(TokenProfileFullModel tokenProfile)
            throws ConnectorException {
        return transferable(keyManagementSyncApiClient
                .listExportableKeyTypes(connectorInfo, tokenProfileScopedRequest(tokenProfile)));
    }

    @Override
    public List<TransferableKeyType> listImportableKeyTypes(TokenProfileFullModel tokenProfile)
            throws ConnectorException {
        return transferable(keyManagementSyncApiClient
                .listImportableKeyTypes(connectorInfo, tokenProfileScopedRequest(tokenProfile)));
    }

    private static List<TransferableKeyType> transferable(List<? extends TransferableKeyTypeV2Dto> declared) {
        return declared
                .stream()
                .map(type -> new TransferableKeyType(type.getKeyRequestType(), type.getAlgorithms()))
                .toList();
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
        return withoutReservedExportable(definitions);
    }

    @Override
    public List<BaseAttribute> listImportKeyAttributes(TokenProfileFullModel tokenProfile, KeyRequestType type)
            throws ConnectorException {
        TokenProfileScopedRequestV2Dto scope = tokenProfileScopedRequest(tokenProfile);
        ImportKeyAttributesRequestV2Dto request = new ImportKeyAttributesRequestV2Dto();
        request.setTokenAttributes(scope.getTokenAttributes());
        request.setTokenProfileAttributes(scope.getTokenProfileAttributes());
        request.setKeyRequestType(type);
        return publishDefinitions(request,
                withoutReservedExportable(keyManagementSyncApiClient.listImportKeyAttributes(connectorInfo, request)));
    }

    /**
     * The schema without the contract-reserved exportable attribute. Core takes the intent from the request's own field
     * and states it to the connector itself, so offering the attribute as well would give a caller a second control
     * that the stated intent then overrides.
     */
    private static List<BaseAttribute> withoutReservedExportable(List<BaseAttribute> definitions) {
        return definitions
                .stream()
                .filter(definition -> !KeyExportableAttribute.NAME.equals(definition.getName()))
                .toList();
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
        return request;
    }

    @Override
    public EncryptDataResponseDto encryptData(OperationKeyContext context, CipherDataRequestDto request)
            throws ConnectorException {
        EncryptDataResponseDto result = new EncryptDataResponseDto();
        result
                .setEncryptedData(cipherData(context, request,
                        schemaRequest -> operationsApiClient.listEncryptAttributes(connectorInfo, schemaRequest),
                        body -> operationsApiClient.encryptData(connectorInfo, body).getEncryptedData()));
        return result;
    }

    @Override
    public DecryptDataResponseDto decryptData(OperationKeyContext context, CipherDataRequestDto request)
            throws ConnectorException {
        DecryptDataResponseDto result = new DecryptDataResponseDto();
        result
                .setDecryptedData(cipherData(context, request,
                        schemaRequest -> operationsApiClient.listDecryptAttributes(connectorInfo, schemaRequest),
                        body -> operationsApiClient.decryptData(connectorInfo, body).getDecryptedData()));
        return result;
    }

    private List<CipherResponseData> cipherData(OperationKeyContext context, CipherDataRequestDto request,
            ConnectorCall<KeyScopedRequestV2Dto, List<BaseAttribute>> schemaCall,
            ConnectorCall<CipherDataRequestV2Dto, List<CipherDataV2Dto>> operationCall) throws ConnectorException {
        List<RequestAttribute> attributes = orEmpty(request.getCipherAttributes());
        TokenProfileScopedRequestV2Dto scope = validatedScope(context, schemaCall, attributes);
        IdentifiedBatch<CipherDataV2Dto> batch = cipherBatch(request.getCipherData());
        CipherDataRequestV2Dto body = keyScoped(new CipherDataRequestV2Dto(), context, scope);
        body.setCipherAttributes(attributes);
        body.setCipherData(batch.items());
        return inRequestOrder(operationCall.call(body), batch, CipherDataV2Dto::getIdentifier, (item, identifier) -> {
            CipherResponseData data = new CipherResponseData();
            data.setData(encodeRequired(item.getData()));
            data.setIdentifier(identifier);
            return data;
        });
    }

    /**
     * The contract fixes the name and values of the attribute that selects the algorithm, so Core reads the selection
     * itself. The connector refuses, at signing, a selection its key does not support.
     */
    @Override
    public ResolvedSignatureAlgorithm resolveSignatureAlgorithm(CryptographicKeyItemOperationModel privateKeyItem,
            CryptographicKeyItemOperationModel publicKeyItem, List<RequestAttribute> signatureAttributes) {
        SignatureAlgorithm algorithm = SignatureAlgorithmAttribute.selectedAlgorithm(signatureAttributes);
        if (!signsWith(algorithm, privateKeyItem.keyAlgorithm(), publicKeyItem.pqcParameterSpecName())) {
            String signingKey = publicKeyItem.pqcParameterSpecName() == null
                    ? privateKeyItem.keyAlgorithm().getCode()
                    : publicKeyItem.pqcParameterSpecName();
            throw new ValidationException(ValidationError
                    .create("Signature algorithm {} does not fit the signing key ({}).", algorithm.getCode(),
                            signingKey));
        }
        return ResolvedSignatureAlgorithm.of(algorithm);
    }

    /** A post-quantum algorithm is its key's parameter set, so it must name the one the key was generated with. */
    private static boolean signsWith(SignatureAlgorithm algorithm, KeyAlgorithm keyAlgorithm,
            String pqcParameterSpecName) {
        return switch (algorithm) {
            case SHA256_WITH_RSA, SHA384_WITH_RSA, SHA512_WITH_RSA, SHA256_WITH_RSA_PSS, SHA384_WITH_RSA_PSS,
                    SHA512_WITH_RSA_PSS ->
                keyAlgorithm == KeyAlgorithm.RSA;
            case SHA256_WITH_ECDSA, SHA384_WITH_ECDSA, SHA512_WITH_ECDSA -> keyAlgorithm == KeyAlgorithm.ECDSA;
            case ED25519, ED448 -> false;
            case FALCON_1024, ML_DSA_44, ML_DSA_65, ML_DSA_87, SLH_DSA_SHA2_128S, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_192S,
                    SLH_DSA_SHA2_192F, SLH_DSA_SHA2_256S, SLH_DSA_SHA2_256F ->
                algorithm.getCode().equalsIgnoreCase(pqcParameterSpecName);
        };
    }

    @Override
    public SignDataResponseDto signData(OperationKeyContext context, SignDataRequestDto request)
            throws ConnectorException {
        List<RequestAttribute> attributes = orEmpty(request.getSignatureAttributes());
        TokenProfileScopedRequestV2Dto scope = validatedScope(context,
                schemaRequest -> operationsApiClient.listSignAttributes(connectorInfo, schemaRequest), attributes);
        IdentifiedBatch<SignatureDataV2Dto> batch = signatureBatch(request.getData());
        SignDataRequestV2Dto body = keyScoped(new SignDataRequestV2Dto(), context, scope);
        body.setExecutionMode(OperationExecutionMode.SYNCHRONOUS);
        body.setSignatureAttributes(attributes);
        body.setData(batch.items());
        ResponseEntity<SignDataResponseV2Dto> response = operationsApiClient.signData(connectorInfo, body);
        SignDataResponseV2Dto responseBody = response.getBody();
        if (response.getStatusCode().value() != 200 || responseBody == null || responseBody.getSignatures() == null
                || responseBody.getSignatures().isEmpty() || responseBody.getOperationMeta() != null) {
            throw new ConnectorException("Connector did not return a synchronous signing result.");
        }
        SignDataResponseDto result = new SignDataResponseDto();
        result
                .setSignatures(inRequestOrder(responseBody.getSignatures(), batch, SignatureDataV2Dto::getIdentifier,
                        (item, identifier) -> {
                            SignatureResponseData data = new SignatureResponseData();
                            data.setData(encodeRequired(item.getData()));
                            data.setIdentifier(identifier);
                            return data;
                        }));
        return result;
    }

    @Override
    public VerifyDataResponseDto verifyData(OperationKeyContext context, VerifyDataRequestDto request)
            throws ConnectorException {
        if (request.getData() == null || request.getSignatures() == null
                || request.getData().size() != request.getSignatures().size()) {
            throw new ValidationException(ValidationError.create("Verification requires one signature per data item."));
        }
        requireAlignedIdentifiers(request.getData(), request.getSignatures());
        List<RequestAttribute> attributes = orEmpty(request.getSignatureAttributes());
        TokenProfileScopedRequestV2Dto scope = validatedScope(context,
                schemaRequest -> operationsApiClient.listVerifyAttributes(connectorInfo, schemaRequest), attributes);
        IdentifiedBatch<SignatureDataV2Dto> data = signatureBatch(request.getData());
        IdentifiedBatch<SignatureDataV2Dto> signatures = signatureBatch(request.getSignatures());
        VerifyDataRequestV2Dto body = keyScoped(new VerifyDataRequestV2Dto(), context, scope);
        body.setSignatureAttributes(attributes);
        body.setData(data.items());
        body.setSignatures(signatures.items());
        VerifyDataResponseV2Dto response = operationsApiClient.verifyData(connectorInfo, body);
        if (response == null || response.getVerifications() == null) {
            throw new ConnectorException("Connector returned no verification result.", connectorInfo);
        }
        // The connector's free-form details reach the caller, so they get the same containment as a schema.
        assertNoExpandedSecretEchoed(scope, response);
        VerifyDataResponseDto result = new VerifyDataResponseDto();
        result
                .setVerifications(inRequestOrder(response.getVerifications(), data,
                        VerificationResponseItemV2Dto::getIdentifier, (item, identifier) -> {
                            VerificationResponseData verification = new VerificationResponseData();
                            verification.setResult(Boolean.TRUE.equals(item.getResult()));
                            verification.setIdentifier(identifier);
                            verification.setDetails(item.getDetails());
                            return verification;
                        }));
        return result;
    }

    @Override
    public List<BaseAttribute> listEncryptAttributes(OperationKeyContext context) throws ConnectorException {
        return listOperationAttributes(context,
                request -> operationsApiClient.listEncryptAttributes(connectorInfo, request));
    }

    @Override
    public List<BaseAttribute> listDecryptAttributes(OperationKeyContext context) throws ConnectorException {
        return listOperationAttributes(context,
                request -> operationsApiClient.listDecryptAttributes(connectorInfo, request));
    }

    @Override
    public List<BaseAttribute> listSignAttributes(OperationKeyContext context) throws ConnectorException {
        return listOperationAttributes(context,
                request -> operationsApiClient.listSignAttributes(connectorInfo, request));
    }

    @Override
    public List<BaseAttribute> listVerifyAttributes(OperationKeyContext context) throws ConnectorException {
        return listOperationAttributes(context,
                request -> operationsApiClient.listVerifyAttributes(connectorInfo, request));
    }

    @Override
    public List<BaseAttribute> listExportKeyAttributes(OperationKeyContext context) throws ConnectorException {
        return listOperationAttributes(context,
                request -> keyManagementSyncApiClient.listExportKeyAttributes(connectorInfo, request));
    }

    /**
     * The connector's answer is checked twice before the envelope is handed on: it must echo no secret the request
     * carried, the passphrase included, and its descriptor must be the key the platform holds. The envelope itself is
     * never opened.
     */
    @Override
    public byte[] exportKey(OperationKeyContext context, HeldKey heldKey, Passphrase passphrase,
            List<RequestAttribute> attributes) throws ConnectorException {
        List<RequestAttribute> stated = orEmpty(attributes);
        TokenProfileScopedRequestV2Dto scope = validatedScope(context,
                request -> keyManagementSyncApiClient.listExportKeyAttributes(connectorInfo, request), stated);
        ExportKeyRequestV2Dto request = keyScoped(new ExportKeyRequestV2Dto(), context, scope);
        request.setKeyRequestType(heldKey.type());
        request.setKeyReference(heldKey.keyReference() == null ? null : heldKey.keyReference().toString());
        request.setExportKeyAttributes(stated);
        String sentPassphrase = new String(passphrase.characters());
        request.setPassphrase(sentPassphrase);
        ExportKeyResponseV2Dto response = sendExport(request, context.keyItem().keyItemUuid());

        Set<String> sentSecrets = new HashSet<>();
        sentSecrets.add(sentPassphrase);
        outboundSecretContainment.recordExpandedSecretsFromRequest(scope.getTokenAttributes(), sentSecrets);
        outboundSecretContainment.recordExpandedSecretsFromRequest(scope.getTokenProfileAttributes(), sentSecrets);
        outboundSecretContainment.assertNoExpandedSecretOutbound(response, sentSecrets);
        if (!responseValidator.keyTransfer().validateExportedKeyDescriptor(descriptorOf(heldKey), response).isValid()) {
            throw connectorFault("Connector described a key other than the one the platform holds.");
        }
        return response.getMaterial().getEncryptedPrivateKeyInfo();
    }

    /**
     * The request carries the passphrase, so whatever the connector answers when the export does not succeed may carry
     * it back. Its words are dropped: a refusal is named by its error code, anything else is a failure.
     */
    private ExportKeyResponseV2Dto sendExport(ExportKeyRequestV2Dto request, UUID keyItemUuid)
            throws ConnectorServerException {
        try {
            return keyManagementSyncApiClient.exportKey(connectorInfo, request);
        } catch (ConnectorException | RuntimeException e) {
            if (e instanceof ConnectorProblemException problem && isRefusal(problem.getProblemDetail())) {
                throw new ValidationException(ValidationError
                        .create("The connector refused to export key item %s (%s)."
                                .formatted(keyItemUuid, problem.getProblemDetail().getErrorCode().name())));
            }
            throw connectorFault("The connector failed to export key item %s.".formatted(keyItemUuid));
        }
    }

    /**
     * The request carries the envelope and the passphrase that opens it, so the connector's answer is checked to echo
     * neither, and its words are dropped when the import does not succeed.
     */
    @Override
    public ImportAnswer importKey(KeyImportTerms terms, KeyImportAttempt attempt, NormalizedKey key, String keyName)
            throws ConnectorException {
        TokenProfileScopedRequestV2Dto scope = tokenProfileScopedRequest(terms.profile());
        ImportKeyRequestV2Dto request = importRequest(terms, attempt, key, scope);
        ResponseEntity<KeyCreationResponseV2Dto> response = sendImport(request);
        Set<String> sentSecrets = scopeSecrets(scope);
        sentSecrets.addAll(key.transportSecrets());
        KeyCreationResponseV2Dto body = response.getBody();
        if (body == null) {
            throw connectorFault(IMPORT_FAILED);
        }
        outboundSecretContainment.assertNoExpandedSecretOutbound(body, sentSecrets, attempt.secretDigests());
        if (response.getStatusCode().value() == HttpStatus.ACCEPTED.value()) {
            return new ImportAnswer.Running(body.getOperationMeta());
        }
        return imported(body, keyName);
    }

    private ImportKeyRequestV2Dto importRequest(KeyImportTerms terms, KeyImportAttempt attempt, NormalizedKey key,
            TokenProfileScopedRequestV2Dto scope) {
        ImportKeyRequestV2Dto request = new ImportKeyRequestV2Dto();
        request.setTokenAttributes(scope.getTokenAttributes());
        request.setTokenProfileAttributes(scope.getTokenProfileAttributes());
        request.setKeyImportId(attempt.uuid().toString());
        request.setKeyReference(attempt.keyReference().toString());
        request
                .setExecutionMode(connectorCapabilityService
                        .supports(terms.profile().tokenInstance().connectorInterface(), FeatureFlag.ASYNCHRONOUS)
                                ? OperationExecutionMode.ASYNCHRONOUS
                                : OperationExecutionMode.SYNCHRONOUS);
        request.setKeyRequestType(terms.type());
        request.setImportKeyAttributes(orEmpty(terms.importAttributes()));
        EncryptedKeyMaterialV2Dto material = new EncryptedKeyMaterialV2Dto();
        material.setEncryptedPrivateKeyInfo(key.encryptedPrivateKeyInfo());
        request.setMaterial(material);
        char[] passphrase = key.transportPassphrase().characters();
        request.setPassphrase(new String(passphrase));
        Arrays.fill(passphrase, '\0');
        request.setExportable(terms.exportable());
        return request;
    }

    /**
     * A refusal is named by its error code, anything else is a failure. A connector that reports the import identifier
     * taken holds an import under it, so what it holds is still to be learned rather than refused.
     */
    private ResponseEntity<KeyCreationResponseV2Dto> sendImport(ImportKeyRequestV2Dto request)
            throws ConnectorServerException {
        try {
            return keyManagementSyncApiClient.importKey(connectorInfo, request);
        } catch (ConnectorException | RuntimeException e) {
            if (e instanceof ConnectorProblemException problem && isRefusal(problem.getProblemDetail())
                    && problem.getProblemDetail().getErrorCode() != ErrorCode.RESOURCE_ALREADY_EXISTS) {
                throw new ValidationException(ValidationError
                        .create(IMPORT_REFUSED.formatted(problem.getProblemDetail().getErrorCode().name())));
            }
            throw connectorFault(IMPORT_FAILED);
        }
    }

    @Override
    public ImportAnswer importKeyStatus(TokenProfileFullModel tokenProfile, List<MetadataAttribute> operationMeta,
            List<String> secretDigests, String keyName) throws ConnectorException {
        OperationTrackingRequestV2Dto request = new OperationTrackingRequestV2Dto();
        request.setOperationMeta(operationMeta);
        KeyCreationStatusResponseV2Dto status;
        try {
            status = keyManagementSyncApiClient.getImportKeyStatus(connectorInfo, request);
        } catch (ConnectorException | RuntimeException e) {
            throw connectorFault(IMPORT_UNREPORTED);
        }
        // Only a completed answer is stored, as the key it describes, so only then are the credentials looked up.
        Set<String> withheld = status.getStatus() == OperationStatus.COMPLETED
                ? scopeSecrets(tokenProfileScopedRequest(tokenProfile))
                : Set.of();
        outboundSecretContainment.assertNoExpandedSecretOutbound(status, withheld, secretDigests);
        return answerOf(status, operationMeta, keyName);
    }

    @Override
    public ImportAnswer importKeyResult(TokenProfileFullModel tokenProfile, UUID keyImportId,
            List<String> secretDigests, String keyName) throws ConnectorException {
        TokenProfileScopedRequestV2Dto scope = tokenProfileScopedRequest(tokenProfile);
        ImportKeyResultRequestV2Dto request = new ImportKeyResultRequestV2Dto();
        request.setTokenAttributes(scope.getTokenAttributes());
        request.setKeyImportId(keyImportId.toString());
        KeyCreationStatusResponseV2Dto status;
        try {
            status = keyManagementSyncApiClient.getImportKeyResult(connectorInfo, request);
        } catch (ConnectorException | RuntimeException e) {
            if (isNotFound(e)) {
                return new ImportAnswer.NotAccepted();
            }
            throw connectorFault(IMPORT_UNREPORTED);
        }
        outboundSecretContainment.assertNoExpandedSecretOutbound(status, scopeSecrets(scope), secretDigests);
        return answerOf(status, null, keyName);
    }

    /** The credentials of the token and the token profile, which no answer about an import may carry back. */
    private Set<String> scopeSecrets(TokenProfileScopedRequestV2Dto scope) {
        Set<String> secrets = new HashSet<>();
        outboundSecretContainment.recordExpandedSecretsFromRequest(scope.getTokenAttributes(), secrets);
        outboundSecretContainment.recordExpandedSecretsFromRequest(scope.getTokenProfileAttributes(), secrets);
        return secrets;
    }

    @Override
    public boolean cancelImportKey(List<MetadataAttribute> operationMeta) {
        OperationTrackingRequestV2Dto request = new OperationTrackingRequestV2Dto();
        request.setOperationMeta(operationMeta);
        try {
            ResponseEntity<Void> response = keyManagementSyncApiClient.cancelImportKey(connectorInfo, request);
            return response != null && response.getStatusCode().value() == HttpStatus.NO_CONTENT.value();
        } catch (ConnectorException | RuntimeException e) {
            log
                    .info("Connector {} did not abort a key import: {}", connectorInfo.getUuid(),
                            e.getClass().getSimpleName());
            return false;
        }
    }

    /** A connector with no record of the import answers 404, with a problem document or without one. */
    private static boolean isNotFound(Exception e) {
        return e instanceof ConnectorEntityNotFoundException || e instanceof ConnectorProblemException problem
                && problem.getProblemDetail().getStatus() == HttpStatus.NOT_FOUND.value();
    }

    private ImportAnswer answerOf(KeyCreationStatusResponseV2Dto status, List<MetadataAttribute> operationMeta,
            String keyName) {
        return switch (status.getStatus()) {
            case IN_PROGRESS -> new ImportAnswer.Running(operationMeta);
            case COMPLETED -> imported(resultOf(status), keyName);
            case FAILED, CANCELLED -> new ImportAnswer.NotImported();
        };
    }

    private static KeyCreationResponseV2Dto resultOf(KeyCreationStatusResponseV2Dto status) {
        return switch (status) {
            case KeyPairOperationStatusResponseV2Dto keyPair -> keyPair.getResult();
            case SecretKeyOperationStatusResponseV2Dto secretKey -> secretKey.getResult();
        };
    }

    private ImportAnswer imported(KeyCreationResponseV2Dto body, String keyName) {
        List<ProviderKeyItem> items = switch (body) {
            case KeyPairDataResponseV2Dto keyPair -> toCreatedKeyPair(keyPair, keyName);
            case SecretKeyDataResponseV2Dto secretKey ->
                List.of(toCreatedKeyItem(keyName, secretKey.getKeyData(), secretKey.getKeyMeta(), null));
        };
        return new ImportAnswer.Imported(body.getKeyRequestType(), items);
    }

    /**
     * A client error the connector named with a code; 401 and 403 turn away the platform's credentials, not the key.
     */
    private static boolean isRefusal(ProblemDetailExtended problem) {
        int status = problem.getStatus();
        return problem.getErrorCode() != null && HttpStatus.Series.resolve(status) == HttpStatus.Series.CLIENT_ERROR
                && status != HttpStatus.UNAUTHORIZED.value() && status != HttpStatus.FORBIDDEN.value();
    }

    private ConnectorServerException connectorFault(String message) {
        ConnectorServerException fault = new ConnectorServerException(message, HttpStatus.BAD_GATEWAY);
        fault.setConnector(connectorInfo);
        return fault;
    }

    private static KeyDataV2Dto descriptorOf(HeldKey heldKey) {
        if (heldKey.type() == KeyRequestType.SECRET) {
            SecretKeyDataV2Dto secretKey = new SecretKeyDataV2Dto();
            secretKey.setAlgorithm(heldKey.algorithm());
            secretKey.setLength(heldKey.length());
            return secretKey;
        }
        PublicKeyDataV2Dto publicKey = new PublicKeyDataV2Dto();
        publicKey.setAlgorithm(heldKey.algorithm());
        publicKey.setLength(heldKey.length());
        publicKey.setPublicKeySpki(heldKey.publicKeySpki());
        return publicKey;
    }

    private List<BaseAttribute> listOperationAttributes(OperationKeyContext context,
            ConnectorCall<KeyScopedRequestV2Dto, List<BaseAttribute>> schemaCall) throws ConnectorException {
        KeyScopedRequestV2Dto request = keyScoped(new KeyScopedRequestV2Dto(), context,
                tokenProfileScopedRequest(context.tokenProfile()));
        return publishDefinitions(request, fetchSchema(schemaCall, request));
    }

    private <T extends KeyScopedRequestV2Dto> T keyScoped(T request, OperationKeyContext context,
            TokenProfileScopedRequestV2Dto scope) {
        if (!(context
                .keyItem()
                .reference() instanceof RemoteKeyReference.MetadataReference(List<MetadataAttribute> keyMeta))
                || keyMeta == null || keyMeta.isEmpty()) {
            throw new ValidationException(
                    ValidationError.create("V2 cryptographic operations require a non-empty metadata handle."));
        }
        request.setTokenAttributes(scope.getTokenAttributes());
        request.setTokenProfileAttributes(scope.getTokenProfileAttributes());
        request.setKeyMeta(keyMeta);
        return request;
    }

    private List<BaseAttribute> fetchSchema(ConnectorCall<KeyScopedRequestV2Dto, List<BaseAttribute>> schemaCall,
            KeyScopedRequestV2Dto request) throws ConnectorException {
        List<BaseAttribute> definitions = schemaCall.call(request);
        if (definitions == null) {
            throw new ConnectorException("Connector returned no attribute schema", connectorInfo);
        }
        return definitions;
    }

    private void assertNoExpandedSecretEchoed(TokenProfileScopedRequestV2Dto sentScope, Object payload) {
        Set<String> expandedSecrets = new HashSet<>();
        outboundSecretContainment.recordExpandedSecretsFromRequest(sentScope.getTokenAttributes(), expandedSecrets);
        outboundSecretContainment
                .recordExpandedSecretsFromRequest(sentScope.getTokenProfileAttributes(), expandedSecrets);
        outboundSecretContainment.assertNoExpandedSecretOutbound(payload, expandedSecrets);
    }

    /** Guards expanded secrets and persists the schema so attribute callbacks can resolve against it. */
    private List<BaseAttribute> publishDefinitions(TokenProfileScopedRequestV2Dto request,
            List<BaseAttribute> definitions) throws ConnectorException {
        assertNoExpandedSecretEchoed(request, definitions);
        try {
            attributeEngine.updateDataAttributeDefinitions(UUID.fromString(connectorInfo.getUuid()), null, definitions);
        } catch (AttributeException e) {
            throw new ConnectorException("Unable to persist operation attributes returned by connector", e,
                    connectorInfo);
        }
        return definitions;
    }

    /**
     * Resolves the token-profile scope once, fetches the operation schema with it and validates the submitted
     * attributes in memory. Nothing the connector returns here is persisted, and a schema echoing a secret the request
     * carried is refused as on the listing path.
     */
    private TokenProfileScopedRequestV2Dto validatedScope(OperationKeyContext context,
            ConnectorCall<KeyScopedRequestV2Dto, List<BaseAttribute>> schemaCall, List<RequestAttribute> attributes)
            throws ConnectorException {
        TokenProfileScopedRequestV2Dto scope = tokenProfileScopedRequest(context.tokenProfile());
        KeyScopedRequestV2Dto request = keyScoped(new KeyScopedRequestV2Dto(), context, scope);
        List<BaseAttribute> definitions = fetchSchema(schemaCall, request);
        assertNoExpandedSecretEchoed(request, definitions);
        AttributeDefinitionUtils.validateAttributes(definitions, attributes);
        return scope;
    }

    /**
     * Restores the order Core sent from the positional identifiers it assigned, so a connector that correlates by
     * identifier and reorders the batch cannot hand the caller a silently permuted result.
     */
    private <S, R> List<R> inRequestOrder(List<S> items, IdentifiedBatch<?> batch, Function<S, String> identifierOf,
            ResultMapper<S, R> toResult) throws ConnectorException {
        List<String> callerIdentifiers = batch.callerIdentifiers();
        if (items.size() != callerIdentifiers.size()) {
            throw new ConnectorException("Connector returned " + items.size() + " results for "
                    + callerIdentifiers.size() + " request items.", connectorInfo);
        }
        List<S> ordered = new ArrayList<>(Collections.nCopies(callerIdentifiers.size(), null));
        for (S item : items) {
            int position = batch.position(identifierOf.apply(item), connectorInfo);
            if (ordered.get(position) != null) {
                throw new ConnectorException("Connector returned the same identifier twice.", connectorInfo);
            }
            ordered.set(position, item);
        }
        List<R> results = new ArrayList<>(ordered.size());
        for (int index = 0; index < ordered.size(); index++) {
            results.add(toResult.map(ordered.get(index), callerIdentifiers.get(index)));
        }
        return results;
    }

    /**
     * Core pairs data with signatures by position, so identifiers the caller sent on both lists must agree there;
     * otherwise each item would be verified against the signature the caller meant for another one.
     */
    private static void requireAlignedIdentifiers(List<SignatureRequestData> data,
            List<SignatureRequestData> signatures) {
        for (int index = 0; index < data.size(); index++) {
            String dataIdentifier = data.get(index).getIdentifier();
            String signatureIdentifier = signatures.get(index).getIdentifier();
            if (dataIdentifier != null && signatureIdentifier != null && !dataIdentifier.equals(signatureIdentifier)) {
                throw new ValidationException(
                        ValidationError.create("Data and signature identifiers must be sent in the same order."));
            }
        }
    }

    private static List<RequestAttribute> orEmpty(List<RequestAttribute> attributes) {
        return attributes == null ? List.of() : attributes;
    }

    private static IdentifiedBatch<CipherDataV2Dto> cipherBatch(List<CipherRequestData> items) {
        return IdentifiedBatch
                .of(items, CipherRequestData::getIdentifier,
                        (item, identifier) -> new CipherDataV2Dto(decode(item.getData()), identifier));
    }

    private static IdentifiedBatch<SignatureDataV2Dto> signatureBatch(List<SignatureRequestData> items) {
        return IdentifiedBatch
                .of(items, SignatureRequestData::getIdentifier,
                        (item, identifier) -> new SignatureDataV2Dto(decode(item.getData()), identifier));
    }

    private static byte[] decode(String base64) {
        if (base64 == null || base64.isEmpty()) {
            throw new ValidationException(ValidationError.create("Every batch item must carry data."));
        }
        return Base64.getDecoder().decode(base64);
    }

    private String encodeRequired(byte[] data) throws ConnectorException {
        if (data == null || data.length == 0) {
            throw new ConnectorException("Connector returned a batch item without data.", connectorInfo);
        }
        return Base64.getEncoder().encodeToString(data);
    }

    /** Sends every item under its position; the caller's identifiers (possibly null) come back by position. */
    private record IdentifiedBatch<T>(List<T> items, List<String> callerIdentifiers) {

        static <S, T> IdentifiedBatch<T> of(List<S> source, Function<S, String> identifierOf,
                BiFunction<S, String, T> toItem) {
            List<T> items = new ArrayList<>(source.size());
            List<String> callerIdentifiers = new ArrayList<>(source.size());
            for (int index = 0; index < source.size(); index++) {
                S item = source.get(index);
                callerIdentifiers.add(identifierOf.apply(item));
                items.add(toItem.apply(item, Integer.toString(index)));
            }
            return new IdentifiedBatch<>(List.copyOf(items), Collections.unmodifiableList(callerIdentifiers));
        }

        /** Resolves the position the connector echoed back, which is the position Core sent the item at. */
        int position(String positionalIdentifier, ApiClientConnectorInfo connector) throws ConnectorException {
            int position;
            try {
                position = Integer.parseInt(positionalIdentifier);
            } catch (NumberFormatException e) {
                throw new ConnectorException("Connector returned an identifier that was not part of the request.", e,
                        connector);
            }
            if (position < 0 || position >= callerIdentifiers.size()) {
                throw new ConnectorException("Connector returned an identifier that was not part of the request.",
                        connector);
            }
            return position;
        }
    }

    @FunctionalInterface
    private interface ConnectorCall<S, T> {
        T call(S request) throws ConnectorException;
    }

    @FunctionalInterface
    private interface ResultMapper<S, R> {
        R map(S item, String callerIdentifier) throws ConnectorException;
    }

}
