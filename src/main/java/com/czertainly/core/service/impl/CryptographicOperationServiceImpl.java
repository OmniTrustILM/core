package com.czertainly.core.service.impl;

import com.czertainly.api.clients.ApiClientConnectorInfo;
import com.czertainly.api.exception.*;
import com.czertainly.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.cryptography.operations.*;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.connector.cryptography.operations.data.CipherRequestData;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.cryptography.key.KeyEvent;
import com.czertainly.api.model.core.cryptography.key.KeyEventStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.core.attribute.*;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.config.TokenContentSigner;
import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.TokenInstanceReference;
import com.czertainly.core.dao.repository.CryptographicKeyItemRepository;
import com.czertainly.core.dao.repository.CryptographicKeyRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.model.crypto.CryptographicKeyItemModel;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.CryptographicKeyEventHistoryService;
import com.czertainly.core.service.CryptographicKeyService;
import com.czertainly.core.service.CryptographicOperationService;
import com.czertainly.core.service.PermissionEvaluator;
import com.czertainly.core.service.TokenInstanceService;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.CertificateRequestUtils;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

@Service
public class CryptographicOperationServiceImpl implements CryptographicOperationService {

    private static final Logger logger = LoggerFactory.getLogger(CryptographicOperationServiceImpl.class);

    // --------------------------------------------------------------------------------
    // Services & API Clients
    // --------------------------------------------------------------------------------
    private TokenInstanceService tokenInstanceService;
    private CryptographicKeyEventHistoryService eventHistoryService;
    private ConnectorApiFactory connectorApiFactory;
    private ConnectorService connectorService;
    private PermissionEvaluator permissionEvaluator;
    private CryptographicKeyService cryptographicKeyService;

    // --------------------------------------------------------------------------------
    // Repositories
    // --------------------------------------------------------------------------------
    private CryptographicKeyRepository cryptographicKeyRepository;
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    // Setters

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @Autowired
    public void setEventHistoryService(CryptographicKeyEventHistoryService eventHistoryService) {
        this.eventHistoryService = eventHistoryService;
    }

    @Autowired
    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setCryptographicKeyRepository(CryptographicKeyRepository cryptographicKeyRepository) {
        this.cryptographicKeyRepository = cryptographicKeyRepository;
    }

    @Autowired
    public void setCryptographicKeyItemRepository(CryptographicKeyItemRepository cryptographicKeyItemRepository) {
        this.cryptographicKeyItemRepository = cryptographicKeyItemRepository;
    }

    @Autowired
    public void setCryptographicKeyService(CryptographicKeyService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    // ----------------------------------------------------------------------------------------------
    // Service Implementations
    // ----------------------------------------------------------------------------------------------

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional
    public List<BaseAttribute> listCipherAttributes(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, UUID uuid, UUID keyItemUuid, KeyAlgorithm keyAlgorithm) throws ConnectorException, NotFoundException {
        permissionEvaluator.tokenProfile(tokenProfileUuid);
        logger.info("Requesting to list cipher attributes for Key: {} and Algorithm {}", keyItemUuid, keyAlgorithm);
        CryptographicKeyItem key = getKeyItemEntity(keyItemUuid);
        logger.debug("Key details: {}", key);
        return listEncryptionAttributes(keyAlgorithm);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENCRYPT, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional
    public EncryptDataResponseDto encryptData(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, UUID uuid, UUID keyItemUuid, CipherDataRequestDto request) throws ConnectorException, NotFoundException {
        permissionEvaluator.tokenProfile(tokenProfileUuid);
        logger.info("Request to encrypt the data using the key: {} and data: {}", keyItemUuid, request);
        CryptographicKeyItemModel key = cryptographicKeyService.getKeyItemModel(keyItemUuid);
        verifyActive(key.state(), key.enabled());
        logger.debug("Key details: {}", key);
        if (request.getCipherData() == null) {
            throw new ValidationException(ValidationError.create("Cannot encrypt null data"));
        }
        if (!key.usage().contains(KeyUsage.ENCRYPT)) {
            throw new ValidationException(
                    ValidationError.create(
                            "Key Usage of the certificate does not support encryption"
                    )
            );
        }
        com.czertainly.api.model.connector.cryptography.operations.CipherDataRequestDto requestDto = new com.czertainly.api.model.connector.cryptography.operations.CipherDataRequestDto();
        requestDto.setCipherData(request.getCipherData().stream().map(e -> {
                    CipherRequestData cipherRequestData = new CipherRequestData();
                    cipherRequestData.setData(base64EncodedToByteArray(e.getData()));
                    cipherRequestData.setIdentifier(e.getIdentifier());
                    return cipherRequestData;
                }).toList()
        );
        requestDto.setCipherAttributes(request.getCipherAttributes());
        logger.debug("Request to the connector: {}", requestDto);
        try {
            ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(key.connectorUuid());
            CryptographicOperationsSyncApiClient apiClient = connectorApiFactory.getCryptographicOperationsApiClient(connectorDto);
            com.czertainly.api.model.connector.cryptography.operations.EncryptDataResponseDto response = apiClient.encryptData(
                    connectorDto,
                    key.tokenInstanceUuid().toString(),
                    key.keyReferenceUuid().toString(),
                    requestDto
            );
            eventHistoryService.addEventHistory(KeyEvent.ENCRYPT, KeyEventStatus.SUCCESS,
                    "Encryption of data success ", null, key.keyItemUuid());
            EncryptDataResponseDto responseDto = new EncryptDataResponseDto();
            if (response.getEncryptedData() != null)
                responseDto.setEncryptedData(response.getEncryptedData().stream().map(e -> {
                    CipherResponseData cipherResponseData = new CipherResponseData();
                    cipherResponseData.setData(byteArrayToBase64Encoded(e.getData()));
                    cipherResponseData.setIdentifier(e.getIdentifier());
                    cipherResponseData.setDetails(e.getDetails());
                    return cipherResponseData;
                }).toList());
            return responseDto;
        } catch (Exception e) {
            eventHistoryService.addEventHistory(KeyEvent.ENCRYPT, KeyEventStatus.FAILED,
                    "Encryption of data failed ", Collections.singletonMap("exception", e.getLocalizedMessage()), key.keyItemUuid());
            throw e;
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DECRYPT, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional
    public DecryptDataResponseDto decryptData(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, UUID uuid, UUID keyItemUuid, CipherDataRequestDto request) throws ConnectorException, NotFoundException {
        permissionEvaluator.tokenProfile(tokenProfileUuid);
        logger.info("Decrypting using the key: {} and data: {}", keyItemUuid, request);
        CryptographicKeyItemModel key = cryptographicKeyService.getKeyItemModel(keyItemUuid);
        verifyActive(key.state(), key.enabled());
        logger.debug("Key details: {}", key);
        if (request.getCipherData() == null) {
            throw new ValidationException(ValidationError.create("Cannot decrypt null data"));
        }
        if (!key.usage().contains(KeyUsage.DECRYPT)) {
            throw new ValidationException(
                    ValidationError.create(
                            "Key Usage of the certificate does not support decryption"
                    )
            );
        }
        com.czertainly.api.model.connector.cryptography.operations.CipherDataRequestDto requestDto = new com.czertainly.api.model.connector.cryptography.operations.CipherDataRequestDto();
        requestDto.setCipherData(request.getCipherData().stream().map(e -> {
                    CipherRequestData cipherRequestData = new CipherRequestData();
                    cipherRequestData.setData(base64EncodedToByteArray(e.getData()));
                    cipherRequestData.setIdentifier(e.getIdentifier());
                    return cipherRequestData;
                }).toList()
        );
        requestDto.setCipherAttributes(request.getCipherAttributes());
        logger.debug("Request to the connector: {}", requestDto);
        try {
            ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(key.connectorUuid());
            CryptographicOperationsSyncApiClient apiClient = connectorApiFactory.getCryptographicOperationsApiClient(connectorDto);
            com.czertainly.api.model.connector.cryptography.operations.DecryptDataResponseDto response = apiClient.decryptData(
                    connectorDto,
                    key.tokenInstanceUuid().toString(),
                    key.keyReferenceUuid().toString(),
                    requestDto);
            eventHistoryService.addEventHistory(KeyEvent.DECRYPT, KeyEventStatus.SUCCESS,
                    "Decryption of data success ", null, key.keyItemUuid());
            DecryptDataResponseDto responseDto = new DecryptDataResponseDto();
            if (response.getDecryptedData() != null)
                responseDto.setDecryptedData(response.getDecryptedData().stream().map(e -> {
                    CipherResponseData cipherResponseData = new CipherResponseData();
                    cipherResponseData.setData(byteArrayToBase64Encoded(e.getData()));
                    cipherResponseData.setIdentifier(e.getIdentifier());
                    cipherResponseData.setDetails(e.getDetails());
                    return cipherResponseData;
                }).toList());
            return responseDto;
        } catch (Exception e) {
            eventHistoryService.addEventHistory(KeyEvent.DECRYPT, KeyEventStatus.FAILED,
                    "Decryption of data failed ", Collections.singletonMap("exception", e.getLocalizedMessage()), key.keyItemUuid());
            throw e;
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional
    public List<BaseAttribute> listSignatureAttributes(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, UUID uuid, UUID keyItemUuid, KeyAlgorithm keyAlgorithm) throws NotFoundException {
        permissionEvaluator.tokenProfile(tokenProfileUuid);
        logger.info("Requesting to list the Signature Attributes for key: {} and Algorithm: {}", keyItemUuid, keyAlgorithm);
        CryptographicKeyItem key = getKeyItemEntity(keyItemUuid);
        logger.debug("Key details: {}", key);
        return listSignatureAttributes(key.getKeyAlgorithm());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.SIGN, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional
    public SignDataResponseDto signData(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, UUID uuid, UUID keyItemUuid, SignDataRequestDto request) throws ConnectorException, NotFoundException {
        permissionEvaluator.tokenProfile(tokenProfileUuid);
        logger.info("Signing the data: {} using the key: {}", request, keyItemUuid);
        CryptographicKeyItemModel key = cryptographicKeyService.getKeyItemModel(keyItemUuid);
        try {
            SignDataResponseDto response = executeSignData(key, request);
            eventHistoryService.addEventHistory(KeyEvent.SIGN, KeyEventStatus.SUCCESS, "Signing data success ", null, key.keyItemUuid());
            return response;
        } catch (Exception e) {
            eventHistoryService.addEventHistory(KeyEvent.SIGN, KeyEventStatus.FAILED,
                    "Signing of data failed ", Collections.singletonMap("exception", e.getLocalizedMessage()), key.keyItemUuid());
            throw e;
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.SIGN, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    public SignDataResponseDto signDataWithoutEventHistory(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, UUID uuid, UUID keyItemUuid, SignDataRequestDto request) throws ConnectorException, NotFoundException {
        permissionEvaluator.tokenProfile(tokenProfileUuid);
        logger.info("Signing the data (no event history): {} using the key: {}", request, keyItemUuid);
        CryptographicKeyItemModel key = cryptographicKeyService.getKeyItemModel(keyItemUuid);
        return executeSignData(key, request);
    }

    private SignDataResponseDto executeSignData(CryptographicKeyItemModel key, SignDataRequestDto request) throws ConnectorException, NotFoundException {
        verifyActive(key.state(), key.enabled());
        logger.debug("Key details: {}", key);
        if (request.getData() == null) {
            throw new ValidationException(ValidationError.create("Cannot sign empty data"));
        }
        if (!key.usage().contains(KeyUsage.SIGN)) {
            throw new ValidationException(ValidationError.create("Key Usage of the certificate does not support signing"));
        }
        validateSignatureAttributes(key.keyAlgorithm(), request.getSignatureAttributes());
        com.czertainly.api.model.connector.cryptography.operations.SignDataRequestDto requestDto = new com.czertainly.api.model.connector.cryptography.operations.SignDataRequestDto();
        requestDto.setSignatureAttributes(request.getSignatureAttributes());
        requestDto.setData(request.getData().stream().map(e -> {
                    com.czertainly.api.model.connector.cryptography.operations.data.SignatureRequestData signatureRequestData = new com.czertainly.api.model.connector.cryptography.operations.data.SignatureRequestData();
                    signatureRequestData.setData(base64EncodedToByteArray(e.getData()));
                    signatureRequestData.setIdentifier(e.getIdentifier());
                    return signatureRequestData;
                }).toList()
        );
        logger.debug("Request to the connector: {}", requestDto);
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(key.connectorUuid());
        CryptographicOperationsSyncApiClient apiClient = connectorApiFactory.getCryptographicOperationsApiClient(connectorDto);
        com.czertainly.api.model.connector.cryptography.operations.SignDataResponseDto response = apiClient.signData(
                connectorDto,
                key.tokenInstanceUuid().toString(),
                key.keyReferenceUuid().toString(),
                requestDto
        );
        SignDataResponseDto responseDto = new SignDataResponseDto();
        if (response.getSignatures() != null) responseDto.setSignatures(response.getSignatures().stream().map(e -> {
            SignatureResponseData signatureResponseData = new SignatureResponseData();
            signatureResponseData.setData(byteArrayToBase64Encoded(e.getData()));
            signatureResponseData.setIdentifier(e.getIdentifier());
            signatureResponseData.setDetails(e.getDetails());
            return signatureResponseData;
        }).toList());
        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.VERIFY, parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional
    public VerifyDataResponseDto verifyData(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, UUID uuid, UUID keyItemUuid, VerifyDataRequestDto request) throws ConnectorException, NotFoundException {
        permissionEvaluator.tokenProfile(tokenProfileUuid);
        logger.info("Request to verify data: {} for the key: {}", request, keyItemUuid);
        CryptographicKeyItemModel key = cryptographicKeyService.getKeyItemModel(keyItemUuid);
        verifyActive(key.state(), key.enabled());
        logger.debug("Key details: {}", key);
        if (request.getSignatures() == null) {
            throw new ValidationException(ValidationError.create("Cannot verify empty data"));
        }
        validateSignatureAttributes(key.keyAlgorithm(), request.getSignatureAttributes());
        if (!key.usage().contains(KeyUsage.VERIFY)) {
            throw new ValidationException(
                    ValidationError.create(
                            "Key Usage of the certificate does not support verification"
                    )
            );
        }
        com.czertainly.api.model.connector.cryptography.operations.VerifyDataRequestDto requestDto = new com.czertainly.api.model.connector.cryptography.operations.VerifyDataRequestDto();
        requestDto.setSignatureAttributes(request.getSignatureAttributes());
        if (request.getData() != null) requestDto.setData(request.getData().stream().map(e -> {
                    com.czertainly.api.model.connector.cryptography.operations.data.SignatureRequestData signatureRequestData = new com.czertainly.api.model.connector.cryptography.operations.data.SignatureRequestData();
                    signatureRequestData.setData(base64EncodedToByteArray(e.getData()));
                    signatureRequestData.setIdentifier(e.getIdentifier());
                    return signatureRequestData;
                }).toList()
        );
        requestDto.setSignatures(request.getSignatures().stream().map(e -> {
                    com.czertainly.api.model.connector.cryptography.operations.data.SignatureRequestData signatureRequestData = new com.czertainly.api.model.connector.cryptography.operations.data.SignatureRequestData();
                    signatureRequestData.setData(base64EncodedToByteArray(e.getData()));
                    signatureRequestData.setIdentifier(e.getIdentifier());
                    return signatureRequestData;
                }).toList()
        );
        logger.debug("Request to the connector: {}", requestDto);
        try {
            ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(key.connectorUuid());
            CryptographicOperationsSyncApiClient apiClient = connectorApiFactory.getCryptographicOperationsApiClient(connectorDto);
            com.czertainly.api.model.connector.cryptography.operations.VerifyDataResponseDto response = apiClient.verifyData(
                    connectorDto,
                    key.tokenInstanceUuid().toString(),
                    key.keyReferenceUuid().toString(),
                    requestDto
            );
            eventHistoryService.addEventHistory(KeyEvent.VERIFY, KeyEventStatus.SUCCESS,
                    "Verification of data completed ", null, key.keyItemUuid());
            VerifyDataResponseDto responseDto = new VerifyDataResponseDto();
            if (response.getVerifications() != null)
                responseDto.setVerifications(response.getVerifications().stream().map(e -> {
                    VerificationResponseData verifyDataResponseDto = new VerificationResponseData();
                    verifyDataResponseDto.setResult(e.isResult());
                    verifyDataResponseDto.setIdentifier(e.getIdentifier());
                    verifyDataResponseDto.setDetails(e.getDetails());
                    return verifyDataResponseDto;
                }).toList());
            return responseDto;
        } catch (Exception e) {
            eventHistoryService.addEventHistory(KeyEvent.VERIFY, KeyEventStatus.FAILED,
                    "Verification of data failed ", Collections.singletonMap("exception", e.getLocalizedMessage()), key.keyItemUuid());
            throw e;
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ANY)
    @Transactional
    public List<BaseAttribute> listRandomAttributes(SecuredUUID tokenInstanceUuid) throws ConnectorException, NotFoundException {
        logger.info("Requesting attributes for random generation for token Instance: {}", tokenInstanceUuid);
        TokenInstanceReference tokenInstanceReference = tokenInstanceService.getTokenInstanceEntity(tokenInstanceUuid);
        logger.debug("Token Instance details: {}", tokenInstanceReference);
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(tokenInstanceReference.getConnectorUuid());
        return connectorApiFactory.getCryptographicOperationsApiClient(connectorDto).listRandomAttributes(
                connectorDto,
                tokenInstanceReference.getTokenInstanceUuid()
        );
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DETAIL)
    @Transactional
    public RandomDataResponseDto randomData(SecuredUUID tokenInstanceUuid, RandomDataRequestDto request) throws ConnectorException, NotFoundException {
        logger.info("Requesting attributes for random generation for token Instance: {}", tokenInstanceUuid);
        TokenInstanceReference tokenInstanceReference = tokenInstanceService.getTokenInstanceEntity(tokenInstanceUuid);
        logger.debug("Token Instance details: {}", tokenInstanceReference);
        com.czertainly.api.model.connector.cryptography.operations.RandomDataRequestDto requestDto = new com.czertainly.api.model.connector.cryptography.operations.RandomDataRequestDto();
        requestDto.setAttributes(request.getAttributes());
        requestDto.setLength(request.getLength());
        logger.debug("Request to the connector: {}", requestDto);
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(tokenInstanceReference.getConnectorUuid());
        com.czertainly.api.model.connector.cryptography.operations.RandomDataResponseDto response = connectorApiFactory.getCryptographicOperationsApiClient(connectorDto).randomData(
                connectorDto,
                tokenInstanceReference.getTokenInstanceUuid(),
                requestDto
        );
        RandomDataResponseDto responseDto = new RandomDataResponseDto();
        responseDto.setData(byteArrayToBase64Encoded(response.getData()));
        return responseDto;
    }

    @Override
    @Transactional
    public String generateCsr(UUID keyUuid, UUID tokenProfileUuid, X500Principal principal, List<RequestAttribute> signatureAttributes, UUID altKeyUUid,
                              UUID altTokenProfileUuid,
                              List<RequestAttribute> altSignatureAttributes) throws NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, AttributeException {
        // Check if the UUID of the Key is empty
        if (keyUuid == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Key UUID Cannot be empty"
                    )
            );
        }

        // Token Profile UUID of the request cannot be empty
        if (tokenProfileUuid == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Token Profile UUID Cannot be empty"
                    )
            );
        }

        Map<KeyType, CryptographicKeyItem> defaultKeyPair = getPublicAndPrivateKey(tokenProfileUuid, keyUuid);
        Map<KeyType, CryptographicKeyItem> altKeyPair = new EnumMap<>(KeyType.class);
        if (altKeyUUid != null && altTokenProfileUuid != null) altKeyPair = getPublicAndPrivateKey(altTokenProfileUuid, altKeyUUid);

        // Generate the CSR
        return generateCsr(
                principal,
                defaultKeyPair.get(KeyType.PUBLIC_KEY).getKeyData(),
                defaultKeyPair.get(KeyType.PRIVATE_KEY),
                defaultKeyPair.get(KeyType.PUBLIC_KEY),
                signatureAttributes,
                altKeyPair.getOrDefault(KeyType.PUBLIC_KEY, null) == null ? null : altKeyPair.get(KeyType.PUBLIC_KEY).getKeyData(),
                altKeyPair.getOrDefault(KeyType.PRIVATE_KEY, null),
                altKeyPair.getOrDefault(KeyType.PUBLIC_KEY, null),
                altSignatureAttributes
        );
    }

    private Map<KeyType, CryptographicKeyItem> getPublicAndPrivateKey(UUID tokenProfileUuid, UUID keyUuid) throws NotFoundException {
        // Check the Permission of the token profile to the user
        permissionEvaluator.tokenProfile(SecuredUUID.fromUUID(tokenProfileUuid));
        CryptographicKey key = cryptographicKeyRepository.findByUuid(
                keyUuid).orElseThrow(
                () -> new NotFoundException(
                        CryptographicKey.class,
                        keyUuid
                )
        );

        if (!key.getTokenProfile().getUuid().equals(tokenProfileUuid)) {
            throw new ValidationException(
                    ValidationError.create(
                            "Key and Token Profile are not associated to each other"
                    )
            );
        }
        CryptographicKeyItem privateKeyItem = null;
        CryptographicKeyItem publicKeyItem = null;

        // Iterate through the items inside the key and assign the private and public Key
        for (CryptographicKeyItem item : key.getItems()) {
            if (item.getType().equals(KeyType.PRIVATE_KEY)) {
                privateKeyItem = item;
            } else if (item.getType().equals(KeyType.PUBLIC_KEY)) {
                publicKeyItem = item;
            } else {
                //do nothing
            }
        }
        if (privateKeyItem == null || publicKeyItem == null) {
            throw new ValidationException(
                    ValidationError.create(
                            "Selected item does not contain the complete keypair"
                    )
            );
        }
        verifyActive(privateKeyItem.getState(), privateKeyItem.isEnabled());
        verifyActive(publicKeyItem.getState(), publicKeyItem.isEnabled());

        return Map.of(KeyType.PUBLIC_KEY, publicKeyItem, KeyType.PRIVATE_KEY, privateKeyItem);
    }

    private static void verifyActive(KeyState state, boolean enabled) {
        if (state != KeyState.ACTIVE || !enabled) {
            throw new ValidationException(ValidationError.create("Key needs to be " + KeyState.ACTIVE.getLabel() + " and enabled."));
        }
    }

    private CryptographicKeyItem getKeyItemEntity(UUID uuid) throws NotFoundException {
        logger.debug("UUID of the key to get the entity: {}", uuid);
        CryptographicKeyItem key = cryptographicKeyItemRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(CryptographicKeyItem.class, uuid));
        logger.debug("Key Instance: {}", key);
        return key;
    }

    private String generateCsr(X500Principal principal, String key, CryptographicKeyItem privateKeyItem, CryptographicKeyItem publicKeyItem, List<RequestAttribute> signatureAttributes,
                               String altKey, CryptographicKeyItem altPrivateKeyItem, CryptographicKeyItem altPublicKeyItem, List<RequestAttribute> altSignatureAttributes) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NotFoundException {
        // Build bouncy castle p10 builder
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                principal,
                CertificateRequestUtils.publicKeyObjectFromString(key, publicKeyItem.getKeyAlgorithm().getCode())
        );

        if (altKey != null && altPrivateKeyItem != null && altPublicKeyItem != null) {
            ApiClientConnectorInfo altConnectorDto = connectorService.getConnectorForApiClient(altPrivateKeyItem.getKey().getTokenInstanceReference().getConnectorUuid());
            ContentSigner altSigner = new TokenContentSigner(
                    connectorApiFactory.getCryptographicOperationsApiClient(altConnectorDto),
                    altConnectorDto,
                    UUID.fromString(altPrivateKeyItem.getKey().getTokenInstanceReference().getTokenInstanceUuid()),
                    altPrivateKeyItem.getKeyReferenceUuid(),
                    altPublicKeyItem.getKeyReferenceUuid(),
                    altPublicKeyItem.getKeyData(),
                    altPublicKeyItem.getKeyAlgorithm(),
                    altSignatureAttributes
            );

            OutputStream sOut = altSigner.getOutputStream();
            sOut.write(altKey.getBytes());
            sOut.close();
            SubjectPublicKeyInfo altPublicKeyInfo = SubjectPublicKeyInfo.getInstance(Base64.getDecoder().decode(altKey));
            p10Builder.addAttribute(Extension.subjectAltPublicKeyInfo, altPublicKeyInfo);
            p10Builder.addAttribute(Extension.altSignatureValue, new DERBitString(altSigner.getSignature()));
            p10Builder.addAttribute(Extension.altSignatureAlgorithm, altSigner.getAlgorithmIdentifier());
        }


        // Assign the custom signer to sign the CSR with the private key from the cryptography provider
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(privateKeyItem.getKey().getTokenInstanceReference().getConnectorUuid());
        ContentSigner signer = new TokenContentSigner(
                connectorApiFactory.getCryptographicOperationsApiClient(connectorDto),
                connectorDto,
                UUID.fromString(privateKeyItem.getKey().getTokenInstanceReference().getTokenInstanceUuid()),
                privateKeyItem.getKeyReferenceUuid(),
                publicKeyItem.getKeyReferenceUuid(),
                publicKeyItem.getKeyData(),
                publicKeyItem.getKeyAlgorithm(),
                signatureAttributes
        );

        // Build the CSR with the DN generated and the signer
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        // Convert the data from byte array to string
        return CertificateRequestUtils.byteArrayCsrToString(csr.getEncoded());
    }

    @Override
    public List<BaseAttribute> listSignatureAttributes(KeyAlgorithm keyAlgorithm) {
        // we need to list based on the key algorithm
        switch (keyAlgorithm) {
            case RSA -> {
                return RsaSignatureAttributes.getRsaSignatureAttributes();
            }
            case ECDSA -> {
                return EcdsaSignatureAttributes.getEcdsaSignatureAttributes();
            }
            case FALCON, MLDSA, SLHDSA -> {
                return List.of();
            }
            default -> throw new ValidationException(
                    ValidationError.create(
                            "Cryptographic key algorithm not supported"
                    )
            );
        }
    }


    private List<BaseAttribute> listEncryptionAttributes(KeyAlgorithm keyAlgorithm) {
        switch (keyAlgorithm) {
            case RSA -> {
                return RsaEncryptionAttributes.getRsaEncryptionAttributes();
            }
            default -> throw new ValidationException(
                    ValidationError.create(
                            "Cryptographic key algorithm not supported"
                    )
            );
        }
    }

    private boolean validateSignatureAttributes(KeyAlgorithm keyAlgorithm, List<RequestAttribute> attributes) {
        if (attributes == null) {
            return false;
        }

        switch (keyAlgorithm) {
            case RSA ->
                    AttributeDefinitionUtils.validateAttributes(RsaSignatureAttributes.getRsaSignatureAttributes(), attributes);
            case ECDSA ->
                    AttributeDefinitionUtils.validateAttributes(EcdsaSignatureAttributes.getEcdsaSignatureAttributes(), attributes);
            case FALCON, MLDSA, SLHDSA -> {
                return true;
            }
            default -> throw new ValidationException(
                    ValidationError.create(
                            "Cryptographic key algorithm not supported"
                    )
            );
        }

        return true;
    }

    private byte[] base64EncodedToByteArray(String encoded) {
        if (encoded == null) {
            return null;
        }
        return Base64.getDecoder().decode(encoded.getBytes(StandardCharsets.UTF_8));
    }

    private String byteArrayToBase64Encoded(byte[] input) {
        if (input == null) {
            return null;
        }
        return Base64.getEncoder().encodeToString(input);
    }
}
