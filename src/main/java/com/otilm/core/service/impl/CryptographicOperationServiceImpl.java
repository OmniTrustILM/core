package com.otilm.core.service.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.cryptography.operations.CipherDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.DecryptDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.EncryptDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.RandomDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.RandomDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.SignDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.SignDataResponseDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataRequestDto;
import com.otilm.api.model.client.cryptography.operations.VerifyDataResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.config.TokenContentSigner;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.crypto.KeyOperationScope;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.CryptographicOperationExternalService;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.handler.key.KeyProviderV1Adapter;
import com.otilm.core.service.handler.key.OperationKeyContext;
import com.otilm.core.service.handler.token.TokenProviderAdapterFactory;
import com.otilm.core.service.v2.ConnectorInternalService;
import com.otilm.core.util.CertificateRequestUtils;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CryptographicOperationServiceImpl
        implements
            CryptographicOperationExternalService,
            CryptographicOperationInternalService {

    private static final Logger logger = LoggerFactory.getLogger(CryptographicOperationServiceImpl.class);

    // --------------------------------------------------------------------------------
    // Services & API Clients
    // --------------------------------------------------------------------------------
    private CryptographicKeyEventHistoryService eventHistoryService;
    private ConnectorApiFactory connectorApiFactory;
    private ConnectorInternalService connectorService;
    private AuthorizationEnforcer authorizationEnforcer;
    private CryptographicKeyInternalService cryptographicKeyService;

    // --------------------------------------------------------------------------------
    // Repositories
    // --------------------------------------------------------------------------------
    private CryptographicKeyRepository cryptographicKeyRepository;
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    private TokenProfileRepository tokenProfileRepository;

    private KeyProviderAdapterFactory keyProviderAdapterFactory;
    private TokenProviderAdapterFactory tokenProviderAdapterFactory;

    // Setters

    @Autowired
    public void setKeyProviderAdapterFactory(KeyProviderAdapterFactory keyProviderAdapterFactory) {
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
    }

    @Autowired
    public void setTokenProviderAdapterFactory(TokenProviderAdapterFactory tokenProviderAdapterFactory) {
        this.tokenProviderAdapterFactory = tokenProviderAdapterFactory;
    }

    @Autowired
    public void setTokenInstanceReferenceRepository(TokenInstanceReferenceRepository tokenInstanceReferenceRepository) {
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
    }

    @Autowired
    public void setTokenProfileRepository(TokenProfileRepository tokenProfileRepository) {
        this.tokenProfileRepository = tokenProfileRepository;
    }

    @Autowired
    public void setEventHistoryService(CryptographicKeyEventHistoryService eventHistoryService) {
        this.eventHistoryService = eventHistoryService;
    }

    @Autowired
    public void setAuthorizationEnforcer(AuthorizationEnforcer authorizationEnforcer) {
        this.authorizationEnforcer = authorizationEnforcer;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setConnectorService(ConnectorInternalService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setCryptographicKeyRepository(CryptographicKeyRepository cryptographicKeyRepository) {
        this.cryptographicKeyRepository = cryptographicKeyRepository;
    }

    @Autowired
    public void setCryptographicKeyInternalService(CryptographicKeyInternalService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    // ----------------------------------------------------------------------------------------------
    // Service Implementations
    // ----------------------------------------------------------------------------------------------

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> listCipherAttributes(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid,
            UUID uuid, UUID keyItemUuid, KeyAlgorithm keyAlgorithm) throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Requesting to list cipher attributes for Key: {} and Algorithm {}", keyItemUuid, keyAlgorithm);
        requireLegacyProvider(cryptographicKeyService.getKeyItemModel(keyItemUuid));
        return KeyProviderV1Adapter.cipherAttributes(keyAlgorithm);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> listEncryptAttributes(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid,
            UUID uuid, UUID keyItemUuid) throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Requesting to list encryption attributes for Key: {}", keyItemUuid);
        OperationKeyContext context = loadContext(tokenInstanceUuid.getValue(), tokenProfileUuid.getValue(), uuid,
                keyItemUuid);
        return adapterFor(context).listEncryptAttributes(context);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> listDecryptAttributes(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid,
            UUID uuid, UUID keyItemUuid) throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Requesting to list decryption attributes for Key: {}", keyItemUuid);
        OperationKeyContext context = loadContext(tokenInstanceUuid.getValue(), tokenProfileUuid.getValue(), uuid,
                keyItemUuid);
        return adapterFor(context).listDecryptAttributes(context);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ENCRYPT,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public EncryptDataResponseDto encryptData(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid,
            UUID uuid, UUID keyItemUuid, CipherDataRequestDto request) throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Request to encrypt data using key: {}", keyItemUuid);
        OperationKeyContext context = loadContext(tokenInstanceUuid.getValue(), tokenProfileUuid.getValue(), uuid,
                keyItemUuid);
        requireActive(context.keyItem());
        if (request.getCipherData() == null) {
            throw new ValidationException(ValidationError.create("Cannot encrypt null data"));
        }
        requireUsage(context.keyItem(), KeyUsage.ENCRYPT, "encryption");
        return recordEvent(context.keyItem(), KeyEvent.ENCRYPT, "Encryption of data success ",
                "Encryption of data failed ", () -> adapterFor(context).encryptData(context, request));
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.DECRYPT,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DecryptDataResponseDto decryptData(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid,
            UUID uuid, UUID keyItemUuid, CipherDataRequestDto request) throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Decrypting using key: {}", keyItemUuid);
        OperationKeyContext context = loadContext(tokenInstanceUuid.getValue(), tokenProfileUuid.getValue(), uuid,
                keyItemUuid);
        requireActive(context.keyItem());
        if (request.getCipherData() == null) {
            throw new ValidationException(ValidationError.create("Cannot decrypt null data"));
        }
        requireUsage(context.keyItem(), KeyUsage.DECRYPT, "decryption");
        return recordEvent(context.keyItem(), KeyEvent.DECRYPT, "Decryption of data success ",
                "Decryption of data failed ", () -> adapterFor(context).decryptData(context, request));
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> listSignatureAttributes(SecuredParentUUID tokenInstanceUuid,
            SecuredUUID tokenProfileUuid, UUID uuid, UUID keyItemUuid, KeyAlgorithm keyAlgorithm)
            throws NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger
                .info("Requesting to list the Signature Attributes for key: {} and Algorithm: {}", keyItemUuid,
                        keyAlgorithm);
        CryptographicKeyItemOperationModel key = cryptographicKeyService.getKeyItemModel(keyItemUuid);
        requireLegacyProvider(key);
        return KeyProviderV1Adapter.signatureAttributes(key.keyAlgorithm());
    }

    private static void requireLegacyProvider(CryptographicKeyItemOperationModel key) {
        if (key.hasConnectorInterface()) {
            throw new NotSupportedException(
                    "Legacy attribute listing is not available for keys on a cryptography provider v2; use the per-operation attribute endpoints.");
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> listSignAttributes(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid,
            UUID uuid, UUID keyItemUuid) throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Requesting to list signing attributes for Key: {}", keyItemUuid);
        OperationKeyContext context = loadContext(tokenInstanceUuid.getValue(), tokenProfileUuid.getValue(), uuid,
                keyItemUuid);
        return adapterFor(context).listSignAttributes(context);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.ANY,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> listVerifyAttributes(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid,
            UUID uuid, UUID keyItemUuid) throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Requesting to list verification attributes for Key: {}", keyItemUuid);
        OperationKeyContext context = loadContext(tokenInstanceUuid.getValue(), tokenProfileUuid.getValue(), uuid,
                keyItemUuid);
        return adapterFor(context).listVerifyAttributes(context);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.SIGN,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public SignDataResponseDto signData(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, UUID uuid,
            UUID keyItemUuid, SignDataRequestDto request) throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Signing data using key: {}", keyItemUuid);
        OperationKeyContext context = loadContext(tokenInstanceUuid.getValue(), tokenProfileUuid.getValue(), uuid,
                keyItemUuid);
        return recordEvent(context.keyItem(), KeyEvent.SIGN, "Signing data success ", "Signing of data failed ",
                () -> executeSignData(context, request));
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.SIGN,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public SignDataResponseDto signDataWithoutEventHistory(SecuredParentUUID tokenInstanceUuid,
            SecuredUUID tokenProfileUuid, UUID uuid, UUID keyItemUuid, SignDataRequestDto request)
            throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Signing data (no event history) using key: {}", keyItemUuid);
        OperationKeyContext context = loadContext(tokenInstanceUuid.getValue(), tokenProfileUuid.getValue(), uuid,
                keyItemUuid);
        return executeSignData(context, request);
    }

    private SignDataResponseDto executeSignData(OperationKeyContext context, SignDataRequestDto request)
            throws ConnectorException, NotFoundException {
        requireActive(context.keyItem());
        if (request.getData() == null) {
            throw new ValidationException(ValidationError.create("Cannot sign empty data"));
        }
        requireUsage(context.keyItem(), KeyUsage.SIGN, "signing");
        return adapterFor(context).signData(context, request);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.VERIFY,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public VerifyDataResponseDto verifyData(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid,
            UUID uuid, UUID keyItemUuid, VerifyDataRequestDto request) throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Request to verify data for key: {}", keyItemUuid);
        OperationKeyContext context = loadContext(tokenInstanceUuid.getValue(), tokenProfileUuid.getValue(), uuid,
                keyItemUuid);
        requireActive(context.keyItem());
        if (request.getSignatures() == null) {
            throw new ValidationException(ValidationError.create("Cannot verify empty data"));
        }
        requireUsage(context.keyItem(), KeyUsage.VERIFY, "verification");
        return recordEvent(context.keyItem(), KeyEvent.VERIFY, "Verification of data completed ",
                "Verification of data failed ", () -> adapterFor(context).verifyData(context, request));
    }

    /**
     * Two projection reads, each in its own short transaction. For a stateless provider the request is built from the
     * key's own profile, so the path parameters must name that key, that profile and that profile's token: otherwise a
     * caller authorized on one token or profile could operate a key from another.
     */
    private OperationKeyContext loadContext(UUID tokenInstanceUuid, UUID tokenProfileUuid, UUID keyUuid,
            UUID keyItemUuid) throws NotFoundException {
        CryptographicKeyItemOperationModel keyItem = cryptographicKeyService.getKeyItemModel(keyItemUuid);
        logger.atDebug().addArgument(keyItem::toIdentifierString).log("Key: {}");
        if (!keyItem.hasConnectorInterface()) {
            return OperationKeyContext.legacy(keyItem);
        }
        KeyOperationScope scope = cryptographicKeyRepository
                .findOperationScopeByUuid(keyItem.keyUuid())
                .orElseThrow(() -> new NotFoundException(CryptographicKey.class, keyItem.keyUuid()));
        if (!keyItem.keyUuid().equals(keyUuid) || !scope.tokenProfileUuid().equals(tokenProfileUuid)
                || !scope.tokenInstanceReferenceUuid().equals(tokenInstanceUuid)) {
            throw new ValidationException(ValidationError
                    .create("Token, token profile, key and key item in the request are not associated."));
        }
        return new OperationKeyContext(keyItem, scope.tokenProfile());
    }

    private KeyProviderAdapter adapterFor(OperationKeyContext context) throws NotFoundException {
        return keyProviderAdapterFactory.forKeyItem(context.keyItem());
    }

    private <T> T recordEvent(CryptographicKeyItemOperationModel key, KeyEvent event, String successMessage,
            String failureMessage, ConnectorOperation<T> operation) throws ConnectorException, NotFoundException {
        T result;
        try {
            result = operation.execute();
        } catch (Exception e) {
            eventHistoryService
                    .addEventHistory(event, KeyEventStatus.FAILED, failureMessage,
                            Collections.singletonMap("exception", e.getLocalizedMessage()), key.keyItemUuid());
            throw e;
        }
        eventHistoryService.addEventHistory(event, KeyEventStatus.SUCCESS, successMessage, null, key.keyItemUuid());
        return result;
    }

    private static void requireActive(CryptographicKeyItemOperationModel key) {
        verifyActive(key.keyState(), key.enabled());
    }

    private static void requireUsage(CryptographicKeyItemOperationModel key, KeyUsage usage, String operation) {
        if (!key.keyUsage().contains(usage)) {
            throw new ValidationException(
                    ValidationError.create("Key Usage of the certificate does not support " + operation));
        }
    }

    @FunctionalInterface
    private interface ConnectorOperation<T> {
        T execute() throws ConnectorException, NotFoundException;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ANY)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> listRandomAttributes(SecuredUUID tokenInstanceUuid)
            throws ConnectorException, NotFoundException {
        logger.info("Requesting attributes for random generation for token Instance: {}", tokenInstanceUuid);
        TokenInstanceBasicModel token = getTokenInstanceModel(tokenInstanceUuid);
        requireLegacyToken(token);
        return tokenProviderAdapterFactory.forToken(token).listRandomAttributes(token, null);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DETAIL,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> listRandomAttributes(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid)
            throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Requesting attributes for random generation for token profile: {}", tokenProfileUuid);
        TokenInstanceBasicModel token = getTokenInstanceModel(tokenInstanceUuid);
        TokenProfileBasicModel profile = getTokenProfileModel(tokenProfileUuid);
        requireProfileAssociatedWithToken(token, profile);
        return tokenProviderAdapterFactory.forToken(token).listRandomAttributes(token, profile);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public RandomDataResponseDto randomData(SecuredUUID tokenInstanceUuid, RandomDataRequestDto request)
            throws ConnectorException, NotFoundException {
        logger.info("Requesting random data generation for token Instance: {}", tokenInstanceUuid);
        TokenInstanceBasicModel token = getTokenInstanceModel(tokenInstanceUuid);
        requireLegacyToken(token);
        logger.atDebug().addArgument(token::toIdentifierString).log("Sending random generation request for token: {}");
        return tokenProviderAdapterFactory.forToken(token).randomData(token, null, request);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DETAIL,
            parentResource = Resource.TOKEN, parentAction = ResourceAction.DETAIL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public RandomDataResponseDto randomData(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid,
            RandomDataRequestDto request) throws ConnectorException, NotFoundException {
        authorizationEnforcer.enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, tokenProfileUuid);
        logger.info("Requesting random data generation for token profile: {}", tokenProfileUuid);
        TokenInstanceBasicModel token = getTokenInstanceModel(tokenInstanceUuid);
        TokenProfileBasicModel profile = getTokenProfileModel(tokenProfileUuid);
        requireProfileAssociatedWithToken(token, profile);
        logger.atDebug().addArgument(token::toIdentifierString).log("Sending random generation request for token: {}");
        return tokenProviderAdapterFactory.forToken(token).randomData(token, profile, request);
    }

    private TokenInstanceBasicModel getTokenInstanceModel(SecuredUUID uuid) throws NotFoundException {
        return tokenInstanceReferenceRepository
                .findBasicModelByUuid(uuid.getValue())
                .orElseThrow(() -> new NotFoundException(TokenInstanceReference.class, uuid.getValue()));
    }

    private TokenProfileBasicModel getTokenProfileModel(SecuredUUID uuid) throws NotFoundException {
        return tokenProfileRepository
                .findBasicModelByUuid(uuid.getValue())
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, uuid.getValue()));
    }

    private static void requireProfileAssociatedWithToken(TokenInstanceBasicModel token,
            TokenProfileBasicModel profile) {
        if (!profile.tokenInstanceReferenceUuid().equals(token.uuid())) {
            throw new ValidationException(ValidationError.create("Token profile is not associated with the token."));
        }
    }

    private static void requireLegacyToken(TokenInstanceBasicModel token) {
        if (token.connectorInterfaceCode() != null) {
            throw new NotSupportedException(
                    "Random-data generation on a cryptography provider v2 token requires a token profile; use the "
                            + "token-profile form of this endpoint.");
        }
    }

    @Override
    // Read-only (key reads + connector signing over HTTP); NOT_SUPPORTED keeps the DB connection out of the
    // crypto-connector round-trip so it is not held while signing (certificate key-generation path).
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public String generateCsr(UUID keyUuid, UUID tokenProfileUuid, X500Principal principal, Extensions extensions,
            List<RequestAttribute> signatureAttributes, UUID altKeyUUid, UUID altTokenProfileUuid,
            List<RequestAttribute> altSignatureAttributes)
            throws NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        if (keyUuid == null) {
            throw new ValidationException(ValidationError.create("Key UUID Cannot be empty"));
        }
        if (tokenProfileUuid == null) {
            throw new ValidationException(ValidationError.create("Token Profile UUID Cannot be empty"));
        }

        Map<KeyType, CryptographicKeyItem> defaultKeyPair = getPublicAndPrivateKey(tokenProfileUuid, keyUuid);
        Map<KeyType, CryptographicKeyItem> altKeyPair = new EnumMap<>(KeyType.class);
        if (altKeyUUid != null && altTokenProfileUuid != null) {
            altKeyPair = getPublicAndPrivateKey(altTokenProfileUuid, altKeyUUid);
        }

        return generateCsr(X500Name.getInstance(principal.getEncoded()), extensions,
                defaultKeyPair.get(KeyType.PUBLIC_KEY).getKeyData(), defaultKeyPair.get(KeyType.PRIVATE_KEY),
                defaultKeyPair.get(KeyType.PUBLIC_KEY), signatureAttributes,
                altKeyPair.getOrDefault(KeyType.PUBLIC_KEY, null) == null
                        ? null
                        : altKeyPair.get(KeyType.PUBLIC_KEY).getKeyData(),
                altKeyPair.getOrDefault(KeyType.PRIVATE_KEY, null), altKeyPair.getOrDefault(KeyType.PUBLIC_KEY, null),
                altSignatureAttributes);
    }

    private Map<KeyType, CryptographicKeyItem> getPublicAndPrivateKey(UUID tokenProfileUuid, UUID keyUuid)
            throws NotFoundException {
        authorizationEnforcer
                .enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, SecuredUUID.fromUUID(tokenProfileUuid));
        // Eager-fetch the profile, key items and token instance reference: the only caller signs outside a
        // transaction, so these traversals must not rely on open-session-in-view.
        CryptographicKey key = cryptographicKeyRepository
                .findWithKeyItemsAndTokenByUuid(keyUuid)
                .orElseThrow(() -> new NotFoundException(CryptographicKey.class, keyUuid));

        if (!key.getTokenProfile().getUuid().equals(tokenProfileUuid)) {
            throw new ValidationException(
                    ValidationError.create("Key and Token Profile are not associated to each other"));
        }
        if (!Boolean.TRUE.equals(key.getTokenProfile().getEnabled())) {
            throw new ValidationException(ValidationError.create("Token Profile is disabled"));
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
                // do nothing
            }
        }
        if (privateKeyItem == null || publicKeyItem == null) {
            throw new ValidationException(
                    ValidationError.create("Selected item does not contain the complete keypair"));
        }
        if (privateKeyItem.getKeyMeta() != null) {
            throw new NotSupportedException("CSR generation is not available for keys on a cryptography provider v2.");
        }
        verifyActive(privateKeyItem.getState(), privateKeyItem.isEnabled());
        verifyActive(publicKeyItem.getState(), publicKeyItem.isEnabled());

        return Map.of(KeyType.PUBLIC_KEY, publicKeyItem, KeyType.PRIVATE_KEY, privateKeyItem);
    }

    private static void verifyActive(KeyState state, boolean enabled) {
        if (state != KeyState.ACTIVE || !enabled) {
            throw new ValidationException(
                    ValidationError.create("Key needs to be " + KeyState.ACTIVE.getLabel() + " and enabled."));
        }
    }

    private String generateCsr(X500Name subject, Extensions extensions, String key, CryptographicKeyItem privateKeyItem,
            CryptographicKeyItem publicKeyItem, List<RequestAttribute> signatureAttributes, String altKey,
            CryptographicKeyItem altPrivateKeyItem, CryptographicKeyItem altPublicKeyItem,
            List<RequestAttribute> altSignatureAttributes)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NotFoundException {
        var publicKey = CertificateRequestUtils
                .publicKeyObjectFromString(key, publicKeyItem.getKeyAlgorithm().getCode());
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);

        if (altKey != null && altPrivateKeyItem != null && altPublicKeyItem != null) {
            ApiClientConnectorInfo altConnectorDto = connectorService
                    .getConnectorForApiClient(
                            altPrivateKeyItem.getKey().getTokenInstanceReference().getConnectorUuid());
            ContentSigner altSigner = new TokenContentSigner(
                    connectorApiFactory.getCryptographicOperationsApiClient(altConnectorDto), altConnectorDto,
                    UUID.fromString(altPrivateKeyItem.getKey().getTokenInstanceReference().getTokenInstanceUuid()),
                    altPrivateKeyItem.getKeyReferenceUuid(), altPublicKeyItem.getKeyReferenceUuid(),
                    altPublicKeyItem.getKeyData(), altPublicKeyItem.getKeyAlgorithm(), altSignatureAttributes);

            OutputStream sOut = altSigner.getOutputStream();
            sOut.write(altKey.getBytes());
            sOut.close();
            SubjectPublicKeyInfo altPublicKeyInfo = SubjectPublicKeyInfo
                    .getInstance(Base64.getDecoder().decode(altKey));
            p10Builder.addAttribute(Extension.subjectAltPublicKeyInfo, altPublicKeyInfo);
            p10Builder.addAttribute(Extension.altSignatureValue, new DERBitString(altSigner.getSignature()));
            p10Builder.addAttribute(Extension.altSignatureAlgorithm, altSigner.getAlgorithmIdentifier());
        }

        // Assign the custom signer to sign the CSR with the private key from the cryptography provider
        ApiClientConnectorInfo connectorDto = connectorService
                .getConnectorForApiClient(privateKeyItem.getKey().getTokenInstanceReference().getConnectorUuid());
        ContentSigner signer = new TokenContentSigner(
                connectorApiFactory.getCryptographicOperationsApiClient(connectorDto), connectorDto,
                UUID.fromString(privateKeyItem.getKey().getTokenInstanceReference().getTokenInstanceUuid()),
                privateKeyItem.getKeyReferenceUuid(), publicKeyItem.getKeyReferenceUuid(), publicKeyItem.getKeyData(),
                publicKeyItem.getKeyAlgorithm(), signatureAttributes);

        if (extensions != null) {
            p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        }

        // Build the CSR with the DN generated and the signer
        PKCS10CertificationRequest csr = p10Builder.build(signer);

        // Convert the data from byte array to string
        return CertificateRequestUtils.byteArrayCsrToString(csr.getEncoded());
    }

    @Override
    public List<BaseAttribute> listSignatureAttributes(KeyAlgorithm keyAlgorithm) throws ValidationException {
        return KeyProviderV1Adapter.signatureAttributes(keyAlgorithm);
    }
}
