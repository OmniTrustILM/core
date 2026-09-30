package com.otilm.core.service.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyExportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.ExportedKeyMaterial;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.CryptographicKeyExportExternalService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.handler.KeyTransferCapabilityService;
import com.otilm.core.service.handler.key.HeldKey;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.handler.key.OperationKeyContext;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Takes plain UUIDs, so the export permission is checked on its own: the owner of an object is granted any action
 * checked against that object, and export must never be granted that way.
 */
@Service
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public class CryptographicKeyExportServiceImpl implements CryptographicKeyExportExternalService {

    private static final String NOT_EXPORTED_TYPE = "Key item %s is a %s; only private and secret keys are exported.";
    private static final String NOT_EXPORTABLE = "Key item %s was not created or imported as exportable.";
    private static final String NOT_ACTIVE = "Key item %s must be active and enabled to be exported.";
    private static final String NO_PROFILE = "Key item %s has no token profile to export it through.";
    private static final String NOT_OFFERED = "Token profile %s does not export the %s algorithm for a %s.";
    private static final String NO_PUBLIC_RECORD = "Key %s holds no public key to check an export against.";
    private static final String CHANGED = "Key item %s changed while it was being exported. Try again.";
    private static final String PROFILE_CHANGED = "Token profile %s changed during the export. Try again.";
    private static final String EXPORT_FAILED = "Key item export failed.";

    private final AuthorizationEnforcer authorizationEnforcer;
    private final CryptographicKeyRepository cryptographicKeyRepository;
    private final CryptographicKeyItemRepository cryptographicKeyItemRepository;
    private final TokenProfileRepository tokenProfileRepository;
    private final CryptographicKeyInternalService cryptographicKeyService;
    private final KeyTransferCapabilityService keyTransferCapabilityService;
    private final KeyProviderAdapterFactory keyProviderAdapterFactory;
    private final CryptographicKeyEventHistoryService eventHistoryService;

    public CryptographicKeyExportServiceImpl(AuthorizationEnforcer authorizationEnforcer,
            CryptographicKeyRepository cryptographicKeyRepository,
            CryptographicKeyItemRepository cryptographicKeyItemRepository,
            TokenProfileRepository tokenProfileRepository, CryptographicKeyInternalService cryptographicKeyService,
            KeyTransferCapabilityService keyTransferCapabilityService,
            KeyProviderAdapterFactory keyProviderAdapterFactory,
            CryptographicKeyEventHistoryService eventHistoryService) {
        this.authorizationEnforcer = authorizationEnforcer;
        this.cryptographicKeyRepository = cryptographicKeyRepository;
        this.cryptographicKeyItemRepository = cryptographicKeyItemRepository;
        this.tokenProfileRepository = tokenProfileRepository;
        this.cryptographicKeyService = cryptographicKeyService;
        this.keyTransferCapabilityService = keyTransferCapabilityService;
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
        this.eventHistoryService = eventHistoryService;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.EXPORT_KEY)
    public List<BaseAttribute> listExportKeyAttributes(UUID keyUuid, UUID keyItemUuid)
            throws ConnectorException, NotFoundException {
        CryptographicKeyBasicModel key = requireAccess(keyUuid);
        CryptographicKeyItemBasicModel item = requireItemOf(key, keyItemUuid);
        OperationKeyContext context = requireExportable(key, item);
        return keyProviderAdapterFactory.forKeyItem(context.keyItem()).listExportKeyAttributes(context);
    }

    /**
     * Core's gates are checked before the connector is asked, and the key item's own again once it has answered, so a
     * key demoted, disabled or compromised meanwhile releases nothing. The history records the message of every
     * failure; none can carry the passphrase, because the adapter drops the connector's words from the one call that
     * sends it.
     */
    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.EXPORT_KEY)
    public ExportedKeyMaterial exportKey(UUID keyUuid, UUID keyItemUuid, KeyExportRequestDto request)
            throws ConnectorException, NotFoundException {
        CryptographicKeyBasicModel key = requireAccess(keyUuid);
        CryptographicKeyItemBasicModel item = requireItemOf(key, keyItemUuid);
        try {
            OperationKeyContext context = requireExportable(key, item);
            byte[] envelope = keyProviderAdapterFactory
                    .forKeyItem(context.keyItem())
                    .exportKey(context, heldKey(item), request.getPassphrase(), request.getExportAttributes());
            if (!cryptographicKeyItemRepository.isExportable(item.uuid())) {
                throw refusal(CHANGED, item.uuid());
            }
            eventHistoryService
                    .addEventHistory(KeyEvent.EXPORT, KeyEventStatus.SUCCESS, "Key item exported.", null, item.uuid());
            return new ExportedKeyMaterial(item.name(), envelope);
        } catch (RuntimeException | ConnectorException | NotFoundException e) {
            recordFailure(item.uuid(), e);
            throw e;
        }
    }

    /**
     * A failure the history cannot record is attached to the attempt's own, so the caller always learns why the export
     * did not happen.
     */
    private void recordFailure(UUID keyItemUuid, Exception failure) {
        try {
            eventHistoryService
                    .addEventHistory(KeyEvent.EXPORT, KeyEventStatus.FAILED,
                            Objects.requireNonNullElse(failure.getMessage(), EXPORT_FAILED), null, keyItemUuid);
        } catch (RuntimeException historyFailure) {
            failure.addSuppressed(historyFailure);
        }
    }

    /**
     * The detail of the key and of its token profile, as the key operations check, and the detail and members of its
     * token, as withdrawing the export permission does.
     */
    private CryptographicKeyBasicModel requireAccess(UUID keyUuid) throws NotFoundException {
        CryptographicKeyBasicModel key = cryptographicKeyRepository
                .findBasicModelByUuid(keyUuid)
                .orElseThrow(() -> new NotFoundException(CryptographicKey.class, keyUuid));
        authorizationEnforcer.enforce(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, SecuredUUID.fromUUID(keyUuid));
        if (key.tokenProfileUuid() != null) {
            authorizationEnforcer
                    .enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL,
                            SecuredUUID.fromUUID(key.tokenProfileUuid()));
        }
        if (key.tokenInstanceReferenceUuid() != null) {
            SecuredUUID token = SecuredUUID.fromUUID(key.tokenInstanceReferenceUuid());
            authorizationEnforcer.enforce(Resource.TOKEN, ResourceAction.DETAIL, token);
            authorizationEnforcer.enforce(Resource.TOKEN, ResourceAction.MEMBERS, token);
        }
        return key;
    }

    private CryptographicKeyItemBasicModel requireItemOf(CryptographicKeyBasicModel key, UUID keyItemUuid)
            throws NotFoundException {
        return cryptographicKeyItemRepository
                .findByUuidAndKeyUuid(keyItemUuid, key.uuid())
                .map(CryptographicKeyItemBasicModel::from)
                .orElseThrow(() -> new NotFoundException(CryptographicKeyItem.class, keyItemUuid));
    }

    /** Core's gates, in order; the connector is asked what it offers only once the key item's own gates pass. */
    private OperationKeyContext requireExportable(CryptographicKeyBasicModel key, CryptographicKeyItemBasicModel item)
            throws ConnectorException, NotFoundException {
        KeyRequestType type = requestTypeOf(item);
        if (!item.exportable()) {
            throw refusal(NOT_EXPORTABLE, item.uuid());
        }
        if (item.state() != KeyState.ACTIVE || !item.enabled()) {
            throw refusal(NOT_ACTIVE, item.uuid());
        }
        TokenProfileFullModel profile = tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(key.tokenProfileUuid(),
                        key.tokenInstanceReferenceUuid())
                .orElseThrow(() -> refusal(NO_PROFILE, item.uuid()));
        Map<KeyRequestType, Set<KeyAlgorithm>> offered = keyTransferCapabilityService
                .exportableKeyTypes(profile)
                .orElseThrow(() -> refusal(PROFILE_CHANGED, profile.name()));
        if (!offered.getOrDefault(type, Set.of()).contains(item.algorithm())) {
            throw refusal(NOT_OFFERED, profile.name(), item.algorithm().getLabel(),
                    type.getLabel().toLowerCase(Locale.ROOT));
        }
        return new OperationKeyContext(cryptographicKeyService.getKeyItemModel(item.uuid()), profile);
    }

    private static KeyRequestType requestTypeOf(CryptographicKeyItemBasicModel item) {
        return switch (item.type()) {
            case PRIVATE_KEY -> KeyRequestType.KEY_PAIR;
            case SECRET_KEY -> KeyRequestType.SECRET;
            case PUBLIC_KEY, SPLIT_KEY ->
                throw refusal(NOT_EXPORTED_TYPE, item.uuid(), item.type().getLabel().toLowerCase(Locale.ROOT));
        };
    }

    /**
     * What the platform holds about the key, for the adapter to check the key the connector says it exported. An
     * imported key carries the reference the platform minted for it; a key created through a connector has none.
     */
    private HeldKey heldKey(CryptographicKeyItemBasicModel item) {
        KeyRequestType type = requestTypeOf(item);
        byte[] publicKeySpki = type == KeyRequestType.KEY_PAIR ? publicKeyOfPair(item) : null;
        UUID keyReference = cryptographicKeyItemRepository.findKeyReferenceUuidByUuid(item.uuid()).orElse(null);
        return new HeldKey(type, item.algorithm(), item.length(), publicKeySpki, keyReference);
    }

    private byte[] publicKeyOfPair(CryptographicKeyItemBasicModel item) {
        return cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(item.parentKeyUuid()))
                .stream()
                .filter(candidate -> candidate.getType() == KeyType.PUBLIC_KEY
                        && candidate.getFormat() == KeyFormat.SPKI && candidate.getKeyData() != null)
                .findFirst()
                .map(publicKey -> Base64.getDecoder().decode(publicKey.getKeyData()))
                .orElseThrow(() -> refusal(NO_PUBLIC_RECORD, item.parentKeyUuid()));
    }

    private static ValidationException refusal(String message, Object... arguments) {
        return new ValidationException(ValidationError.create(message.formatted(arguments)));
    }
}
