package com.otilm.core.service.impl;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.ImportOutcome;
import com.otilm.api.model.client.cryptography.key.KeyImportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.key.normalization.DerivationBudget;
import com.otilm.core.key.normalization.KeyNormalizer;
import com.otilm.core.key.normalization.NormalizedKey;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.mapper.crypto.CryptographicKeyDtoMapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImportedKey;
import com.otilm.core.model.crypto.ImportedKeyDetail;
import com.otilm.core.model.crypto.KeyImportMetadata;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.handler.KeyImportSaga;
import com.otilm.core.service.handler.KeyTransferCapabilityService;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.CryptographyUtil;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import static com.otilm.core.service.handler.KeyImportGates.ALGORITHM_NOT_OFFERED;
import static com.otilm.core.service.handler.KeyImportGates.PROFILE_CHANGED;

/**
 * Takes plain UUIDs, so the import permission is checked on its own: the owner of an object is granted any action
 * checked against that object, and import must never be granted that way.
 *
 * <p>
 * The import itself answers the caller only in the platform's words: the connector's never reach it on a call that
 * carried the key.
 * </p>
 */
@Service
@Transactional(propagation = Propagation.NOT_SUPPORTED, rollbackFor = Exception.class)
public class CryptographicKeyImportServiceImpl implements CryptographicKeyImportExternalService {

    /** The refusal of a key the inventory holds already to a caller who may not see it, for either kind of key. */
    public static final String KEY_EXISTS = "The key already exists.";

    private static final String NOT_EXPORTED = "Token profile %s does not export the %s algorithm for a %s, so the key cannot be imported as exportable.";
    private static final String NOT_A_GROUP = "Group UUID %s is not valid.";

    private final AuthorizationEnforcer authorizationEnforcer;
    private final KeyImportGates keyImportGates;
    private final KeyTransferCapabilityService keyTransferCapabilityService;
    private final KeyProviderAdapterFactory keyProviderAdapterFactory;
    private final AttributeEngine attributeEngine;
    private final KeyNormalizer keyNormalizer;
    private final KeyImportSaga keyImportSaga;
    private final GroupRepository groupRepository;

    public CryptographicKeyImportServiceImpl(AuthorizationEnforcer authorizationEnforcer, KeyImportGates keyImportGates,
            KeyTransferCapabilityService keyTransferCapabilityService,
            KeyProviderAdapterFactory keyProviderAdapterFactory, AttributeEngine attributeEngine,
            KeyNormalizer keyNormalizer, KeyImportSaga keyImportSaga, GroupRepository groupRepository) {
        this.authorizationEnforcer = authorizationEnforcer;
        this.keyImportGates = keyImportGates;
        this.keyTransferCapabilityService = keyTransferCapabilityService;
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
        this.attributeEngine = attributeEngine;
        this.keyNormalizer = keyNormalizer;
        this.keyImportSaga = keyImportSaga;
        this.groupRepository = groupRepository;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.IMPORT_KEY)
    public List<BaseAttribute> listImportKeyAttributes(UUID tokenInstanceUuid, UUID tokenProfileUuid,
            KeyRequestType type) throws ConnectorException, NotFoundException {
        TokenProfileFullModel profile = keyImportGates.requireAccess(tokenInstanceUuid, tokenProfileUuid);
        keyImportGates.requireImportable(profile, type);
        return keyProviderAdapterFactory.forToken(profile.tokenInstance()).listImportKeyAttributes(profile, type);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.IMPORT_KEY)
    public ImportedKeyDetail importKey(UUID tokenInstanceUuid, UUID tokenProfileUuid, KeyRequestType type,
            KeyImportRequestDto request) throws ConnectorException, NotFoundException, AttributeException {
        ImportedKey imported = imported(tokenInstanceUuid, tokenProfileUuid, type, request);
        return new ImportedKeyDetail(detailOf(imported), imported.outcome());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.IMPORT_KEY)
    public ImportedKey importKeyWithOutcome(UUID tokenInstanceUuid, UUID tokenProfileUuid, KeyRequestType type,
            KeyImportRequestDto request) throws ConnectorException, NotFoundException, AttributeException {
        return imported(tokenInstanceUuid, tokenProfileUuid, type, request);
    }

    /**
     * Checks everything the file does not decide before opening it, and what the key it holds decides once opened; the
     * saga then carries the key across the connector boundary. The caller's copy of the file and the key made from it
     * are overwritten whatever the outcome.
     */
    private ImportedKey imported(UUID tokenInstanceUuid, UUID tokenProfileUuid, KeyRequestType type,
            KeyImportRequestDto request) throws ConnectorException, NotFoundException, AttributeException {
        TokenProfileFullModel profile = keyImportGates.requireAccess(tokenInstanceUuid, tokenProfileUuid);
        Set<KeyAlgorithm> importable = keyImportGates.requireImportable(profile, type);
        KeyImportMetadata metadata = new KeyImportMetadata(request.getName(), request.getDescription(),
                requireGroups(request.getGroupUuids()), request.getCustomAttributes());
        attributeEngine.validateCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, request.getCustomAttributes());
        List<RequestAttribute> importAttributes = requireImportAttributes(profile, type, request.getImportAttributes());
        boolean exportable = Boolean.TRUE.equals(request.getExportable());
        byte[] file = request.getFile().content();
        try {
            NormalizedKey key = keyNormalizer
                    .normalize(file, request.getInputPassphrase(), type, DerivationBudget.forFile());
            try {
                requireAlgorithm(profile, type, importable, key.algorithm());
                requireExportable(profile, type, key.algorithm(), exportable);
                KeyImportTerms terms = new KeyImportTerms(profile, type, key.algorithm(), fingerprintOf(key),
                        exportable, importAttributes, AuthHelper.getUserIdentification());
                return keyImportSaga.importKey(terms, ImportIdempotencyKey.of(terms, file), key, metadata);
            } finally {
                key.clear();
            }
        } finally {
            Arrays.fill(file, (byte) 0);
        }
    }

    /** The groups the key joins, each checked to exist before anything is imported. */
    private Set<UUID> requireGroups(List<String> groupUuids) throws NotFoundException {
        if (groupUuids == null) {
            return Set.of();
        }
        Set<UUID> groups = new HashSet<>();
        for (String groupUuid : groupUuids) {
            UUID uuid;
            try {
                uuid = UUID.fromString(groupUuid);
            } catch (IllegalArgumentException e) {
                throw refusal(NOT_A_GROUP, groupUuid);
            }
            if (groupRepository.findByUuid(uuid).isEmpty()) {
                throw new NotFoundException(Group.class, uuid);
            }
            groups.add(uuid);
        }
        return groups;
    }

    /** The import attributes, validated against the connector's schema as key creation validates its own. */
    private List<RequestAttribute> requireImportAttributes(TokenProfileFullModel profile, KeyRequestType type,
            List<RequestAttribute> attributes) throws ConnectorException, NotFoundException, AttributeException {
        List<RequestAttribute> stated = attributes == null ? List.of() : attributes;
        List<BaseAttribute> definitions = keyProviderAdapterFactory
                .forToken(profile.tokenInstance())
                .listImportKeyAttributes(profile, type);
        attributeEngine
                .validateUpdateDataAttributes(profile.tokenInstance().connectorUuid(), null, definitions, stated);
        return stated;
    }

    private static void requireAlgorithm(TokenProfileFullModel profile, KeyRequestType type,
            Set<KeyAlgorithm> importable, KeyAlgorithm algorithm) {
        if (!importable.contains(algorithm)) {
            throw refusal(ALGORITHM_NOT_OFFERED, profile.name(), algorithm.getLabel(),
                    type.getLabel().toLowerCase(Locale.ROOT));
        }
    }

    /** An exportable key needs export of its type and algorithm, since the permission can never be raised later. */
    private void requireExportable(TokenProfileFullModel profile, KeyRequestType type, KeyAlgorithm algorithm,
            boolean exportable) throws ConnectorException, NotFoundException {
        if (!exportable) {
            return;
        }
        Map<KeyRequestType, Set<KeyAlgorithm>> exported = keyTransferCapabilityService
                .exportableKeyTypes(profile)
                .orElseThrow(() -> refusal(PROFILE_CHANGED, profile.name()));
        if (!exported.getOrDefault(type, Set.of()).contains(algorithm)) {
            throw refusal(NOT_EXPORTED, profile.name(), algorithm.getLabel(), type.getLabel().toLowerCase(Locale.ROOT));
        }
    }

    /** The fingerprint of the key's public key, as the inventory computes it; a secret key has none. */
    private static String fingerprintOf(NormalizedKey key) {
        if (key.type() == KeyRequestType.SECRET) {
            return null;
        }
        return CryptographyUtil
                .calculateKeyFingerprint(new KeyMaterial(KeyFormat.SPKI,
                        Base64.getEncoder().encodeToString(key.subjectPublicKeyInfo())));
    }

    /**
     * The key's detail as it is now, named in the audit record. A key the inventory held already changed nothing, and
     * is shown only to a caller who may see it; any other is refused in words that say only that the key exists.
     */
    private KeyDetailDto detailOf(ImportedKey imported) {
        CryptographicKeyFullModel key = imported.key();
        if (imported.outcome() == ImportOutcome.EXISTING) {
            requireVisible(key);
        }
        KeyDetailDto detail = CryptographicKeyDtoMapper.mapToDetailDto(key);
        detail
                .setCustomAttributes(
                        attributeEngine.getObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.uuid()));
        LoggingHelper.putLogResourceInfo(Resource.CRYPTOGRAPHIC_KEY, false, key.uuid().toString(), key.name());
        return detail;
    }

    private void requireVisible(CryptographicKeyFullModel key) {
        try {
            authorizationEnforcer
                    .enforce(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, SecuredUUID.fromUUID(key.uuid()));
        } catch (AccessDeniedException hidden) {
            throw new ValidationException(ValidationError.create(KEY_EXISTS));
        }
    }

    private static ValidationException refusal(String message, Object... arguments) {
        return new ValidationException(ValidationError.create(message.formatted(arguments)));
    }
}
