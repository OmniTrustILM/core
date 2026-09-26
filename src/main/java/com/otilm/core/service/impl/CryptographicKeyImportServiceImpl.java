package com.otilm.core.service.impl;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.cryptography.key.KeyImportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.key.normalization.KeyNormalizer;
import com.otilm.core.key.normalization.NormalizedKey;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.mapper.crypto.CryptographicKeyDtoMapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImportedKey;
import com.otilm.core.model.crypto.KeyImportMetadata;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyImportExternalService;
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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

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
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public class CryptographicKeyImportServiceImpl implements CryptographicKeyImportExternalService {

    private static final String DISABLED = "Token profile %s is disabled.";
    private static final String NOT_OFFERED = "Token profile %s does not import a %s.";
    private static final String PROFILE_CHANGED = "Token profile %s changed while its import was checked. Try again.";
    private static final String ALGORITHM_NOT_OFFERED = "Token profile %s does not import the %s algorithm for a %s.";
    private static final String NOT_EXPORTED = "Token profile %s does not export the %s algorithm for a %s, so the key cannot be imported as exportable.";
    private static final String NOT_A_GROUP = "Group UUID %s is not valid.";

    private final AuthorizationEnforcer authorizationEnforcer;
    private final TokenProfileRepository tokenProfileRepository;
    private final KeyTransferCapabilityService keyTransferCapabilityService;
    private final KeyProviderAdapterFactory keyProviderAdapterFactory;
    private final AttributeEngine attributeEngine;
    private final KeyNormalizer keyNormalizer;
    private final KeyImportSaga keyImportSaga;
    private final GroupRepository groupRepository;

    public CryptographicKeyImportServiceImpl(AuthorizationEnforcer authorizationEnforcer,
            TokenProfileRepository tokenProfileRepository, KeyTransferCapabilityService keyTransferCapabilityService,
            KeyProviderAdapterFactory keyProviderAdapterFactory, AttributeEngine attributeEngine,
            KeyNormalizer keyNormalizer, KeyImportSaga keyImportSaga, GroupRepository groupRepository) {
        this.authorizationEnforcer = authorizationEnforcer;
        this.tokenProfileRepository = tokenProfileRepository;
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
        TokenProfileFullModel profile = requireAccess(tokenInstanceUuid, tokenProfileUuid);
        requireImportable(profile, type);
        return keyProviderAdapterFactory.forToken(profile.tokenInstance()).listImportKeyAttributes(profile, type);
    }

    /**
     * Checks everything the file does not decide before opening it, and what the key it holds decides once opened; the
     * saga then carries the key across the connector boundary. The caller's copy of the file and the key made from it
     * are overwritten whatever the outcome.
     */
    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.IMPORT_KEY)
    public KeyDetailDto importKey(UUID tokenInstanceUuid, UUID tokenProfileUuid, KeyRequestType type,
            KeyImportRequestDto request) throws ConnectorException, NotFoundException, AttributeException {
        TokenProfileFullModel profile = requireAccess(tokenInstanceUuid, tokenProfileUuid);
        Set<KeyAlgorithm> importable = requireImportable(profile, type);
        KeyImportMetadata metadata = new KeyImportMetadata(request.getName(), request.getDescription(),
                requireGroups(request.getGroupUuids()));
        attributeEngine.validateCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, request.getCustomAttributes());
        List<RequestAttribute> importAttributes = requireImportAttributes(profile, type, request.getImportAttributes());
        boolean exportable = Boolean.TRUE.equals(request.getExportable());
        byte[] file = request.getFile().content();
        try {
            NormalizedKey key = keyNormalizer.normalize(file, request.getInputPassphrase(), type);
            try {
                requireAlgorithm(profile, type, importable, key.algorithm());
                requireExportable(profile, type, key.algorithm(), exportable);
                KeyImportTerms terms = new KeyImportTerms(profile, type, key.algorithm(), fingerprintOf(key),
                        exportable, importAttributes, AuthHelper.getUserIdentification());
                ImportedKey imported = keyImportSaga
                        .importKey(terms, ImportIdempotencyKey.of(terms, file), key, metadata);
                return detailOf(imported, request.getCustomAttributes());
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

    private static String fingerprintOf(NormalizedKey key) {
        return CryptographyUtil
                .calculateKeyFingerprint(new KeyMaterial(KeyFormat.SPKI,
                        Base64.getEncoder().encodeToString(key.subjectPublicKeyInfo())));
    }

    /**
     * The key's detail, named in the audit record. A new key gets its custom attributes as key creation writes them; a
     * repeat changes nothing, and shows the key as it is now to a caller who may still see it.
     */
    private KeyDetailDto detailOf(ImportedKey imported, List<RequestAttribute> customAttributes)
            throws NotFoundException, AttributeException {
        CryptographicKeyFullModel key = imported.key();
        List<ResponseAttribute> keyAttributes;
        if (imported.repeat()) {
            authorizationEnforcer
                    .enforce(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, SecuredUUID.fromUUID(key.uuid()));
            keyAttributes = attributeEngine.getObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.uuid());
        } else {
            keyAttributes = attributeEngine
                    .updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, key.uuid(), customAttributes);
        }
        KeyDetailDto detail = CryptographicKeyDtoMapper.mapToDetailDto(key);
        detail.setCustomAttributes(keyAttributes);
        LoggingHelper.putLogResourceInfo(Resource.CRYPTOGRAPHIC_KEY, false, key.uuid().toString(), key.name());
        return detail;
    }

    /** The detail of the token profile, and the detail and members of its token, as exporting a key requires. */
    private TokenProfileFullModel requireAccess(UUID tokenInstanceUuid, UUID tokenProfileUuid)
            throws NotFoundException {
        TokenProfileFullModel profile = tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(tokenProfileUuid, tokenInstanceUuid)
                .orElseThrow(() -> new NotFoundException(TokenProfile.class, tokenProfileUuid));
        authorizationEnforcer
                .enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, SecuredUUID.fromUUID(tokenProfileUuid));
        SecuredUUID token = SecuredUUID.fromUUID(tokenInstanceUuid);
        authorizationEnforcer.enforce(Resource.TOKEN, ResourceAction.DETAIL, token);
        authorizationEnforcer.enforce(Resource.TOKEN, ResourceAction.MEMBERS, token);
        return profile;
    }

    /** Core's gates for the profile, in order: enabled, then importing the type at all. */
    private Set<KeyAlgorithm> requireImportable(TokenProfileFullModel profile, KeyRequestType type)
            throws ConnectorException, NotFoundException {
        if (!Boolean.TRUE.equals(profile.enabled())) {
            throw refusal(DISABLED, profile.name());
        }
        Map<KeyRequestType, Set<KeyAlgorithm>> importable = keyTransferCapabilityService
                .importableKeyTypes(profile)
                .orElseThrow(() -> refusal(PROFILE_CHANGED, profile.name()));
        Set<KeyAlgorithm> algorithms = importable.getOrDefault(type, Set.of());
        if (algorithms.isEmpty()) {
            throw refusal(NOT_OFFERED, profile.name(), type.getLabel().toLowerCase(Locale.ROOT));
        }
        return algorithms;
    }

    private static ValidationException refusal(String message, Object... arguments) {
        return new ValidationException(ValidationError.create(message.formatted(arguments)));
    }
}
