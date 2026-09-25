package com.otilm.core.service.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import com.otilm.core.service.handler.KeyTransferCapabilityService;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
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
 */
@Service
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public class CryptographicKeyImportServiceImpl implements CryptographicKeyImportExternalService {

    private static final String DISABLED = "Token profile %s is disabled.";
    private static final String NOT_OFFERED = "Token profile %s does not import a %s.";
    private static final String PROFILE_CHANGED = "Token profile %s changed while its import was checked. Try again.";

    private final AuthorizationEnforcer authorizationEnforcer;
    private final TokenProfileRepository tokenProfileRepository;
    private final KeyTransferCapabilityService keyTransferCapabilityService;
    private final KeyProviderAdapterFactory keyProviderAdapterFactory;

    public CryptographicKeyImportServiceImpl(AuthorizationEnforcer authorizationEnforcer,
            TokenProfileRepository tokenProfileRepository, KeyTransferCapabilityService keyTransferCapabilityService,
            KeyProviderAdapterFactory keyProviderAdapterFactory) {
        this.authorizationEnforcer = authorizationEnforcer;
        this.tokenProfileRepository = tokenProfileRepository;
        this.keyTransferCapabilityService = keyTransferCapabilityService;
        this.keyProviderAdapterFactory = keyProviderAdapterFactory;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CRYPTOGRAPHIC_KEY, action = ResourceAction.IMPORT_KEY)
    public List<BaseAttribute> listImportKeyAttributes(UUID tokenInstanceUuid, UUID tokenProfileUuid,
            KeyRequestType type) throws ConnectorException, NotFoundException {
        TokenProfileFullModel profile = requireAccess(tokenInstanceUuid, tokenProfileUuid);
        requireImportable(profile, type);
        return keyProviderAdapterFactory.forToken(profile.tokenInstance()).listImportKeyAttributes(profile, type);
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
    private void requireImportable(TokenProfileFullModel profile, KeyRequestType type)
            throws ConnectorException, NotFoundException {
        if (!Boolean.TRUE.equals(profile.enabled())) {
            throw refusal(DISABLED, profile.name());
        }
        Map<KeyRequestType, Set<KeyAlgorithm>> importable = keyTransferCapabilityService
                .importableKeyTypes(profile)
                .orElseThrow(() -> refusal(PROFILE_CHANGED, profile.name()));
        if (importable.getOrDefault(type, Set.of()).isEmpty()) {
            throw refusal(NOT_OFFERED, profile.name(), type.getLabel().toLowerCase(Locale.ROOT));
        }
    }

    private static ValidationException refusal(String message, Object... arguments) {
        return new ValidationException(ValidationError.create(message.formatted(arguments)));
    }
}
