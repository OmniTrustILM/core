package com.otilm.core.service.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Key listing reaches past the inventory to the token itself. It needs a profile whose connector advertises it and a
 * caller who may see the token's members.
 */
@Component
public class KeyListGates {

    public static final String NOT_LISTABLE = "Token profile %s cannot list the keys in its key storage: its connector "
            + "does not support key listing.";

    private final KeyImportGates keyImportGates;
    private final ConnectorCapabilityService connectorCapabilityService;

    public KeyListGates(KeyImportGates keyImportGates, ConnectorCapabilityService connectorCapabilityService) {
        this.keyImportGates = keyImportGates;
        this.connectorCapabilityService = connectorCapabilityService;
    }

    /** Whether the profile's connector can list the key pairs of its token. */
    public boolean isAvailable(TokenProfileFullModel profile) {
        return isAvailable(profile.tokenInstance());
    }

    /** The same, for a profile read with its token's connector interface, as the profile list filter reads it. */
    public boolean isAvailable(TokenProfile profile) {
        return connectorCapabilityService
                .supports(profile.getTokenInstanceReference().getConnectorInterface(), FeatureFlag.KEY_LIST);
    }

    /** Whether the token's connector can list the key pairs it holds. */
    public boolean isAvailable(TokenInstanceFullModel tokenInstance) {
        return connectorCapabilityService.supports(tokenInstance.connectorInterface(), FeatureFlag.KEY_LIST);
    }

    /**
     * The token's profile, with access enforced as key import enforces it.
     *
     * @throws NotFoundException if the token has no such profile
     * @throws ValidationException if the profile's connector lacks key listing, or the profile is disabled
     */
    public TokenProfileFullModel requireListable(UUID tokenInstanceUuid, UUID tokenProfileUuid)
            throws NotFoundException {
        TokenProfileFullModel profile = keyImportGates.requireAccess(tokenInstanceUuid, tokenProfileUuid);
        requireListableAndEnabled(profile);
        return profile;
    }

    private void requireListableAndEnabled(TokenProfileFullModel profile) {
        if (!isAvailable(profile)) {
            throw new ValidationException(ValidationError.create(NOT_LISTABLE.formatted(profile.name())));
        }
        if (!Boolean.TRUE.equals(profile.enabled())) {
            throw new ValidationException(ValidationError.create(KeyImportGates.DISABLED.formatted(profile.name())));
        }
    }
}
