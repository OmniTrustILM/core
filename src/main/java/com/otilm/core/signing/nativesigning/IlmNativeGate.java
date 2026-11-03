package com.otilm.core.signing.nativesigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;

import java.util.UUID;

/**
 * Stateless check run before every native signing operation dispatches. Checks run in this order: the requested UUID
 * matches the model, ILM_NATIVE is enabled, the profile is enabled, the workflow matches the operation, and the scheme
 * is not delegated.
 */
public final class IlmNativeGate {

    private IlmNativeGate() {
    }

    public static void require(SigningProfileModel<?, ?> profile, UUID requestedUuid, NativeOperation operation)
            throws NotFoundException {
        // The model cache is keyed by name, so a rename between reads can return another profile.
        if (!profile.uuid().equals(requestedUuid)) {
            throw new NotFoundException("Signing Profile not found: " + requestedUuid);
        }
        if (!profile.enabledProtocols().contains(SigningProtocol.ILM_NATIVE)) {
            throw new ValidationException(
                    "Signing profile '%s' does not have the ILM_NATIVE protocol enabled.".formatted(profile.name()));
        }
        if (!profile.enabled()) {
            throw new ValidationException("Signing profile '%s' is disabled.".formatted(profile.name()));
        }
        if (profile.workflow().getWorkflowType() != operation.servedWorkflow()) {
            throw new ValidationException("Signing profile '%s' is not a %s profile."
                    .formatted(profile.name(), operation.servedWorkflow().getCode()));
        }
        if (profile.signingScheme().getSchemeType() == SigningScheme.DELEGATED) {
            throw new ValidationException(
                    "Signing profile '%s' uses delegated signing; the native API signs only with keys ILM manages."
                            .formatted(profile.name()));
        }
    }
}
