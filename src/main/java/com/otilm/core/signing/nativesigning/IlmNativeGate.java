package com.otilm.core.signing.nativesigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileGateRow;
import com.otilm.core.model.signing.SigningProfileModel;

import java.util.UUID;

/**
 * Stateless checks run before every native signing operation dispatches. {@link IlmNativeProfileResolver} is the only
 * entry point: it runs the record check before the model loads, so a profile whose model cannot be built is still
 * refused here, and the model check on the model it loads. Both run these checks in this order: ILM_NATIVE is enabled,
 * the profile is enabled, the workflow matches the operation, and the scheme is not delegated. The model check first
 * confirms the model is the requested profile.
 */
final class IlmNativeGate {

    private IlmNativeGate() {
    }

    static void require(SigningProfileGateRow profile, NativeOperation operation) {
        requireServes(profile.name(), profile.ilmNativeEnabled(), profile.enabled(), profile.workflowType(),
                profile.signingScheme(), operation);
    }

    static void require(SigningProfileModel<?, ?> profile, UUID requestedUuid, NativeOperation operation)
            throws NotFoundException {
        // The model cache is keyed by name, so a rename between reads can return another profile.
        if (!profile.uuid().equals(requestedUuid)) {
            throw new NotFoundException("Signing Profile not found: " + requestedUuid);
        }
        requireServes(profile.name(), profile.enabledProtocols().contains(SigningProtocol.ILM_NATIVE),
                profile.enabled(), profile.workflow().getWorkflowType(), profile.signingScheme().getSchemeType(),
                operation);
    }

    private static void requireServes(String name, boolean ilmNativeEnabled, boolean enabled,
            SigningWorkflowType workflowType, SigningScheme scheme, NativeOperation operation) {
        if (!ilmNativeEnabled) {
            throw new ValidationException(
                    "Signing profile '%s' does not have the ILM_NATIVE protocol enabled.".formatted(name));
        }
        if (!enabled) {
            throw new ValidationException("Signing profile '%s' is disabled.".formatted(name));
        }
        if (workflowType != operation.servedWorkflow()) {
            throw new ValidationException(
                    "Signing profile '%s' is not a %s profile.".formatted(name, operation.servedWorkflow().getCode()));
        }
        if (scheme == SigningScheme.DELEGATED) {
            throw new ValidationException(
                    "Signing profile '%s' uses delegated signing; the native API signs only with keys ILM manages."
                            .formatted(name));
        }
    }
}
