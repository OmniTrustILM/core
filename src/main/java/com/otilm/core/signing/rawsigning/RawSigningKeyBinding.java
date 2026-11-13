package com.otilm.core.signing.rawsigning;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Refuses a raw run whose key also signs for a content-signing or timestamping profile. Profile save refuses that
 * binding, but a raw profile saved before the rule existed can still hold one, and a raw caller could then sign the
 * digest of what the other profile attests.
 */
@Component
public class RawSigningKeyBinding {

    private final SigningProfileVersionRepository signingProfileVersionRepository;

    public RawSigningKeyBinding(SigningProfileVersionRepository signingProfileVersionRepository) {
        this.signingProfileVersionRepository = signingProfileVersionRepository;
    }

    /**
     * Asks the database on every run rather than reading the cached model: saving another profile on the key changes
     * the binding and evicts nothing cached for this one.
     */
    public void requireKeyNotShared(ResolvedManagedRawSigningProfile profile) throws SigningEngineException {
        List<String> conflictingProfileNames = signingProfileVersionRepository
                .findLatestProfileNamesBySigningKeyAndWorkflowIn(signingKeyUuid(profile.resolvedScheme()),
                        RawSigningProfileRules.conflictingWorkflows(SigningWorkflowType.RAW_SIGNING), profile.uuid());
        if (!conflictingProfileNames.isEmpty()) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "the signing key of Signing Profile '%s' also signs for Signing Profile(s) of another workflow: %s"
                            .formatted(profile.name(), String.join(", ", conflictingProfileNames)),
                    "This Signing Profile is not configured to sign raw digests");
        }
    }

    private static UUID signingKeyUuid(ResolvedManagedScheme scheme) {
        return switch (scheme) {
            case ResolvedStaticKeyManagedSigning staticKey -> staticKey.certificate().keyUuid();
        };
    }
}
