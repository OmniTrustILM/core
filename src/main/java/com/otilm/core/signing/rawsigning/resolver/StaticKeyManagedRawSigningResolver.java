package com.otilm.core.signing.rawsigning.resolver;

import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.workflow.ManagedRawSigningWorkflow;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.resolver.ManagedSchemeResolver;
import com.otilm.core.signing.engine.resolver.SigningProfileResolver;
import org.springframework.stereotype.Component;

/**
 * Resolves a {@link SigningProfileModel} with a {@link ManagedRawSigningWorkflow} into the transient
 * {@link ResolvedManagedRawSigningProfile}.
 */
@Component
public class StaticKeyManagedRawSigningResolver implements SigningProfileResolver {

    private final ManagedSchemeResolver schemeResolver;

    public StaticKeyManagedRawSigningResolver(ManagedSchemeResolver schemeResolver) {
        this.schemeResolver = schemeResolver;
    }

    @Override
    public boolean supports(SigningProfileModel<?, ?> profile) {
        return profile.workflow() instanceof ManagedRawSigningWorkflow;
    }

    @Override
    public ResolvedManagedRawSigningProfile resolve(SigningProfileModel<?, ?> model) throws SigningEngineException {
        ManagedRawSigningWorkflow workflow = (ManagedRawSigningWorkflow) model.workflow();
        ResolvedManagedScheme resolvedScheme = schemeResolver.resolve(model.name(), model.signingScheme());

        return new ResolvedManagedRawSigningProfile(model.uuid(), model.name(), model.description(), model.version(),
                model.enabled(), model.enabledProtocols(), workflow.certificatePurpose(), resolvedScheme);
    }
}
