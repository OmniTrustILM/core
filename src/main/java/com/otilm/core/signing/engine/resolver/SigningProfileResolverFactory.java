package com.otilm.core.signing.engine.resolver;

import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedSigningProfile;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Selects the appropriate {@link SigningProfileResolver} for a given signing profile and delegates resolution.
 */
@Component
public class SigningProfileResolverFactory {

    private final List<SigningProfileResolver> resolvers;

    public SigningProfileResolverFactory(List<SigningProfileResolver> resolvers) {
        this.resolvers = resolvers;
    }

    public ResolvedSigningProfile resolve(SigningProfileModel<?, ?> profile) throws SigningEngineException {
        return resolvers
                .stream()
                .filter(r -> r.supports(profile))
                .findFirst()
                .orElseThrow(() -> new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                        "No SigningProfileResolver supports workflow '%s'"
                                .formatted(profile.workflow().getClass().getSimpleName()),
                        "The system is misconfigured."))
                .resolve(profile);
    }
}
