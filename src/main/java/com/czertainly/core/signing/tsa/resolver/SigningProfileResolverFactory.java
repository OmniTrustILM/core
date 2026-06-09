package com.czertainly.core.signing.tsa.resolver;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.core.model.signing.SigningProfileModel;
import com.czertainly.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Selects the appropriate {@link SigningProfileResolver} for a given signing profile and delegates resolution.
 */
@Component
public class SigningProfileResolverFactory {

    private final List<SigningProfileResolver> resolvers;

    public SigningProfileResolverFactory(List<SigningProfileResolver> resolvers) {
        this.resolvers = resolvers;
    }

    public ResolvedManagedTimestampingProfile resolve(SigningProfileModel<?, ?> profile) throws TspException {
        return resolvers.stream()
                .filter(r -> r.supports(profile))
                .findFirst()
                .orElseThrow(() -> new TspException(
                        TspFailureInfo.SYSTEM_FAILURE,
                        "No SigningProfileResolver supports workflow '%s'".formatted(
                                profile.workflow().getClass().getSimpleName()),
                        "The system is misconfigured."))
                .resolve(profile);
    }
}
