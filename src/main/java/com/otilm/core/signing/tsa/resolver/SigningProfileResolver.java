package com.otilm.core.signing.tsa.resolver;

import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedTimestampingProfile;

/**
 * Resolves a cached, UUID-only {@link SigningProfileModel} into the transient
 * {@link ResolvedManagedTimestampingProfile} consumed by the timestamping pipeline.
 *
 * <p>Each implementation handles one workflow type and declares support via {@link #supports}.
 * {@link SigningProfileResolverFactory} selects the matching implementation at request time.</p>
 */
public interface SigningProfileResolver {

    boolean supports(SigningProfileModel<?, ?> profile);

    ResolvedManagedTimestampingProfile resolve(SigningProfileModel<?, ?> profile) throws TspException;
}
