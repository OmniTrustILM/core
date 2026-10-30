package com.otilm.core.signing.engine.resolver;

import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedSigningProfile;
import com.otilm.core.signing.engine.error.SigningEngineException;

/**
 * Resolves a cached, UUID-only {@link SigningProfileModel} into the transient {@link ResolvedSigningProfile}. Each
 * implementation handles one workflow type and declares support via {@link #supports}.
 */
public interface SigningProfileResolver {

    boolean supports(SigningProfileModel<?, ?> profile);

    ResolvedSigningProfile resolve(SigningProfileModel<?, ?> profile) throws SigningEngineException;
}
