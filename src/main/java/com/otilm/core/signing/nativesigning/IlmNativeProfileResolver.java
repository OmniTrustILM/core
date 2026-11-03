package com.otilm.core.signing.nativesigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.SigningProfileInternalService;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Resolves the signing profile a native operation runs on. Native operations obtain their profile only through this
 * resolver, so the {@link IlmNativeGate} cannot be skipped; authorizing the caller stays with the calling service.
 */
@Component
public class IlmNativeProfileResolver {

    private final SigningProfileRepository signingProfileRepository;
    private final SigningProfileInternalService signingProfileService;

    public IlmNativeProfileResolver(SigningProfileRepository signingProfileRepository,
            SigningProfileInternalService signingProfileService) {
        this.signingProfileRepository = signingProfileRepository;
        this.signingProfileService = signingProfileService;
    }

    /**
     * Checks the profile record before the model loads, so a profile whose model cannot be built is still refused with
     * the gate's reason, then checks the model, which may come from the cache.
     *
     * @throws NotFoundException if no profile has the UUID, or the profile was renamed while it resolved
     * @throws ValidationException if the profile cannot serve the operation
     */
    @SuppressWarnings("java:S1452") // wildcards for the same reason as SigningRecordInputSource#signingProfile
    public SigningProfileModel<?, ?> resolve(UUID uuid, NativeOperation operation) throws NotFoundException {
        SigningProfile profile = signingProfileRepository
                .findByUuid(SecuredUUID.fromUUID(uuid))
                .orElseThrow(() -> new NotFoundException("Signing Profile not found: " + uuid));
        IlmNativeGate.require(profile, operation);
        SigningProfileModel<?, ?> model = signingProfileService.loadSigningProfileModel(profile.getName());
        IlmNativeGate.require(model, uuid, operation);
        return model;
    }
}
