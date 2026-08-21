package com.otilm.core.signing.contentsigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Turns a content-signing profile's timestamp-source reference into the profile name the in-process timestamp bridge
 * takes. The reference is deliberately unpinned, so it is resolved per request rather than cached.
 */
@Component
public class TimestampSourceResolver {

    private static final String CLIENT_MESSAGE = "Internal error while timestamping the signature";

    private final SigningProfileInternalService signingProfileService;

    public TimestampSourceResolver(SigningProfileInternalService signingProfileService) {
        this.signingProfileService = signingProfileService;
    }

    public String profileNameFor(UUID timestampSourceProfileUuid) throws SigningEngineException {
        if (timestampSourceProfileUuid == null) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "the Signing Profile names no timestamp source, so no timestamp can be embedded", CLIENT_MESSAGE);
        }
        try {
            return signingProfileService.getResourceObjectInternal(timestampSourceProfileUuid).getName();
        } catch (NotFoundException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "the Signing Profile named as the timestamp source no longer exists: " + timestampSourceProfileUuid,
                    e, CLIENT_MESSAGE);
        }
    }
}
