package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.model.client.signing.profile.workflow.timestamp.InternalTimestampSourceRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.timestamp.TimestampSourceRequestDto;
import java.util.UUID;

/** Reads the timestamp source a content-signing workflow request names, for validation and for persistence alike. */
public final class TimestampSourceRequests {

    private TimestampSourceRequests() {
    }

    /**
     * Only an ILM-managed TSA may issue these timestamps.
     */
    public static UUID internalProfileUuid(TimestampSourceRequestDto timestampSource) {
        return switch (timestampSource) {
            case null -> null;
            case InternalTimestampSourceRequestDto(UUID signingProfileUuid) -> signingProfileUuid;
        };
    }
}
