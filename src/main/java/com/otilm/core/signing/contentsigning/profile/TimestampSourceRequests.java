package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.model.client.signing.profile.workflow.timestamp.InternalTimestampSourceRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.timestamp.TimestampSourceRequestDto;
import java.util.UUID;

/** Reads the timestamp source a content-signing workflow request names, for validation and for persistence alike. */
public final class TimestampSourceRequests {

    private TimestampSourceRequests() {
    }

    /**
     * Only an ILM-managed TSA may issue these timestamps. The switch is exhaustive over the sealed
     * {@code TimestampSourceRequestDto}, so admitting a second source type breaks the build here rather than silently
     * mapping it away to {@code null} as if it had been omitted.
     */
    public static UUID internalProfileUuid(TimestampSourceRequestDto timestampSource) {
        return switch (timestampSource) {
            case null -> null;
            case InternalTimestampSourceRequestDto(UUID signingProfileUuid) -> signingProfileUuid;
        };
    }
}
