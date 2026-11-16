package com.otilm.core.signing.engine.batch;

import com.otilm.api.model.core.settings.PlatformSettingsDto;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SigningSettingsDto;
import com.otilm.core.settings.SettingsCache;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** A run admits its native signing batch here before any connector or provider call. */
public final class BatchAdmission {

    private static final String REPEATED_IDENTIFIER = "Identifier appears more than once in the request";

    private BatchAdmission() {
    }

    /**
     * Refuses a batch above the platform's items-per-request cap or with a repeated identifier.
     *
     * @param identifiers the caller-chosen identifiers of the batch's items, in request order
     * @throws SigningEngineException an {@code INVALID_INPUT} naming the cap, or attributed to the repeated identifier
     */
    public static void admit(List<String> identifiers) throws SigningEngineException {
        int cap = maxItemsPerRequest();
        if (identifiers.size() > cap) {
            throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT,
                    "batch of %d items exceeds the cap of %d".formatted(identifiers.size(), cap),
                    "A request may carry at most %d items".formatted(cap));
        }
        Set<String> admitted = new HashSet<>();
        for (String identifier : identifiers) {
            if (!admitted.add(identifier)) {
                throw new SigningEngineException(SigningEngineFailure.INVALID_INPUT, "batch repeats an identifier",
                        REPEATED_IDENTIFIER).withItem(identifier);
            }
        }
    }

    private static int maxItemsPerRequest() {
        PlatformSettingsDto platform = SettingsCache.getSettings(SettingsSection.PLATFORM);
        SigningSettingsDto signing = platform != null ? platform.getSigning() : null;
        Integer configuredCap = signing != null ? signing.getMaxItemsPerRequest() : null;
        return configuredCap != null ? configuredCap : SigningSettingsDto.DEFAULT_MAX_ITEMS_PER_REQUEST;
    }
}
