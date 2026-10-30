package com.otilm.core.model.crypto;

import com.otilm.api.model.core.cryptography.key.KeyUsage;
import java.util.UUID;

/** Flat projection of a key's token profile and token, as a v2 operation request needs them. */
public record KeyOperationScope(UUID tokenProfileUuid, String tokenProfileName, String tokenProfileDescription,
        String tokenInstanceName, UUID tokenInstanceReferenceUuid, Boolean tokenProfileEnabled,
        int tokenProfileUsageBitmask) {

    public TokenProfileBasicModel tokenProfile() {
        return new ImmutableTokenProfileBasicModel(tokenProfileUuid, tokenProfileName, tokenProfileDescription,
                tokenInstanceName, tokenInstanceReferenceUuid, tokenProfileEnabled,
                KeyUsage.convertBitMaskToSet(tokenProfileUsageBitmask).stream().toList());
    }
}
