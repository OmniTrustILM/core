package com.otilm.core.model.crypto;

import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.TokenProfile;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Immutable token-profile snapshot that does not require its token-instance association to be loaded. */
public record ImmutableTokenProfileBasicModel(UUID uuid, String name, String description, String tokenInstanceName,
        UUID tokenInstanceReferenceUuid, Boolean enabled, List<KeyUsage> usages) implements TokenProfileBasicModel {

    public ImmutableTokenProfileBasicModel {
        usages = usages == null ? List.of() : List.copyOf(usages);
    }

    public static ImmutableTokenProfileBasicModel from(TokenProfile tokenProfile) {
        Objects.requireNonNull(tokenProfile, "Token profile is required.");
        return new ImmutableTokenProfileBasicModel(tokenProfile.getUuid(), tokenProfile.getName(),
                tokenProfile.getDescription(), tokenProfile.getTokenInstanceName(),
                tokenProfile.getTokenInstanceReferenceUuid(), tokenProfile.getEnabled(), tokenProfile.getUsage());
    }
}
