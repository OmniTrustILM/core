package com.otilm.core.model.crypto;

import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Immutable token-profile snapshot without persistence associations. */
public record ImmutableTokenProfileFullModel(UUID uuid, String name, String description, String tokenInstanceName,
        UUID tokenInstanceReferenceUuid, Boolean enabled, List<KeyUsage> usages, TokenInstanceFullModel tokenInstance,
        UUID connectorUuid) implements TokenProfileFullModel {

    public ImmutableTokenProfileFullModel {
        usages = usages == null ? List.of() : List.copyOf(usages);
    }

    public static ImmutableTokenProfileFullModel from(TokenProfile tokenProfile) {
        Objects.requireNonNull(tokenProfile, "Token profile is required.");
        TokenInstanceReference tokenInstance = Objects
                .requireNonNull(tokenProfile.getTokenInstanceReference(),
                        "Token profile full model requires a token instance.");

        ImmutableTokenInstanceFullModel tokenInstanceFullModel = ImmutableTokenInstanceFullModel.from(tokenInstance);

        return new ImmutableTokenProfileFullModel(tokenProfile.getUuid(), tokenProfile.getName(),
                tokenProfile.getDescription(), tokenProfile.getTokenInstanceName(),
                Objects
                        .requireNonNull(tokenProfile.getTokenInstanceReferenceUuid(),
                                "Token profile full model requires a token instance UUID."),
                tokenProfile.getEnabled(), tokenProfile.getUsage(), tokenInstanceFullModel,
                tokenInstance.getConnectorUuid());
    }
}
