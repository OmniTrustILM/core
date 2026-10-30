package com.otilm.core.model.crypto;

import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record ImmutableTokenProfileListModel(UUID uuid, String name, String description, String tokenInstanceName,
        UUID tokenInstanceReferenceUuid, Boolean enabled, List<KeyUsage> usages,
        TokenInstanceStatus tokenInstanceStatus) implements TokenProfileListModel {

    public ImmutableTokenProfileListModel {
        usages = usages == null ? List.of() : List.copyOf(usages);
    }

    public static ImmutableTokenProfileListModel from(TokenProfile profile) {
        Objects.requireNonNull(profile, "Token profile is required.");
        TokenInstanceReference token = Objects
                .requireNonNull(profile.getTokenInstanceReference(),
                        "Token profile list model requires a token instance.");
        return new ImmutableTokenProfileListModel(profile.getUuid(), profile.getName(), profile.getDescription(),
                profile.getTokenInstanceName(), profile.getTokenInstanceReferenceUuid(), profile.getEnabled(),
                profile.getUsage(), token.getStatus());
    }
}
