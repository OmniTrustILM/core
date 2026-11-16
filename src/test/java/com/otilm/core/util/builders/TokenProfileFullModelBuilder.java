package com.otilm.core.util.builders;

import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.otilm.core.util.builders.TokenInstanceFullModelBuilder.aTokenSnapshot;

/**
 * Builds an enabled token-profile snapshot on a {@link TokenInstanceFullModelBuilder#aTokenSnapshot() token snapshot}.
 * Tests override only the token or the enabled flag their scenario turns on.
 */
public final class TokenProfileFullModelBuilder {

    private TokenInstanceFullModel tokenInstance = aTokenSnapshot().build();
    private boolean enabled = true;
    private List<KeyUsage> usages = List.of();

    public static TokenProfileFullModelBuilder aTokenProfileSnapshot() {
        return new TokenProfileFullModelBuilder();
    }

    public TokenProfileFullModelBuilder withTokenInstance(TokenInstanceFullModel tokenInstance) {
        this.tokenInstance = tokenInstance;
        return this;
    }

    public TokenProfileFullModelBuilder withEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    public TokenProfileFullModelBuilder withUsages(KeyUsage... usages) {
        this.usages = List.of(usages);
        return this;
    }

    public ImmutableTokenProfileFullModel build() {
        return new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, tokenInstance.name(),
                tokenInstance.uuid(), enabled, usages, tokenInstance, tokenInstance.connectorUuid(), Map.of(), Map.of(),
                0);
    }
}
