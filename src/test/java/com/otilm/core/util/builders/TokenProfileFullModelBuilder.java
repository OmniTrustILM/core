package com.otilm.core.util.builders;

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

    public ImmutableTokenProfileFullModel build() {
        return new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, tokenInstance.name(),
                tokenInstance.uuid(), enabled, List.of(), tokenInstance, tokenInstance.connectorUuid(), Map.of(),
                Map.of(), 0);
    }
}
