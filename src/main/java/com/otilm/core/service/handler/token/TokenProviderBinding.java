package com.otilm.core.service.handler.token;

import com.otilm.core.model.connector.ImmutableConnectorInterface;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/** Adapter selected for a connector together with the exact interface row a new token must persist. */
public record TokenProviderBinding(TokenProviderAdapter adapter,
        @Nullable ImmutableConnectorInterface connectorInterface) {

    public TokenProviderBinding {
        Objects.requireNonNull(adapter, "A token-provider adapter is required.");
    }
}
