package com.otilm.core.util.ai;

import com.otilm.core.feasibility.ConversationStreamAuthGateway;
import com.otilm.core.util.lifecycle.TestSessionContextOwner;
import java.io.IOException;
import java.net.URI;
import java.util.UUID;
import org.springframework.boot.SpringApplication;

public abstract class ConversationStreamHttpProofSupport extends AuthoritativePolicyProofSupport {
    protected static final UUID ACTOR = UUID.fromString("00000000-0000-4000-8000-000000000071");
    protected static final ConversationStreamAuthGateway GATEWAY = gateway();

    private static ConversationStreamAuthGateway gateway() {
        try {
            var gateway = new ConversationStreamAuthGateway(URI.create(AUTHORITY.url()), ACTOR);
            if (TestSessionContextOwner.isEnabled()) {
                SpringApplication.getShutdownHandlers().add(gateway::close);
            } else {
                Runtime.getRuntime().addShutdownHook(new Thread(gateway::close));
            }
            return gateway;
        } catch (IOException failure) {
            throw new IllegalStateException("HTTP proof authority unavailable");
        }
    }

    public static String gatewayUrl() {
        return GATEWAY.url();
    }
}
