package com.otilm.core.feasibility;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.security.access.AccessDeniedException;

/** In-process coordinator only. No HTTP route, stream, actor header or deployment activation. */
public final class ConversationStreamFixture {
    private final ConversationTimeline timeline;
    private final ConversationStreamAuthorization authorization;
    private volatile Runnable afterAuthorization = () -> {
    };

    public ConversationStreamFixture(ConversationTimeline timeline, ConversationStreamAuthorization authorization) {
        this.timeline = timeline;
        this.authorization = authorization;
    }

    public ConversationTimeline.Batch read(UUID actor, UUID conversation, Optional<UUID> cursor, int limit) {
        return authorized(actor, conversation, scope -> timeline.read(conversation, scope.revision(), cursor, limit));
    }

    public ConversationTimeline.RunResult command(UUID actor, UUID conversation, ConversationTimeline.CommandKind kind,
            String key, byte[] body) {
        return authorized(actor, conversation, scope -> timeline.command(scope, kind, key, body));
    }

    public ConversationTimeline.RunResult cancel(UUID actor, UUID conversation, UUID run, String key, byte[] body) {
        return authorized(actor, conversation, scope -> timeline.cancel(scope, run, key, body));
    }

    private <T> T authorized(UUID actor, UUID conversation, Function<ConversationTimeline.Scope, Optional<T>> action) {
        for (int attempt = 0; attempt < 3; attempt++) {
            ConversationTimeline.Scope scope = timeline.scope(actor, conversation);
            authorization.require(actor, scope);
            afterAuthorization.run();
            Optional<T> result = action.apply(scope);
            if (result.isPresent()) {
                return result.orElseThrow();
            }
        }
        throw new AccessDeniedException("Conversation unavailable");
    }

    public void afterAuthorization(Runnable barrier) {
        afterAuthorization = java.util.Objects.requireNonNull(barrier);
    }
}
