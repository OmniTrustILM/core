package com.otilm.core.security.ai;

import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/** Thread-confined authority state. Opening and closing are available only to the trusted invocation entry. */
public final class AiReadInvocationContext {
    private static final ThreadLocal<AiReadInvocationContext> CURRENT = new ThreadLocal<>();
    private final UUID invocationUuid = UUID.randomUUID();
    private final UUID pinnedActorUuid;
    private final CertificateReadScope scope;
    private final long deadline;
    private final Function<Duration, AuthenticationInfo> authenticate;

    AiReadInvocationContext(UUID pinnedActorUuid, CertificateReadScope scope, Duration timeout,
            Function<Duration, AuthenticationInfo> authenticate) {
        this.pinnedActorUuid = pinnedActorUuid;
        this.scope = scope;
        this.deadline = System.nanoTime() + timeout.toNanos();
        this.authenticate = authenticate;
    }

    public static Optional<AiReadInvocationContext> current() {
        return Optional.ofNullable(CURRENT.get());
    }

    public static boolean isActive() {
        return CURRENT.get() != null;
    }

    static void open(AiReadInvocationContext context) {
        if (isActive()) {
            throw denied();
        }
        CURRENT.set(context);
    }

    static void close() {
        CURRENT.remove();
    }

    public UUID invocationUuid() {
        return invocationUuid;
    }

    public UUID pinnedActorUuid() {
        return pinnedActorUuid;
    }

    public CertificateReadScope scope() {
        return scope;
    }

    /** Monotonic, cooperative budget; transport cancellation never starts a detached operation worker. */
    public Duration remainingAuthorityTimeout() {
        long remaining = deadline - System.nanoTime();
        if (CURRENT.get() != this || Thread.currentThread().isInterrupted() || remaining <= 0) {
            throw denied();
        }
        return Duration.ofNanos(Math.min(remaining, Duration.ofSeconds(5).toNanos()));
    }

    /** Floors the remaining budget to JDBC's whole seconds; a subsecond budget cannot start SQL. */
    public int remainingQueryTimeoutSeconds() {
        requirePinnedActor(SecurityContextHolder.getContext().getAuthentication());
        int seconds = (int) remainingAuthorityTimeout().toSeconds();
        if (seconds < 1) {
            throw denied();
        }
        return seconds;
    }

    public PlatformUserDetails requirePinnedActor(Authentication authentication) {
        remainingAuthorityTimeout();
        if (!(authentication instanceof PlatformAuthenticationToken token) || !token.isAuthenticated()) {
            throw denied();
        }
        PlatformUserDetails principal = token.getPrincipal();
        if (principal == null || !pinnedActorUuid.toString().equals(principal.getUserUuid())) {
            throw denied();
        }
        return principal;
    }

    /** Refreshes the actual current actor at every vote, rather than accepting a supplied cached permission JSON. */
    public String refreshPrincipal() {
        requirePinnedActor(SecurityContextHolder.getContext().getAuthentication());
        return authenticateAndInstall();
    }

    String authenticateAndInstall() {
        AuthenticationInfo info;
        try {
            info = authenticate.apply(remainingAuthorityTimeout());
            if (info == null || info.isAnonymous() || !pinnedActorUuid.toString().equals(info.getUserUuid())
                    || info.getRawData() == null) {
                throw denied();
            }
        } catch (Exception failure) {
            throw denied();
        }
        remainingAuthorityTimeout();
        var freshContext = SecurityContextHolder.createEmptyContext();
        freshContext.setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
        SecurityContextHolder.setContext(freshContext);
        LoggingHelper.clearActorInfo();
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, info.getAuthMethod());
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, info.getUserUuid(), info.getUsername());
        return info.getRawData();
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Certificate read authority unavailable");
    }
}
