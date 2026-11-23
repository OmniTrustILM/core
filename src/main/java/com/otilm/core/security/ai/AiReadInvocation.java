package com.otilm.core.security.ai;

import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.util.AuthHelper;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;

/** Trusted Java-only synchronous entry. No request field, header or production caller opens this scope. */
@Component
public final class AiReadInvocation {
    private final PlatformAuthenticationClient authenticationClient;

    public AiReadInvocation(PlatformAuthenticationClient authenticationClient) {
        this.authenticationClient = authenticationClient;
    }

    public <T, E extends Exception> T call(UUID pinnedActorUuid, CertificateReadScope scope, Duration timeout,
            AuthHelper.ThrowingSupplier<T, E> operation) throws E {
        if (AiReadInvocationContext.isActive()) {
            throw new AccessDeniedException("Nested certificate read invocation is unavailable");
        }
        Objects.requireNonNull(pinnedActorUuid, "Pinned actor is required");
        Objects.requireNonNull(scope, "Certificate read scope is required");
        Objects.requireNonNull(operation, "Read operation is required");
        if (timeout == null || timeout.isNegative() || timeout.isZero()
                || timeout.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException("Read timeout must be positive and at most thirty seconds");
        }
        var callerContext = SecurityContextHolder.getContext();
        var callerRequest = RequestContextHolder.getRequestAttributes();
        Map<String, String> callerMdc = MDC.getCopyOfContextMap();
        var context = new AiReadInvocationContext(pinnedActorUuid, scope, timeout,
                remaining -> authenticationClient.authenticateByUserUuidAuthoritatively(pinnedActorUuid, remaining));
        try {
            SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
            RequestContextHolder.resetRequestAttributes();
            MDC.clear();
            AiReadInvocationContext.open(context);
            context.authenticateAndInstall();
            T result = operation.get();
            context.requirePinnedActor(SecurityContextHolder.getContext().getAuthentication());
            return result;
        } finally {
            AiReadInvocationContext.close();
            SecurityContextHolder.setContext(callerContext);
            RequestContextHolder.resetRequestAttributes();
            if (callerRequest != null) {
                RequestContextHolder.setRequestAttributes(callerRequest, false);
            }
            if (callerMdc == null) {
                MDC.clear();
            } else {
                MDC.setContextMap(callerMdc);
            }
        }
    }
}
