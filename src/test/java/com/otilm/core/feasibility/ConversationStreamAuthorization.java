package com.otilm.core.feasibility;

import com.otilm.core.security.ai.AiReadInvocation;
import com.otilm.core.security.ai.CertificateReadScope;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateExternalService;
import java.time.Duration;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** Discards protected health results; every retained certificate must pass the real F05 boundary. */
public final class ConversationStreamAuthorization {
    private final AiReadInvocation invocation;
    private final CertificateExternalService certificates;
    private volatile Runnable beforeInvocation = () -> {
    };

    public ConversationStreamAuthorization(AiReadInvocation invocation, CertificateExternalService certificates) {
        this.invocation = invocation;
        this.certificates = certificates;
    }

    public void require(UUID actor, ConversationTimeline.Scope scope) {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Ambient transaction unavailable");
        }
        if (actor == null || !actor.equals(scope.owner()) || scope.certificates().isEmpty()) {
            throw denied();
        }
        beforeInvocation.run();
        try {
            invocation
                    .call(actor, new CertificateReadScope(scope.raProfileId(), scope.certificates()),
                            Duration.ofSeconds(5), () -> {
                                for (UUID certificate : scope.certificates()) {
                                    certificates
                                            .getStoredCertificateHealth(SecuredParentUUID.fromUUID(scope.raProfileId()),
                                                    SecuredUUID.fromUUID(certificate));
                                }
                                return null;
                            });
        } catch (Exception failure) {
            throw denied();
        }
    }

    /** Passive caller-thread probe; it cannot supply or cache an authorization result. */
    public void beforeInvocation(Runnable observation) {
        beforeInvocation = java.util.Objects.requireNonNull(observation);
    }

    private static AccessDeniedException denied() {
        return new AccessDeniedException("Conversation unavailable");
    }
}
