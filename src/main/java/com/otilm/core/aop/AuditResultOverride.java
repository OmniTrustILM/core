package com.otilm.core.aop;

import com.otilm.api.model.core.logging.enums.OperationResult;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

/**
 * Allows protocol controllers that must swallow exceptions (e.g. TSP, which always returns HTTP 200)
 * to signal audit failure without throwing past the {@link AuditLogAspect}.
 *
 * <p>Request-scoped: Spring creates one instance per HTTP request and discards it when the request
 * ends, so the value set by the controller is read by the aspect within the same request and never
 * leaks across requests. A {@link ScopedProxyMode#TARGET_CLASS} proxy lets the singleton controller
 * and aspect hold a reference that resolves to the current request's instance on each call.</p>
 */
@Component
@Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class AuditResultOverride {

    private OperationResult result;

    public void setFailure() {
        this.result = OperationResult.FAILURE;
    }

    /**
     * Reads the override and resets it, so the signal set during one audited method's body is
     * consumed by that method's aspect frame and cannot contaminate a subsequent audited method
     * running within the same request.
     */
    OperationResult consume() {
        OperationResult current = result;
        result = null;
        return current;
    }
}
