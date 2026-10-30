package com.otilm.core.aop;

import java.io.Serializable;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

/**
 * Lets an audited method whose response carries no payload (a 204 delete, a resolve) hand the audit record its
 * operation data — the {@link AuditLogAspect} otherwise captures data only from {@code Loggable} responses, so the
 * content of a destructive operation would be lost to the audit trail.
 *
 * <p>
 * Request-scoped with a {@link ScopedProxyMode#TARGET_CLASS} proxy, mirroring {@link AuditResultOverride}: the value
 * set during one request is consumed by the same request's aspect frame and never leaks across requests.
 * </p>
 */
@Component
@Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class AuditOperationDataOverride {

    private Serializable data;

    public void set(Serializable data) {
        this.data = data;
    }

    /**
     * Reads the override and resets it, so data set during one audited method's body cannot contaminate a subsequent
     * audited method running within the same request.
     */
    Serializable consume() {
        Serializable current = data;
        data = null;
        return current;
    }
}
