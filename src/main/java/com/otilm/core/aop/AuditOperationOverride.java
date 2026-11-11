package com.otilm.core.aop;

import com.otilm.api.model.core.logging.enums.Operation;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

/**
 * Lets an audited method annotated with {@link Operation#UNKNOWN} hand the audit record the operation it discovers
 * inside its body, such as a protocol endpoint that learns the operation from the message it parses.
 *
 * <p>
 * Request-scoped like {@link AuditResultOverride}: the value set during the method is read by the aspect within the
 * same request and never leaks across requests.
 * </p>
 */
@Component
@Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class AuditOperationOverride {

    private Operation operation;

    public void set(Operation operation) {
        this.operation = operation;
    }

    /**
     * Reads the override and resets it, so the operation set during one audited method's body is consumed by that
     * method's aspect frame and cannot contaminate a subsequent audited method running within the same request.
     */
    Operation consume() {
        Operation current = operation;
        operation = null;
        return current;
    }
}
