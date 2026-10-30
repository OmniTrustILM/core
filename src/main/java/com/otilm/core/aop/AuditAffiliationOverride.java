package com.otilm.core.aop;

import com.otilm.api.model.core.auth.Resource;
import java.util.UUID;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

/**
 * Hands the audit record an affiliated resource that the audited method discovers only inside its body — the
 * {@link AuditLogAspect} otherwise derives affiliation solely from annotated parameters. Request-scoped with a
 * {@link ScopedProxyMode#TARGET_CLASS} proxy, mirroring {@link AuditOperationDataOverride}.
 */
@Component
@Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class AuditAffiliationOverride {

    private Resource resource;
    private UUID objectUuid;

    public void set(Resource resource, UUID objectUuid) {
        this.resource = resource;
        this.objectUuid = objectUuid;
    }

    /**
     * Reads the override and resets it, so affiliation set during one audited method's body cannot contaminate a
     * subsequent audited method running within the same request.
     */
    Affiliation consume() {
        if (resource == null) {
            return null;
        }
        Affiliation current = new Affiliation(resource, objectUuid);
        resource = null;
        objectUuid = null;
        return current;
    }

    record Affiliation(Resource resource, UUID objectUuid) {
    }
}
