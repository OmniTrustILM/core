package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.ai.AiReadInvocationContext;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Setter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

@Data
public class SecurityFilter {
    private SecurityResourceFilter resourceFilter;

    private SecurityResourceFilter parentResourceFilter;

    private SecurityResourceFilter groupMembersFilter;

    private String parentRefProperty;

    @Setter(AccessLevel.NONE)
    private UUID completedInvocationUuid;

    void clearInvocationFilters() {
        completedInvocationUuid = null;
        resourceFilter = null;
        parentResourceFilter = null;
        groupMembersFilter = null;
        parentRefProperty = null;
    }

    void completeInvocation(AiReadInvocationContext context) {
        context.requirePinnedActor(SecurityContextHolder.getContext().getAuthentication());
        completedInvocationUuid = context.invocationUuid();
    }

    /** Completion belongs to one internal invocation and never replaces the SQL access predicates. */
    public AiReadInvocationContext requireCurrentCertificateRead() {
        var context = AiReadInvocationContext.current().orElseThrow(SecurityFilter::incomplete);
        context.requirePinnedActor(SecurityContextHolder.getContext().getAuthentication());
        if (!context.invocationUuid().equals(completedInvocationUuid) || resourceFilter == null
                || resourceFilter.getResource() != Resource.CERTIFICATE
                || resourceFilter.getResourceAction() != ResourceAction.LIST || parentResourceFilter == null
                || parentResourceFilter.getResource() != Resource.RA_PROFILE
                || parentResourceFilter.getResourceAction() != ResourceAction.MEMBERS
                || !"raProfileUuid".equals(parentRefProperty)) {
            throw incomplete();
        }
        return context;
    }

    private static AccessDeniedException incomplete() {
        return new AccessDeniedException("Certificate read filter is incomplete");
    }

    public static SecurityFilter create() {
        return new SecurityFilter();
    }

}
