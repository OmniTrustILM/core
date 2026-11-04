package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.ObjectActionsAware;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.util.AuthHelper;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Component;

/**
 * Reports the actions the current principal may perform on one object, so a detail response can tell a client which
 * controls to offer.
 *
 * <p>
 * Each grantable action the resource declares is decided by {@link AuthorizationEnforcer#isAuthorized}, the same check
 * that guards the request, so ownership, group membership and object grants are honoured without restating the policy.
 * That costs one OPA request per declared action; a principal granted every resource skips them.
 */
@Component
public class ObjectActionResolver {

    private final AuthorizationEnforcer authorizationEnforcer;
    private final ContextRefreshListener contextRefreshListener;

    public ObjectActionResolver(AuthorizationEnforcer authorizationEnforcer,
            ContextRefreshListener contextRefreshListener) {
        this.authorizationEnforcer = authorizationEnforcer;
        this.contextRefreshListener = contextRefreshListener;
    }

    public <T extends ObjectActionsAware> T withAllowedActions(Resource resource, String objectUuid, T model) {
        return withAllowedActions(resource, UUID.fromString(objectUuid), model);
    }

    public <T extends ObjectActionsAware> T withAllowedActions(Resource resource, UUID objectUuid, T model) {
        model.setAllowedActions(allowedActions(resource, SecuredUUID.fromUUID(objectUuid)));
        return model;
    }

    List<ResourceAction> allowedActions(Resource resource, SecuredUUID objectUuid) {
        List<ResourceAction> declared = declaredActions(resource);
        if (Boolean.TRUE.equals(AuthHelper.getUserProfile().getPermissions().getAllowAllResources())) {
            return declared;
        }
        return declared
                .stream()
                .filter(action -> authorizationEnforcer.isAuthorized(resource, action, objectUuid))
                .toList();
    }

    private List<ResourceAction> declaredActions(Resource resource) {
        return contextRefreshListener
                .getResources()
                .stream()
                .filter(syncResource -> syncResource.getName().getCode().equals(resource.getCode()))
                .flatMap(syncResource -> syncResource.getActions().stream())
                .distinct()
                .map(ResourceAction::findByCode)
                .filter(action -> action.getAccessType() != ResourceAction.AccessType.NOT_GRANTABLE)
                .sorted(Comparator.comparing(ResourceAction::getCode))
                .toList();
    }
}
