package com.otilm.core.auth;

import com.otilm.api.model.core.auth.RoleDto;
import com.otilm.api.model.core.auth.RolePermissionsRequestDto;
import com.otilm.api.model.core.auth.RoleRequestDto;
import com.otilm.api.model.core.auth.RoleWithPaginationDto;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.model.auth.SyncResponseDto;
import com.otilm.core.security.authn.client.ResourceApiClient;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.util.AuthHelper;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class AuthResourceSynchronizer {

    private static final Logger logger = LoggerFactory.getLogger(AuthResourceSynchronizer.class);
    private ContextRefreshListener contextRefreshListener;
    private ResourceApiClient resourceApiClient;
    private RoleManagementApiClient roleManagementApiClient;

    @Autowired
    public void setEndpointsListener(ContextRefreshListener contextRefreshListener) {
        this.contextRefreshListener = contextRefreshListener;
    }

    @Autowired
    public void setEndPointApiClient(ResourceApiClient resourceApiClient) {
        this.resourceApiClient = resourceApiClient;
    }

    @Autowired
    public void setRoleManagementApiClient(RoleManagementApiClient roleManagementApiClient) {
        this.roleManagementApiClient = roleManagementApiClient;
    }

    @EventListener({ApplicationReadyEvent.class})
    public void register() {
        logger.info("Initiating Endpoints sync");
        List<ResourceSyncRequestDto> resources = contextRefreshListener.getResources();
        logger.debug("Resources: {}", resources);
        // Sync API Operation here
        try {
            SyncResponseDto response = resourceApiClient.syncResources(resources);
            logger.info("Sync operation completed, Response is {}", response);
            reconcileAuditorRole(resources);
        } catch (Exception e) {
            // Not only connection errors: a reachable auth service that rejects the sync fails with something else
            // entirely, and no response from it is worth refusing to start over.
            logger.error("Unable to synchronize resources with Auth Service: {}", e.getMessage(), e);
        }
    }

    /**
     * Brings the auditor role in line with the catalogue this boot just synced, creating it when it is missing. Runs
     * only after {@code syncResources} succeeded, since the auth service rejects a permission naming a resource or
     * action it does not yet know. Best effort: a role the platform can start without must never stop it starting.
     * <p>
     * Creating it here rather than from a migration is deliberate. The role carries no system user - unlike the
     * acme/scep/cmp/localhost identities, it is meant to be assigned to people - and a system user is the only thing a
     * migration is actually needed for. A migration that calls the auth service also aborts the whole migration chain
     * when that service is unreachable, leaving the schema half-built.
     */
    private void reconcileAuditorRole(List<ResourceSyncRequestDto> resources) {
        try {
            RolePermissionsRequestDto derived = ReadOnlyRolePermissions.deriveFrom(resources);
            RoleDto existing = findRoleNamedAuditor();

            if (existing == null) {
                createAuditorRole(derived);
            } else if (Boolean.TRUE.equals(existing.getSystemRole())) {
                rebuildPermissionsIfOutOfStep(existing.getUuid(), derived);
            } else {
                // A role of that name the deployment defined itself is not this one, and rewriting it would strip or
                // widen grants someone there relies on. Leaving it alone costs that deployment the built-in role.
                logger
                        .warn("Role '{}' exists but is not a system role, so it was left untouched and the read-only"
                                + " system role was not created; rename it to have the platform manage '{}'",
                                AuthHelper.AUDITOR_ROLE_NAME, AuthHelper.AUDITOR_ROLE_NAME);
            }
        } catch (Exception e) {
            logger.error("Unable to reconcile system role '{}': {}", AuthHelper.AUDITOR_ROLE_NAME, e.getMessage(), e);
        }
    }

    /** Created holding exactly the derived set, so a deployment that never had the role ends this startup with it. */
    private void createAuditorRole(RolePermissionsRequestDto derived) {
        RoleRequestDto request = new RoleRequestDto();
        request.setName(AuthHelper.AUDITOR_ROLE_NAME);
        request
                .setDescription("System role granting every read action on every resource and nothing that changes"
                        + " anything; kept in step with the resource catalogue on every startup");
        request.setSystemRole(true);
        request.setPermissions(derived);

        try {
            roleManagementApiClient.createRole(request);
            logger
                    .info("System role '{}' created from the resource catalogue: {} resources, {} actions",
                            AuthHelper.AUDITOR_ROLE_NAME, derived.getResources().size(),
                            ReadOnlyRolePermissions.countActions(derived));
        } catch (Exception e) {
            String raced = uuidOfRoleCreatedConcurrently();
            if (raced == null) {
                throw e;
            }
            logger
                    .info("System role '{}' was created by another instance during this startup, reconciling that one",
                            AuthHelper.AUDITOR_ROLE_NAME);
            rebuildPermissionsIfOutOfStep(raced, derived);
        }
    }

    /**
     * Replicas start together, so several find the role missing and all of them try to create it. Role names are unique
     * in the auth service, so every loser is refused - and the role it wanted now exists.
     *
     * @return the role to reconcile instead, or {@code null} when the creation failed for some other reason
     */
    private String uuidOfRoleCreatedConcurrently() {
        RoleDto raced = findRoleNamedAuditor();
        return raced != null && Boolean.TRUE.equals(raced.getSystemRole()) ? raced.getUuid() : null;
    }

    private void rebuildPermissionsIfOutOfStep(String roleUuid, RolePermissionsRequestDto derived) {
        if (ReadOnlyRolePermissions.matches(derived, roleManagementApiClient.getPermissions(roleUuid))) {
            logger
                    .debug("System role '{}' already holds the permissions derived from the resource catalogue",
                            AuthHelper.AUDITOR_ROLE_NAME);
            return;
        }

        roleManagementApiClient.savePermissions(roleUuid, derived);
        logger
                .info("System role '{}' permissions rebuilt from the resource catalogue: {} resources, {} actions",
                        AuthHelper.AUDITOR_ROLE_NAME, derived.getResources().size(),
                        ReadOnlyRolePermissions.countActions(derived));
    }

    /**
     * Matched by name across every role rather than among the system ones, so a name already taken by a role the
     * platform did not create is told apart from the role being absent - which would create a duplicate of it.
     * <p>
     * Assumes the auth service returns every role in one response. It does today: the endpoint ignores paging
     * parameters and asks for a page of 1000. Beyond that the role would look absent on every boot and each one would
     * attempt a creation the auth service refuses.
     */
    private RoleDto findRoleNamedAuditor() {
        RoleWithPaginationDto roles = roleManagementApiClient.getRoles();
        if (roles == null || roles.getData() == null) {
            return null;
        }
        return roles
                .getData()
                .stream()
                .filter(role -> AuthHelper.AUDITOR_ROLE_NAME.equals(role.getName()))
                .findFirst()
                .orElse(null);
    }
}
