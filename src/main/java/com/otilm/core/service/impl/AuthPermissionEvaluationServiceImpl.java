package com.otilm.core.service.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.PermissionEvaluator;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthPermissionEvaluationServiceImpl implements PermissionEvaluator {

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.DETAIL)
    public void tokenProfile(SecuredUUID uuid) throws NotFoundException {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DETAIL)
    public void tokenInstance(SecuredUUID uuid) throws NotFoundException {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.MEMBERS)
    public void tokenInstanceMembers(SecuredUUID uuid) {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public void certificate(SecuredUUID uuid) throws NotFoundException {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DETAIL)
    public void authorityInstance(SecuredUUID uuid) throws NotFoundException {
        // Method empty on only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN_PROFILE, action = ResourceAction.LIST)
    public void tokenProfiles(List<SecuredUUID> uuids) {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT_PROFILE, action = ResourceAction.MEMBERS)
    public void vaultProfileMembers(SecuredUUID securedUUID) {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.ACME_PROFILE, action = ResourceAction.DETAIL)
    public void acmeProfile(SecuredUUID uuid) throws NotFoundException {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.DETAIL)
    public void signingProfile(SecuredUUID uuid) throws NotFoundException {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.SIGNING_PROFILE, action = ResourceAction.DETAIL)
    public void signingProfiles(List<SecuredUUID> uuids) {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.VAULT, action = ResourceAction.DETAIL)
    public void vaultInstance(SecuredUUID uuid) {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

    @Override
    @ExternalAuthorization(resource = Resource.TSP_PROFILE, action = ResourceAction.TIMESTAMP)
    public void tspProfileTimestamping(SecuredUUID uuid) {
        // Method empty to only evaluate permissions based on ExternalAuthorization annotation
    }

}
