package com.czertainly.core.service;

import com.otilm.api.exception.NotFoundException;
import com.czertainly.core.security.authz.SecuredUUID;

import java.util.List;

public interface PermissionEvaluator {
    /**
     * Function to evaluate the permission for the Token Profiles
     * @param uuid UUID of the token Profile
     * @throws NotFoundException when the Token profile with the requested UUID is not found
     */
    void tokenProfile(SecuredUUID uuid) throws NotFoundException;

    /**
     * Function to evaluate the permission for the Token Instance
     * @param uuid UUID of the token instance
     * @throws NotFoundException when the Token profile with the requested UUID is not found
     */
    void tokenInstance(SecuredUUID uuid) throws NotFoundException;

    /**
     * Function to evaluate the permission for the Token Instance Members Action
     * @param uuid UUID of the token instance
     * @throws NotFoundException when the Token profile with the requested UUID is not found
     */
    void tokenInstanceMembers(SecuredUUID uuid) throws NotFoundException;

    /**
     * Function to evaluate the permission for the Certificate
     * @param uuid UUID of the token instance
     * @throws NotFoundException when the certificate with the requested UUID is not found
     */
    void certificate(SecuredUUID uuid) throws NotFoundException;

    /**
     * Function to evaluate the permission for the Authority Instance
     * @param uuid UUID of the authority instance
     * @throws NotFoundException when the Token profile with the requested UUID is not found
     */
    void authorityInstance(SecuredUUID uuid) throws NotFoundException;

    /**
     * Function to evaluate the permission for list of token profiles
     * @param uuids UUIDs of the token profile
     */
    void tokenProfiles(List<SecuredUUID> uuids);

    void vaultProfileMembers(SecuredUUID securedUUID);

    void acmeProfile(SecuredUUID uuid) throws NotFoundException;

    void vaultInstance(SecuredUUID uuid);
}
