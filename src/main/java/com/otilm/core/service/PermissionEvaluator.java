package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.security.authz.SecuredUUID;

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
     * Function to evaluate ENTITY:DETAIL permission for an Entity Instance.
     * @param uuid UUID of the entity instance
     * @throws NotFoundException when the entity instance with the requested UUID is not found
     */
    void entityInstance(SecuredUUID uuid) throws NotFoundException;

    /**
     * Function to evaluate the permission for list of token profiles
     * @param uuids UUIDs of the token profile
     */
    void tokenProfiles(List<SecuredUUID> uuids);

    void vaultProfileMembers(SecuredUUID securedUUID);

    void acmeProfile(SecuredUUID uuid) throws NotFoundException;

    /**
     * Function to evaluate the permission for the Signing Profile connected to a signing record
     *
     * @param uuid UUID of the signing profile
     * @throws NotFoundException when the signing profile with the requested UUID is not found
     */
    void signingProfile(SecuredUUID uuid) throws NotFoundException;

    /**
     * Function to evaluate access to a set of signing profiles in a single authorization check.
     * The whole set is authorized together: if access to any profile is denied, the check fails.
     *
     * @param uuids UUIDs of the signing profiles
     */
    void signingProfiles(List<SecuredUUID> uuids);

    void vaultInstance(SecuredUUID uuid);

    /**
     * Function to evaluate the TIMESTAMP permission on a TSP profile. Used by the timestamping flow to authorize the
     * action on its own, separately from request processing, so a denial can be caught precisely without masking an
     * authorization failure raised deeper in the processing path.
     *
     * @param uuid UUID of the TSP profile
     * @throws NotFoundException when the TSP profile with the requested UUID is not found
     */
    void tspProfileTimestamping(SecuredUUID uuid) throws NotFoundException;
}
