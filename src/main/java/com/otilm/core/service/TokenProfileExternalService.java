package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.cryptography.tokenprofile.AddTokenProfileRequestDto;
import com.otilm.api.model.client.cryptography.tokenprofile.EditTokenProfileRequestDto;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;
import java.util.Optional;

public interface TokenProfileExternalService {
    /**
     * Get the list of token profiles
     *
     * @param enabled - Boolean state if the profile is enabled or not
     * @param filter Security Filter for Access Control
     * @return List of Token Profiles {@Link TokenProfileDto}
     */
    List<TokenProfileDto> listTokenProfiles(Optional<Boolean> enabled, SecurityFilter filter);

    /**
     * Get the details of a token profile which has Token Instance association
     *
     * @param tokenInstanceUuid - UUID of the Token Instance
     * @param uuid              - UUID of the Token Profile
     * @return Details of the token Profile {@Link TokenProfileDetailDto}
     * @throws NotFoundException When the token instance or token profile is not found
     */
    TokenProfileDetailDto getTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException;

    /**
     * Create a new token profile
     *
     * @param tokenInstanceUuid UUID of the token instance on which the token profile has to be created
     * @param request           Request DTO containing the parameters for creating the new token profile. {@Link AddTokenProfileRequestDto}
     * @return Details of the newly created token profile
     * @throws AlreadyExistException when the token profile with same data already exists
     * @throws ValidationException   when there are issues with the attribute validation
     * @throws ConnectorException    when there are issues related with connector communication
     */
    TokenProfileDetailDto createTokenProfile(SecuredParentUUID tokenInstanceUuid, AddTokenProfileRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException;

    /**
     * Update the token profile
     *
     * @param tokenInstanceUuid UUID of the token instance where the token profile is created
     * @param uuid              UUID of the concerned token profile
     * @param request           Request containing the update details. {@Link EditTokenProfileRequestDto}
     * @return Details of the updated token profile
     * @throws ConnectorException when there are issues with the connector communication
     */
    TokenProfileDetailDto editTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid, EditTokenProfileRequestDto request) throws ConnectorException, AttributeException, NotFoundException;

    /**
     * Delete a token profile
     *
     * @param tokenInstanceUuid UUID of the token instance where the token profile is created
     * @param uuid              UUID of the concerned token profile
     * @throws NotFoundException when the token profile is not found
     */
    void deleteTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException;

    /**
     * @param tokenProfileUuid UUID of the concerned token profile. Use this method when the profile is not associated with any instance
     * @throws NotFoundException when the token profile is not found
     */
    void deleteTokenProfile(SecuredUUID tokenProfileUuid) throws NotFoundException;

    /**
     * @param tokenInstanceUuid UUID of the token instance where the token profile is created
     * @param uuid              UUID of the concerned token profile
     * @throws NotFoundException when the token profile is not found
     */
    void disableTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException;

    /**
     * @param tokenInstanceUuid UUID of the token instance where the token profile is created
     * @param uuid              UUID of the concerned token profile
     * @throws NotFoundException when the token profile is not found
     */
    void enableTokenProfile(SecuredParentUUID tokenInstanceUuid, SecuredUUID uuid) throws NotFoundException;

    /**
     * @param uuids UUIDs of the token profile
     */
    void deleteTokenProfile(List<SecuredUUID> uuids);

    /**
     * @param uuids UUIDs of the token profile
     */
    void disableTokenProfile(List<SecuredUUID> uuids);

    /**
     * @param uuids UUIDs of the token profile
     */
    void enableTokenProfile(List<SecuredUUID> uuids);

    /**
     * Function to update the usages for the key
     * @param uuids UUIDs of the token profiles for the key updates
     * @param usages Usages of the keys in the token profile
     */
    void updateKeyUsages(List<SecuredUUID> uuids, List<KeyUsage> usages);

    /**
     * Update the key usages for multiple keys and its items
     * @param tokenInstanceUuid UUID of the token instance
     * @param tokenProfileUuid Token Profile UUID
     * @param usages Usages of the key
     */
    void updateKeyUsages(SecuredParentUUID tokenInstanceUuid, SecuredUUID tokenProfileUuid, List<KeyUsage> usages) throws NotFoundException;

}
