package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.model.SecuredList;

import java.util.List;

public interface RaProfileInternalService extends ResourceExtensionService {

    SecuredList<RaProfile> listRaProfilesAssociatedWithAcmeProfile(String acmeProfileUuid, SecurityFilter filter);

    RaProfile getRaProfileEntity(SecuredUUID uuid) throws NotFoundException;

    void bulkRemoveAssociatedAcmeProfile(List<SecuredUUID> uuids);

    void bulkRemoveAssociatedScepProfile(List<SecuredUUID> uuids);

    /**
     * Function to list the RA Profiles associated with the CMP Profiles
     * @param cmpProfileUuid UUID of the CMP Profile
     * @param filter Security filter
     * @return List of RA Profiles associated with the CMP Profiles
     */
    SecuredList<RaProfile> listRaProfilesAssociatedWithCmpProfile(String cmpProfileUuid, SecurityFilter filter);

    /**
     * Remove CMP Profiles from the RA Profiles
     *
     * @param uuids List of RA Profile UUIDs
     */
    void bulkRemoveAssociatedCmpProfile(List<SecuredUUID> uuids);

    /**
     * Save the RA Profile entity to the database
     *
     * @param raProfile RA profile entity
     * @return RA Profile Entity
     */
    RaProfile updateRaProfileEntity(RaProfile raProfile);

    /**
     * Get the number of ra profiles per user for dashboard
     *
     * @return Number of raprofiles
     */
    Long statisticsRaProfilesCount(SecurityFilter filter);

    /**
     * Function to check if an user has RA profile Access for member certificates
     *
     * @param certificateUuid UUID of the certificate
     * @param raProfileUuid UUID of the RA Profile
     */
    void evaluateCertificateRaProfilePermissions(SecuredUUID certificateUuid, SecuredParentUUID raProfileUuid);

    /**
     * Function to list the RA Profiles associated with the SCEP Profiles
     * @param scepProfileUuid UUID of the SCEP Profile
     * @param filter Security filter
     * @return List of RA Profiles associated with the SCEP Profiles
     */
    SecuredList<RaProfile> listRaProfilesAssociatedWithScepProfile(String scepProfileUuid, SecurityFilter filter);
}
