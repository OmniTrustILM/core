package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.est.EstProfileEditRequestDto;
import com.otilm.api.model.client.est.EstProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.core.est.EstProfileDetailDto;
import com.otilm.api.model.core.est.EstProfileDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import java.util.List;
import java.util.UUID;

public interface EstProfileExternalService {

    List<EstProfileDto> listEstProfiles(SecurityFilter filter, String origin);

    EstProfileDetailDto getEstProfile(SecuredUUID uuid, String origin) throws NotFoundException;

    EstProfileDetailDto createEstProfile(EstProfileRequestDto request, String origin)
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    EstProfileDetailDto updateEstProfile(SecuredUUID uuid, EstProfileEditRequestDto request, String origin)
            throws ConnectorException, AttributeException, NotFoundException;

    void deleteEstProfile(SecuredUUID uuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkDeleteEstProfiles(List<SecuredUUID> uuids);

    /** Deactivates EST on the RA Profiles that have the profiles activated, then deletes the profiles. */
    List<BulkActionMessageDto> forceDeleteEstProfiles(List<SecuredUUID> uuids);

    void enableEstProfile(SecuredUUID uuid) throws NotFoundException;

    void disableEstProfile(SecuredUUID uuid) throws NotFoundException;

    void bulkEnableEstProfiles(List<SecuredUUID> uuids);

    void bulkDisableEstProfiles(List<SecuredUUID> uuids);

    /**
     * Sets the RA Profile that serves the profile's own label. The RA Profile's UUID is not a {@link SecuredUUID}: the
     * authorization of this method would take it for one of the EST Profiles it is checked on.
     */
    void updateRaProfile(SecuredUUID uuid, UUID raProfileUuid) throws NotFoundException;
}
