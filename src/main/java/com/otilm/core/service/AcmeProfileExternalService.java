package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.acme.AcmeProfileEditRequestDto;
import com.otilm.api.model.client.acme.AcmeProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.core.acme.AcmeEabKeyDto;
import com.otilm.api.model.core.acme.AcmeProfileDto;
import com.otilm.api.model.core.acme.AcmeProfileListDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import java.util.List;

public interface AcmeProfileExternalService {

    List<AcmeProfileListDto> listAcmeProfile(SecurityFilter filter);

    AcmeProfileDto getAcmeProfile(SecuredUUID uuid) throws NotFoundException;

    AcmeProfileDto createAcmeProfile(AcmeProfileRequestDto request) throws AlreadyExistException, ValidationException,
            ConnectorException, AttributeException, NotFoundException;

    AcmeProfileDto editAcmeProfile(SecuredUUID uuid, AcmeProfileEditRequestDto request)
            throws ConnectorException, AttributeException, NotFoundException;

    void deleteAcmeProfile(SecuredUUID uuid) throws NotFoundException, ValidationException;

    void enableAcmeProfile(SecuredUUID uuid) throws NotFoundException;

    void disableAcmeProfile(SecuredUUID uuid) throws NotFoundException;

    void bulkEnableAcmeProfile(List<SecuredUUID> uuids);

    void bulkDisableAcmeProfile(List<SecuredUUID> uuids);

    List<BulkActionMessageDto> bulkDeleteAcmeProfile(List<SecuredUUID> uuids);

    void updateRaProfile(SecuredUUID uuid, String raProfileUuid) throws NotFoundException;

    List<BulkActionMessageDto> bulkForceRemoveACMEProfiles(List<SecuredUUID> uuids) throws ValidationException;

    /**
     * Generates an External Account Binding key and returns it once, without storing or associating it. The operator
     * puts it to use by creating a secret from it and registering that secret on an ACME profile.
     */
    AcmeEabKeyDto generateEabKey();
}
