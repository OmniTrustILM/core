package com.otilm.core.service;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.authority.AuthorityInstanceRequestDto;
import com.otilm.api.model.client.authority.AuthorityInstanceUpdateRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndIdDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.authority.AuthorityInstanceDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;

import java.util.List;

public interface AuthorityInstanceService extends ResourceExtensionService {
    List<AuthorityInstanceDto> listAuthorityInstances(SecurityFilter filter);

    AuthorityInstanceDto getAuthorityInstance(SecuredUUID uuid) throws ConnectorException, NotFoundException;

    AuthorityInstanceDto createAuthorityInstance(AuthorityInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    AuthorityInstanceDto editAuthorityInstance(SecuredUUID uuid, AuthorityInstanceUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException;

    void deleteAuthorityInstance(SecuredUUID uuid) throws ConnectorException, NotFoundException;

    List<NameAndIdDto> listEndEntityProfiles(SecuredUUID uuid) throws ConnectorException, NotFoundException;

    List<NameAndIdDto> listCertificateProfiles(SecuredUUID uuid, Integer endEntityProfileId) throws ConnectorException, NotFoundException;

    List<NameAndIdDto> listCAsInProfile(SecuredUUID uuid, Integer endEntityProfileId) throws ConnectorException, NotFoundException;

    List<BaseAttribute> listRAProfileAttributes(SecuredUUID uuid) throws ConnectorException, NotFoundException;

    Boolean validateRAProfileAttributes(SecuredUUID uuid, List<RequestAttribute> attributes) throws ConnectorException, NotFoundException;

    List<BulkActionMessageDto> bulkDeleteAuthorityInstance(List<SecuredUUID> uuids) throws ValidationException, ConnectorException;

    List<BulkActionMessageDto> forceDeleteAuthorityInstance(List<SecuredUUID> uuids) throws ValidationException, NotFoundException;
}
