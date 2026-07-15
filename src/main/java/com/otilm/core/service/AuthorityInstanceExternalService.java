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
import java.util.UUID;

public interface AuthorityInstanceExternalService {
    List<AuthorityInstanceDto> listAuthorityInstances(SecurityFilter filter);

    AuthorityInstanceDto getAuthorityInstance(SecuredUUID uuid) throws ConnectorException, NotFoundException;

    AuthorityInstanceDto createAuthorityInstance(AuthorityInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException;

    AuthorityInstanceDto editAuthorityInstance(SecuredUUID uuid, AuthorityInstanceUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException;

    void deleteAuthorityInstance(SecuredUUID uuid) throws ConnectorException, NotFoundException;

    List<NameAndIdDto> listEndEntityProfiles(SecuredUUID uuid) throws ConnectorException, NotFoundException;

    List<NameAndIdDto> listCertificateProfiles(SecuredUUID uuid, Integer endEntityProfileId) throws ConnectorException, NotFoundException;

    List<NameAndIdDto> listCAsInProfile(SecuredUUID uuid, Integer endEntityProfileId) throws ConnectorException, NotFoundException;

    /**
     * Lists the authority attribute schema for a stateless v3 authority connector (used by the
     * create-authority form), keyed by connector UUID. v3-only: throws ValidationException when the
     * connector has no AUTHORITY interface or a non-v3 one. {@code interfaceUuid} is optional and only
     * disambiguates a connector that exposes more than one AUTHORITY interface. Side effect: persists
     * the returned definitions via the attribute engine for later validation and content preparation.
     */
    List<BaseAttribute> listAuthorityInstanceAttributes(SecuredUUID connectorUuid, UUID interfaceUuid) throws ConnectorException, AttributeException, NotFoundException;

    List<BaseAttribute> listRAProfileAttributes(SecuredUUID uuid) throws ConnectorException, NotFoundException, AttributeException;

    Boolean validateRAProfileAttributes(SecuredUUID uuid, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException;

    List<BulkActionMessageDto> bulkDeleteAuthorityInstance(List<SecuredUUID> uuids) throws ValidationException, ConnectorException;

    List<BulkActionMessageDto> forceDeleteAuthorityInstance(List<SecuredUUID> uuids) throws ValidationException, NotFoundException;
}
