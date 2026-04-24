package com.czertainly.core.service.impl;

import com.czertainly.api.interfaces.client.v1.EndEntityProfileSyncApiClient;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.authority.AuthorityInstanceUpdateRequestDto;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndIdDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;

import com.czertainly.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.czertainly.api.model.connector.authority.AuthorityProviderInstanceDto;
import com.czertainly.api.model.connector.authority.AuthorityProviderInstanceRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.authority.AuthorityInstanceDto;
import com.czertainly.api.model.core.connector.ConnectorApiClientDto;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.connector.FunctionGroupDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.*;
import com.czertainly.core.util.AttributeDefinitionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service(Resource.Codes.AUTHORITY)
@Transactional
public class AuthorityInstanceServiceImpl implements AuthorityInstanceService, AttributeResourceService {
    private static final Logger logger = LoggerFactory.getLogger(AuthorityInstanceServiceImpl.class);

    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    private ConnectorService connectorService;
    private CredentialService credentialService;
    private ConnectorApiFactory connectorApiFactory;
    private RaProfileService raProfileService;
    private AttributeEngine attributeEngine;
    private ResourceService resourceService;

    @Autowired
    public void setResourceService(ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setAuthorityInstanceReferenceRepository(AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository) {
        this.authorityInstanceReferenceRepository = authorityInstanceReferenceRepository;
    }

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setCredentialService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setRaProfileService(RaProfileService raProfileService) {
        this.raProfileService = raProfileService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.LIST)
    public List<AuthorityInstanceDto> listAuthorityInstances(SecurityFilter filter) {
        return authorityInstanceReferenceRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(AuthorityInstanceReference::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DETAIL)
    public AuthorityInstanceDto getAuthorityInstance(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        AuthorityInstanceReference authorityInstanceReference = getAuthorityInstanceReferenceEntity(uuid);

        List<ResponseAttribute> attributes = attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.AUTHORITY, authorityInstanceReference.getUuid()).connector(authorityInstanceReference.getConnectorUuid()).build());

        AuthorityInstanceDto authorityInstanceDto = authorityInstanceReference.mapToDto();
        authorityInstanceDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.AUTHORITY, uuid.getValue()));
        if (authorityInstanceReference.getConnector() == null) {
            authorityInstanceDto.setConnectorName(authorityInstanceReference.getConnectorName() + " (Deleted)");
            authorityInstanceDto.setConnectorUuid("");
            authorityInstanceDto.setAttributes(attributes);
            logger.warn("Connector associated with the Authority: {} is not found. Unable to show details", authorityInstanceReference.getName());

            return authorityInstanceDto;
        }

        ConnectorApiClientDto connectorDto = authorityInstanceReference.getConnector().mapToApiClientDtoV1();
        AuthorityProviderInstanceDto authorityProviderInstanceDto = connectorApiFactory.getAuthorityInstanceApiClient(connectorDto).getAuthorityInstance(connectorDto,
                authorityInstanceReference.getAuthorityInstanceUuid());

        if (attributes.isEmpty() && authorityProviderInstanceDto.getAttributes() != null && !authorityProviderInstanceDto.getAttributes().isEmpty()) {
            try {
                List<RequestAttribute> requestAttributes = AttributeDefinitionUtils.getClientAttributes(authorityProviderInstanceDto.getAttributes());
                attributeEngine.updateDataAttributeDefinitions(authorityInstanceReference.getConnectorUuid(), null, authorityProviderInstanceDto.getAttributes());
                attributes = attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.AUTHORITY, authorityInstanceReference.getUuid()).connector(authorityInstanceReference.getConnectorUuid()).build(), requestAttributes);
            } catch (AttributeException e) {
                logger.warn("Could not update data attributes for authority {} retrieved from connector", authorityInstanceReference.getName());
            }
        }

        authorityInstanceDto.setAttributes(attributes);
        return authorityInstanceDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.CREATE)
    public AuthorityInstanceDto createAuthorityInstance(com.czertainly.api.model.client.authority.AuthorityInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        if (authorityInstanceReferenceRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(AuthorityInstanceReference.class, request.getName());
        }

        SecuredUUID connectorUuid = SecuredUUID.fromString(request.getConnectorUuid());
        ConnectorDto connector = connectorService.getConnector(connectorUuid);
        FunctionGroupCode codeToSearch = FunctionGroupCode.AUTHORITY_PROVIDER;
        for (FunctionGroupDto function : connector.getFunctionGroups()) {
            if (function.getFunctionGroupCode() == FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER) {
                codeToSearch = FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER;
                break;
            }
        }
        attributeEngine.validateCustomAttributesContent(Resource.AUTHORITY, request.getCustomAttributes());
        connectorService.mergeAndValidateAttributes(connectorUuid, codeToSearch, request.getAttributes(), request.getKind());

        // Load complete credential data and resource data
        var dataAttributes = attributeEngine.getDataAttributesByContent(connectorUuid.getValue(), request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);

        AuthorityProviderInstanceRequestDto authorityInstanceDto = new AuthorityProviderInstanceRequestDto();
        authorityInstanceDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
        authorityInstanceDto.setKind(request.getKind());
        authorityInstanceDto.setName(request.getName());

        AuthorityProviderInstanceDto response = connectorApiFactory.getAuthorityInstanceApiClient(connector).createAuthorityInstance(connector, authorityInstanceDto);

        AuthorityInstanceReference authorityInstanceRef = new AuthorityInstanceReference();
        authorityInstanceRef.setAuthorityInstanceUuid(response.getUuid());
        authorityInstanceRef.setName(request.getName());
        authorityInstanceRef.setStatus("connected");
        authorityInstanceRef.setConnectorUuid(connectorUuid.getValue());
        authorityInstanceRef.setKind(request.getKind());
        authorityInstanceRef.setConnectorName(connector.getName());
        authorityInstanceReferenceRepository.save(authorityInstanceRef);

        AuthorityInstanceDto dto = authorityInstanceRef.mapToDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.AUTHORITY, authorityInstanceRef.getUuid(), request.getCustomAttributes()));
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.AUTHORITY, authorityInstanceRef.getUuid()).connector(authorityInstanceRef.getConnectorUuid()).build(), request.getAttributes()));
        return authorityInstanceRef.mapToDto();
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.UPDATE)
    public AuthorityInstanceDto editAuthorityInstance(SecuredUUID uuid, AuthorityInstanceUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        AuthorityInstanceReference authorityInstanceRef = getAuthorityInstanceReferenceEntity(uuid);
        AuthorityInstanceDto ref = authorityInstanceRef.mapToDto();
        ConnectorDto connector = connectorService.getConnector(SecuredUUID.fromString(ref.getConnectorUuid()));

        FunctionGroupCode codeToSearch = FunctionGroupCode.AUTHORITY_PROVIDER;

        for (FunctionGroupDto function : connector.getFunctionGroups()) {
            if (function.getFunctionGroupCode() == FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER) {
                codeToSearch = FunctionGroupCode.LEGACY_AUTHORITY_PROVIDER;
                break;
            }
        }
        attributeEngine.validateCustomAttributesContent(Resource.AUTHORITY, request.getCustomAttributes());
        connectorService.mergeAndValidateAttributes(SecuredUUID.fromUUID(authorityInstanceRef.getConnectorUuid()), codeToSearch, request.getAttributes(), ref.getKind());

        // Load complete credential data
        var dataAttributes = attributeEngine.getDataAttributesByContent(authorityInstanceRef.getConnectorUuid(), request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);

        AuthorityProviderInstanceRequestDto authorityInstanceDto = new AuthorityProviderInstanceRequestDto();
        authorityInstanceDto.setKind(ref.getKind());
        authorityInstanceDto.setName(ref.getName());
        authorityInstanceDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
        connectorApiFactory.getAuthorityInstanceApiClient(connector).updateAuthorityInstance(connector,
                authorityInstanceRef.getAuthorityInstanceUuid(), authorityInstanceDto);
        authorityInstanceReferenceRepository.save(authorityInstanceRef);

        AuthorityInstanceDto dto = authorityInstanceRef.mapToDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.AUTHORITY, authorityInstanceRef.getUuid(), request.getCustomAttributes()));
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.AUTHORITY, authorityInstanceRef.getUuid()).connector(authorityInstanceRef.getConnectorUuid()).build(), request.getAttributes()));

        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DELETE)
    public void deleteAuthorityInstance(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        AuthorityInstanceReference authorityInstanceRef = getAuthorityInstanceReferenceEntity(uuid);
        removeAuthorityInstance(authorityInstanceRef);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DETAIL)
    public List<NameAndIdDto> listEndEntityProfiles(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        AuthorityInstanceReference authorityInstanceRef = getAuthorityInstanceReferenceEntity(uuid);
        ConnectorApiClientDto connectorDto = authorityInstanceRef.getConnector().mapToApiClientDtoV1();
        EndEntityProfileSyncApiClient endEntityProfileApiClient = connectorApiFactory.getEndEntityProfileApiClient(connectorDto);

        return endEntityProfileApiClient.listEndEntityProfiles(connectorDto,
                authorityInstanceRef.getAuthorityInstanceUuid());
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DETAIL)
    public List<NameAndIdDto> listCertificateProfiles(SecuredUUID uuid, Integer endEntityProfileId) throws ConnectorException, NotFoundException {
        AuthorityInstanceReference authorityInstanceRef = getAuthorityInstanceReferenceEntity(uuid);
        ConnectorApiClientDto connectorDto = authorityInstanceRef.getConnector().mapToApiClientDtoV1();
        EndEntityProfileSyncApiClient endEntityProfileApiClient = connectorApiFactory.getEndEntityProfileApiClient(connectorDto);

        return endEntityProfileApiClient.listCertificateProfiles(connectorDto,
                authorityInstanceRef.getAuthorityInstanceUuid(), endEntityProfileId);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DETAIL)
    public List<NameAndIdDto> listCAsInProfile(SecuredUUID uuid, Integer endEntityProfileId) throws ConnectorException, NotFoundException {
        AuthorityInstanceReference authorityInstanceRef = getAuthorityInstanceReferenceEntity(uuid);
        ConnectorApiClientDto connectorDto = authorityInstanceRef.getConnector().mapToApiClientDtoV1();
        EndEntityProfileSyncApiClient endEntityProfileApiClient = connectorApiFactory.getEndEntityProfileApiClient(connectorDto);

        return endEntityProfileApiClient.listCAsInProfile(connectorDto,
                authorityInstanceRef.getAuthorityInstanceUuid(), endEntityProfileId);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.ANY)
    public List<BaseAttribute> listRAProfileAttributes(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        AuthorityInstanceReference authorityInstance = getAuthorityInstanceReferenceEntity(uuid);
        ConnectorApiClientDto connectorDto = authorityInstance.getConnector().mapToApiClientDtoV1();

        return connectorApiFactory.getAuthorityInstanceApiClient(connectorDto).listRAProfileAttributes(connectorDto, authorityInstance.getAuthorityInstanceUuid());
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.ANY)
    public Boolean validateRAProfileAttributes(SecuredUUID uuid, List<RequestAttribute> attributes) throws ConnectorException, NotFoundException {
        AuthorityInstanceReference authorityInstance = getAuthorityInstanceReferenceEntity(uuid);
        ConnectorApiClientDto connectorDto = authorityInstance.getConnector().mapToApiClientDtoV1();

        return connectorApiFactory.getAuthorityInstanceApiClient(connectorDto).validateRAProfileAttributes(connectorDto, authorityInstance.getAuthorityInstanceUuid(),
                attributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteAuthorityInstance(List<SecuredUUID> uuids) throws ValidationException {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            AuthorityInstanceReference authorityInstanceRef = null;
            try {
                authorityInstanceRef = authorityInstanceReferenceRepository.findByUuid(uuid)
                        .orElseThrow(() -> new NotFoundException(AuthorityInstanceReference.class, uuid));
                removeAuthorityInstance(authorityInstanceRef);
            } catch (NotFoundException e) {
                logger.error("Authority Instance not found: {}", uuid);
            } catch (Exception e) {
                logger.warn(e.getMessage());
                messages.add(new BulkActionMessageDto(uuid.toString(), authorityInstanceRef != null ? authorityInstanceRef.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> forceDeleteAuthorityInstance(List<SecuredUUID> uuids) throws ValidationException {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            AuthorityInstanceReference authorityInstanceRef = null;
            try {
                authorityInstanceRef = authorityInstanceReferenceRepository.findByUuid(uuid)
                        .orElseThrow(() -> new NotFoundException(AuthorityInstanceReference.class, uuid));
                if (!authorityInstanceRef.getRaProfiles().isEmpty()) {
                    for (RaProfile ref : authorityInstanceRef.getRaProfiles()) {
                        ref.setAuthorityInstanceReference(null);
                        raProfileService.updateRaProfileEntity(ref);
                    }
                }
                authorityInstanceRef.setRaProfiles(null);
                authorityInstanceReferenceRepository.save(authorityInstanceRef);
                removeAuthorityInstance(authorityInstanceRef);
            } catch (Exception e) {
                logger.warn("Unable to delete the Authority instance with uuid {}. It may have been deleted. {}", uuid, e.getMessage());
                messages.add(new BulkActionMessageDto(uuid.toString(), authorityInstanceRef != null ? authorityInstanceRef.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return authorityInstanceReferenceRepository.findResourceObject(objectUuid, AuthorityInstanceReference_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return authorityInstanceReferenceRepository.findResourceObject(objectUuid.getValue(), AuthorityInstanceReference_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return authorityInstanceReferenceRepository.listResourceObjects(filter, AuthorityInstanceReference_.name, null, pagination);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getAuthorityInstanceReferenceEntity(uuid);
        // Since there are is no parent to the Authority, exclusive parent permission evaluation need not be done
    }

    private AuthorityInstanceReference getAuthorityInstanceReferenceEntity(SecuredUUID uuid) throws NotFoundException {
        return authorityInstanceReferenceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(AuthorityInstanceReference.class, uuid));
    }

    private void removeAuthorityInstance(AuthorityInstanceReference authorityInstanceRef) throws ValidationException {
        ValidationError error = null;
        if (authorityInstanceRef.getRaProfiles() != null && !authorityInstanceRef.getRaProfiles().isEmpty()) {
            error = ValidationError.create("Dependent RA profiles: {}", String.join(" ,", authorityInstanceRef.getRaProfiles().stream().map(RaProfile::getName).collect(Collectors.toSet())));
        }

        if (error != null) {
            throw new ValidationException(error);
        }
        if (authorityInstanceRef.getConnector() != null) {
            try {
                ConnectorApiClientDto connectorDto = authorityInstanceRef.getConnector().mapToApiClientDtoV1();
                connectorApiFactory.getAuthorityInstanceApiClient(connectorDto).removeAuthorityInstance(connectorDto, authorityInstanceRef.getAuthorityInstanceUuid());
            } catch (ConnectorEntityNotFoundException notFoundException) {
                logger.warn("Authority is already deleted in the connector. Proceeding to remove it from the core");
            } catch (Exception e) {
                logger.error(e.getMessage());
                throw new ValidationException(e.getMessage());
            }
        } else {
            logger.debug("Deleting authority without connector: {}", authorityInstanceRef);
        }
        attributeEngine.deleteObjectAttributeContent(Resource.AUTHORITY, authorityInstanceRef.getUuid());
        authorityInstanceReferenceRepository.delete(authorityInstanceRef);
    }

    @Override
    public ResourceObjectContentData getResourceObjectContent(UUID uuid) {
        return null;
    }
}
