package com.czertainly.core.service.impl;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.cryptography.token.TokenInstanceRequestDto;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceStatusDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorApiClientDto;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.czertainly.api.model.core.cryptography.token.TokenInstanceDto;
import com.czertainly.api.model.core.cryptography.token.TokenInstanceStatusDetailDto;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.TokenInstanceReferenceRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.CredentialService;
import com.czertainly.core.service.ResourceService;
import com.czertainly.core.service.TokenInstanceService;
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

@Service(Resource.Codes.TOKEN)
@Transactional
public class TokenInstanceServiceImpl implements TokenInstanceService {

    private static final Logger logger = LoggerFactory.getLogger(TokenInstanceServiceImpl.class);

    // --------------------------------------------------------------------------------
    // Services & API Clients
    // --------------------------------------------------------------------------------
    private ConnectorApiFactory connectorApiFactory;
    private ConnectorServiceImpl connectorService;
    private CredentialService credentialService;
    private AttributeEngine attributeEngine;
    private ResourceService resourceService;

    // --------------------------------------------------------------------------------
    // Repositories
    // --------------------------------------------------------------------------------
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    public void setResourceService(ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setTokenInstanceReferenceRepository(TokenInstanceReferenceRepository tokenInstanceReferenceRepository) {
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
    }

    @Autowired
    public void setConnectorService(ConnectorServiceImpl connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setCredentialService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    //-------------------------------------------------------------------------------------
    //Service Implementations
    //-------------------------------------------------------------------------------------

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.LIST)
    public List<TokenInstanceDto> listTokenInstances(SecurityFilter filter) {
        logger.info("Listing token instances");
        return tokenInstanceReferenceRepository.findUsingSecurityFilter(filter)
                .stream()
                .map(TokenInstanceReference::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DETAIL)
    public TokenInstanceDetailDto getTokenInstance(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        logger.info("Getting token instance with uuid: {}", uuid);
        TokenInstanceReference tokenInstanceReference = getTokenInstanceReferenceEntity(uuid);
        TokenInstanceDetailDto tokenInstanceDetailDto = tokenInstanceReference.mapToDetailDto();
        logger.debug("Token Instance detail: {}", tokenInstanceDetailDto);
        if (tokenInstanceReference.getConnector() == null) {
            tokenInstanceDetailDto.setConnectorName(tokenInstanceReference.getConnectorName() + " (Deleted)");
            tokenInstanceDetailDto.setConnectorUuid("");
            logger.warn("Connector associated with the Authority: {} is not found. Unable to show details", tokenInstanceReference);
            return tokenInstanceDetailDto;
        }

        TokenInstanceStatusDto status;
        TokenInstanceStatusDetailDto statusDetail = new TokenInstanceStatusDetailDto();
        try {
            ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();
            status = connectorApiFactory.getTokenInstanceApiClient(connectorDto).getTokenInstanceStatus(
                    connectorDto,
                    tokenInstanceReference.getTokenInstanceUuid()
            );
            tokenInstanceReference.setStatus(status.getStatus());
            tokenInstanceReferenceRepository.save(tokenInstanceReference);
            statusDetail.setStatus(status.getStatus());
            statusDetail.setComponents(status.getComponents());
        } catch (ConnectorException e) {
            logger.error("Unable to communicate with connector: {}", e.getMessage());
            statusDetail.setStatus(TokenInstanceStatus.UNKNOWN);
            tokenInstanceDetailDto.setStatus(statusDetail);
        }

        tokenInstanceDetailDto.setStatus(statusDetail);
        tokenInstanceDetailDto.setConnectorName(tokenInstanceReference.getConnector().getName());
        tokenInstanceDetailDto.setConnectorUuid(tokenInstanceReference.getConnector().getUuid().toString());
        tokenInstanceDetailDto.setAttributes(attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenInstanceReference.getUuid()).connector(tokenInstanceReference.getConnectorUuid()).build()));
        tokenInstanceDetailDto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.TOKEN, uuid.getValue()));
        tokenInstanceDetailDto.setMetadata(attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenInstanceReference.getUuid()).build()));
        logger.debug("Token Instance detail: {}", tokenInstanceDetailDto);
        return tokenInstanceDetailDto;
    }

    @Override
    // Internal Use Only. Not exposed in controller
    public TokenInstanceReference getTokenInstanceEntity(SecuredUUID uuid) throws NotFoundException {
        return getTokenInstanceReferenceEntity(uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.CREATE)
    public TokenInstanceDetailDto createTokenInstance(TokenInstanceRequestDto request) throws AlreadyExistException, ValidationException, ConnectorException, AttributeException, NotFoundException {
        logger.info("Creating token instance with name: {}", request.getName());
        if (tokenInstanceReferenceRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(TokenInstanceReference.class, request.getName());
        }

        ConnectorDto connector = connectorService.getConnector(SecuredUUID.fromString(request.getConnectorUuid()));
        UUID connectorUuid =  UUID.fromString(connector.getUuid());

        attributeEngine.validateCustomAttributesContent(Resource.TOKEN, request.getCustomAttributes());
        connectorService.mergeAndValidateAttributes(SecuredUUID.fromUUID(connectorUuid), FunctionGroupCode.CRYPTOGRAPHY_PROVIDER, request.getAttributes(), request.getKind());

        // Load complete credential data
        var dataAttributes = attributeEngine.getDataAttributesByContent(connectorUuid, request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);

        com.czertainly.api.model.connector.cryptography.token.TokenInstanceRequestDto tokenInstanceRequestDto =
                new com.czertainly.api.model.connector.cryptography.token.TokenInstanceRequestDto();
        tokenInstanceRequestDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
        tokenInstanceRequestDto.setKind(request.getKind());
        tokenInstanceRequestDto.setName(request.getName());
        logger.debug("Token Instance Request to the connector: {}", tokenInstanceRequestDto);
        com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto response =
                connectorApiFactory.getTokenInstanceApiClient(connector).createTokenInstance(connector, tokenInstanceRequestDto);
        TokenInstanceStatusDto status = connectorApiFactory.getTokenInstanceApiClient(connector).getTokenInstanceStatus(connector, response.getUuid());
        logger.debug("Token Instance Response from the connector: {}", response);
        TokenInstanceReference tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setTokenInstanceUuid(response.getUuid());
        tokenInstanceReference.setName(request.getName());
        tokenInstanceReference.setConnectorUuid(connectorUuid);
        tokenInstanceReference.setKind(request.getKind());
        tokenInstanceReference.setConnectorName(connector.getName());
        tokenInstanceReference.setStatus(status.getStatus());
        logger.debug("Token Instance Reference: {}", tokenInstanceReference);
        tokenInstanceReferenceRepository.save(tokenInstanceReference);

        attributeEngine.updateMetadataAttributes(response.getMetadata(), ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenInstanceReference.getUuid()).connector(connectorUuid).build());
        logger.debug("Metadata and Custom attributes created");
        TokenInstanceDetailDto dto = tokenInstanceReference.mapToDetailDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.TOKEN, tokenInstanceReference.getUuid(), request.getCustomAttributes()));
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenInstanceReference.getUuid()).connector(connectorUuid).build(), request.getAttributes()));
        dto.setMetadata(attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenInstanceReference.getUuid()).build()));

        logger.debug("Token Instance detail: {}", dto);
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.UPDATE)
    public TokenInstanceDetailDto updateTokenInstance(SecuredUUID uuid, TokenInstanceRequestDto request) throws ConnectorException, ValidationException, AttributeException, NotFoundException {
        logger.info("Updating token instance with uuid: {}", uuid);
        TokenInstanceReference tokenInstanceReference = getTokenInstanceReferenceEntity(uuid);
        logger.debug("Token Instance Reference: {}", tokenInstanceReference);
        ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();

        attributeEngine.validateCustomAttributesContent(Resource.TOKEN, request.getCustomAttributes());
        connectorService.mergeAndValidateAttributes(SecuredUUID.fromUUID(tokenInstanceReference.getConnectorUuid()), FunctionGroupCode.CRYPTOGRAPHY_PROVIDER, request.getAttributes(), request.getKind());

        TokenInstanceStatusDto status;
        TokenInstanceStatusDetailDto statusDetail = new TokenInstanceStatusDetailDto();
        try {
            status = connectorApiFactory.getTokenInstanceApiClient(connectorDto).getTokenInstanceStatus(connectorDto, tokenInstanceReference.getTokenInstanceUuid());
            tokenInstanceReference.setStatus(status.getStatus());
            tokenInstanceReferenceRepository.save(tokenInstanceReference);
            statusDetail.setStatus(status.getStatus());
            statusDetail.setComponents(status.getComponents());
        } catch (ConnectorException e) {
            logger.error("Unable to communicate with connector: {}", e.getMessage());
            statusDetail.setStatus(TokenInstanceStatus.UNKNOWN);
        }

        // Load complete credential data
        var dataAttributes = attributeEngine.getDataAttributesByContent(tokenInstanceReference.getConnectorUuid(), request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);

        com.czertainly.api.model.connector.cryptography.token.TokenInstanceRequestDto tokenInstanceRequestDto =
                new com.czertainly.api.model.connector.cryptography.token.TokenInstanceRequestDto();
        tokenInstanceRequestDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
        tokenInstanceRequestDto.setKind(request.getKind());
        tokenInstanceRequestDto.setName(request.getName());
        logger.debug("Token Instance Request to the connector: {}", tokenInstanceRequestDto);
        com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto response =
                connectorApiFactory.getTokenInstanceApiClient(connectorDto).updateTokenInstance(connectorDto, tokenInstanceReference.getTokenInstanceUuid(), tokenInstanceRequestDto);

        attributeEngine.updateMetadataAttributes(response.getMetadata(), ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenInstanceReference.getUuid()).connector(tokenInstanceReference.getConnectorUuid()).build());

        logger.debug("Metadata and Custom attributes updated");
        TokenInstanceDetailDto dto = tokenInstanceReference.mapToDetailDto();
        dto.setStatus(statusDetail);
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.TOKEN, tokenInstanceReference.getUuid(), request.getCustomAttributes()));
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenInstanceReference.getUuid()).connector(tokenInstanceReference.getConnectorUuid()).build(), request.getAttributes()));
        dto.setMetadata(attributeEngine.getMappedMetadataContent(ObjectAttributeContentInfo.builder(Resource.TOKEN, tokenInstanceReference.getUuid()).build()));
        logger.debug("Token Instance detail: {}", dto);
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DELETE)
    public void deleteTokenInstance(SecuredUUID uuid) throws NotFoundException {
        logger.info("Deleting token instance with uuid: {}", uuid);
        TokenInstanceReference tokenInstanceReference = getTokenInstanceReferenceEntity(uuid);
        removeTokenInstance(tokenInstanceReference);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ACTIVATE)
    public void activateTokenInstance(SecuredUUID uuid, List<RequestAttribute> attributes) throws ConnectorException, NotFoundException {
        logger.info("Activating token instance with uuid: {}", uuid);
        TokenInstanceReference tokenInstanceReference = getTokenInstanceReferenceEntity(uuid);
        ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();
        connectorApiFactory.getTokenInstanceApiClient(connectorDto).activateTokenInstance(
                connectorDto,
                tokenInstanceReference.getTokenInstanceUuid(),
                attributes
        );
        tokenInstanceReference.setStatus(TokenInstanceStatus.ACTIVATED);
        logger.info("Token instance activated");
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ACTIVATE)
    public void deactivateTokenInstance(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        logger.info("Deactivating token instance with uuid: {}", uuid);
        TokenInstanceReference tokenInstanceReference = getTokenInstanceReferenceEntity(uuid);
        ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();
        connectorApiFactory.getTokenInstanceApiClient(connectorDto).deactivateTokenInstance(
                connectorDto,
                tokenInstanceReference.getTokenInstanceUuid()
        );
        tokenInstanceReference.setStatus(TokenInstanceStatus.DEACTIVATED);
        logger.info("Token instance deactivated");
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DELETE)
    public void deleteTokenInstance(List<SecuredUUID> uuids) {
        logger.info("Deleting token instances with uuids: {}", uuids);
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            TokenInstanceReference tokenInstanceReference = null;
            try {
                tokenInstanceReference = getTokenInstanceReferenceEntity(uuid);
                removeTokenInstance(tokenInstanceReference);
            } catch (NotFoundException e) {
                logger.error("Token Instance not found: {}", uuid);
            } catch (Exception e) {
                logger.warn(e.getMessage());
                messages.add(new BulkActionMessageDto(uuid.toString(), tokenInstanceReference != null ? tokenInstanceReference.getName() : "", e.getMessage()));
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DETAIL)
    public TokenInstanceDetailDto reloadStatus(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        logger.info("Reloading status of token instance with uuid: {}", uuid);
        TokenInstanceReference tokenInstanceReference = getTokenInstanceReferenceEntity(uuid);
        ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();
        TokenInstanceStatusDto status = connectorApiFactory.getTokenInstanceApiClient(connectorDto).getTokenInstanceStatus(
                connectorDto,
                tokenInstanceReference.getTokenInstanceUuid()
        );
        tokenInstanceReference.setStatus(status.getStatus());
        tokenInstanceReferenceRepository.save(tokenInstanceReference);
        logger.info("Token instance status reloaded. Status of the token instance: {}", status);
        return getTokenInstance(uuid);

    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ANY)
    public List<BaseAttribute> listTokenProfileAttributes(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        logger.info("Listing token profile attributes of token instance with uuid: {}", uuid);
        TokenInstanceReference tokenInstanceReference = getTokenInstanceReferenceEntity(uuid);
        logger.debug("Token instance detail: {}", tokenInstanceReference);
        ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();
        return connectorApiFactory.getTokenInstanceApiClient(connectorDto).listTokenProfileAttributes(
                connectorDto,
                tokenInstanceReference.getTokenInstanceUuid()
        );
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ANY)
    public void validateTokenProfileAttributes(SecuredUUID uuid, List<RequestAttribute> attributes) throws ConnectorException, NotFoundException {
        logger.info("Validating token profile attributes of token instance with uuid: {}", uuid);
        TokenInstanceReference tokenInstanceReference = getTokenInstanceReferenceEntity(uuid);
        logger.debug("Token instance detail: {}", tokenInstanceReference);
        ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();
        connectorApiFactory.getTokenInstanceApiClient(connectorDto).validateTokenProfileAttributes(connectorDto, tokenInstanceReference.getTokenInstanceUuid(),
                attributes);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ANY)
    public List<BaseAttribute> listTokenInstanceActivationAttributes(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        logger.info("Listing token instance activation attributes of token instance with uuid: {}", uuid);
        TokenInstanceReference tokenInstanceReference = getTokenInstanceReferenceEntity(uuid);
        logger.debug("Token instance detail: {}", tokenInstanceReference);
        ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();
        return connectorApiFactory.getTokenInstanceApiClient(connectorDto).listTokenInstanceActivationAttributes(
                connectorDto,
                tokenInstanceReference.getTokenInstanceUuid()
        );
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return tokenInstanceReferenceRepository.findResourceObject(objectUuid, TokenInstanceReference_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return tokenInstanceReferenceRepository.listResourceObjects(filter, TokenInstanceReference_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return getResourceObjectInternal(objectUuid.getValue());
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getTokenInstanceEntity(uuid);
        // Since there are is no parent to the Group, exclusive parent permission evaluation need not be done
    }

    private TokenInstanceReference getTokenInstanceReferenceEntity(SecuredUUID uuid) throws NotFoundException {
        return tokenInstanceReferenceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenInstanceReference.class, uuid));
    }

    private void removeTokenInstance(TokenInstanceReference tokenInstanceReference) throws ValidationException {
        logger.info("Removing token instance: {}", tokenInstanceReference);
        ValidationError error = null;
        if (tokenInstanceReference.getTokenProfiles() != null && !tokenInstanceReference.getTokenProfiles().isEmpty()) {
            error = ValidationError.create("Dependent Token Profiles: {}",
                    String.join(" ,",
                            tokenInstanceReference
                                    .getTokenProfiles()
                                    .stream()
                                    .map(TokenProfile::getName)
                                    .collect(Collectors.toSet()
                                    )
                    )
            );
        }

        if (error != null) {
            logger.error("Token Instances has associations and cannot be deleted: {}", error);
            throw new ValidationException(error);
        }
        if (tokenInstanceReference.getConnector() != null) {
            try {
                logger.debug("Deleting token instance with connector: {}", tokenInstanceReference);
                ConnectorApiClientDto connectorDto = tokenInstanceReference.getConnector().mapToApiClientDtoV1();
                connectorApiFactory.getTokenInstanceApiClient(connectorDto).removeTokenInstance(connectorDto, tokenInstanceReference.getTokenInstanceUuid());
            } catch (Exception e) {
                logger.error(e.getMessage());
                throw new ValidationException(e.getMessage());
            }
        } else {
            logger.debug("Deleting token instance without connector: {}", tokenInstanceReference);
        }
        logger.debug("Deleting token instance attributes");
        attributeEngine.deleteObjectAttributeContent(Resource.TOKEN, tokenInstanceReference.getUuid());
        tokenInstanceReferenceRepository.delete(tokenInstanceReference);
        logger.info("Token instance removed: {}", tokenInstanceReference);
    }
}
