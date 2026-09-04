package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.cryptography.token.TokenInstanceRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceStatusDetailDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenInstanceReference_;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.mapper.crypto.TokenInstanceDtoMapper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenInstanceBasicModel;
import com.otilm.core.model.crypto.TokenInstanceFullModel;
import com.otilm.core.model.crypto.TokenProfileBasicModel;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenInstanceInternalService;
import com.otilm.core.service.handler.token.RemoteTokenLifecycleCapability;
import com.otilm.core.service.handler.token.TokenActivationCapability;
import com.otilm.core.service.handler.token.TokenConfigurationValidationCapability;
import com.otilm.core.service.handler.token.TokenProfileValidationCapability;
import com.otilm.core.service.handler.token.TokenProviderAdapter;
import com.otilm.core.service.handler.token.TokenProviderAdapterFactory;
import com.otilm.core.service.handler.token.TokenProviderBinding;
import com.otilm.core.service.v2.ConnectorExternalService;
import com.otilm.core.service.writer.TokenInstanceReferenceWriter;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service(Resource.Codes.TOKEN)
public class TokenInstanceServiceImpl implements TokenInstanceExternalService, TokenInstanceInternalService {

    private static final Logger logger = LoggerFactory.getLogger(TokenInstanceServiceImpl.class);

    // --------------------------------------------------------------------------------
    // Services & API Clients
    // --------------------------------------------------------------------------------
    private ConnectorExternalService connectorExternalService;
    private CredentialInternalService credentialService;
    private AttributeEngine attributeEngine;
    private ResourceInternalService resourceService;
    private TokenProviderAdapterFactory tokenProviderAdapterFactory;

    // --------------------------------------------------------------------------------
    // Repositories
    // --------------------------------------------------------------------------------
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    private TokenInstanceReferenceWriter tokenInstanceReferenceWriter;

    private static @NonNull TokenInstanceBasicModel createNewTokenInstance(TokenInstanceRequestDto request,
            ImmutableConnectorFullModel connector, TokenProviderBinding binding,
            com.otilm.api.model.connector.cryptography.token.TokenInstanceDto creationResult) {
        return new ImmutableTokenInstanceBasicModel(UUID.randomUUID(),
                creationResult != null ? creationResult.getUuid() : null, request.getName(),
                TokenInstanceStatus.UNKNOWN, request.getKind(), connector.uuid(), connector.name(),
                binding.connectorInterface() == null ? null : binding.connectorInterface().uuid(), 0);
    }

    @Autowired
    public void setResourceService(ResourceInternalService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setTokenProviderAdapterFactory(TokenProviderAdapterFactory tokenProviderAdapterFactory) {
        this.tokenProviderAdapterFactory = tokenProviderAdapterFactory;
    }

    @Autowired
    public void setTokenInstanceReferenceRepository(TokenInstanceReferenceRepository tokenInstanceReferenceRepository) {
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
    }

    @Autowired
    public void setTokenInstanceReferenceWriter(TokenInstanceReferenceWriter tokenInstanceReferenceWriter) {
        this.tokenInstanceReferenceWriter = tokenInstanceReferenceWriter;
    }

    @Autowired
    public void setConnectorExternalService(ConnectorExternalService connectorExternalService) {
        this.connectorExternalService = connectorExternalService;
    }

    // -------------------------------------------------------------------------------------
    // Service Implementations
    // -------------------------------------------------------------------------------------

    @Autowired
    public void setCredentialService(CredentialInternalService credentialService) {
        this.credentialService = credentialService;
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.LIST)
    public List<TokenInstanceDto> listTokenInstances(SecurityFilter filter) {
        logger.info("Listing token instances");
        return tokenInstanceReferenceRepository
                .findBasicModelsUsingSecurityFilter(filter)
                .stream()
                .map(TokenInstanceDtoMapper::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.ANY)
    public List<BaseAttribute> listTokenAttributes(SecuredUUID connectorUuid, @Nullable String kind)
            throws ConnectorException, NotFoundException {
        logger.info("Listing token attributes for connector '{}'", connectorUuid);
        ImmutableConnectorFullModel connector = connectorExternalService.getConnectorFullModel(connectorUuid);

        return tokenProviderAdapterFactory.forConnector(connector).listTokenAttributes(kind);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DETAIL)
    public TokenInstanceDetailDto getTokenInstance(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        logger.info("Getting token instance with uuid: '{}'", uuid);
        TokenInstanceFullModel tokenInstance = getTokenInstanceModel(uuid);
        if (tokenInstance.connectorUuid() == null) {
            logger
                    .warn("Connector associated with token instance '{}' is not found. Returning persisted details",
                            tokenInstance.name());
            TokenInstanceStatusDetailDto status = new TokenInstanceStatusDetailDto(TokenInstanceStatus.DISCONNECTED);
            return assembleTokenInstanceDetail(tokenInstance, status);
        }
        TokenProviderAdapter adapter = tokenProviderAdapterFactory.forToken(tokenInstance);
        TokenInstanceStatusDetailDto refreshedStatus = refreshTokenInstanceStatus(tokenInstance, adapter);
        tokenInstanceReferenceWriter.updateStatus(tokenInstance.uuid(), refreshedStatus.getStatus());
        return assembleTokenInstanceDetail(tokenInstance, refreshedStatus);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.CREATE)
    public TokenInstanceDetailDto createTokenInstance(TokenInstanceRequestDto request) throws AlreadyExistException,
            ValidationException, ConnectorException, AttributeException, NotFoundException {
        logger.info("Creating token instance with name: '{}'", request.getName());
        if (tokenInstanceReferenceRepository.existsByName(request.getName())) {
            throw new AlreadyExistException(TokenInstanceReference.class, request.getName());
        }

        UUID connectorUuid;
        try {
            connectorUuid = UUID.fromString(request.getConnectorUuid());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new ValidationException(
                    ValidationError.create("The connector UUID '{}' is malformed", request.getConnectorUuid()));
        }

        ImmutableConnectorFullModel connector = connectorExternalService
                .getConnectorFullModel(SecuredUUID.fromUUID(connectorUuid));
        TokenProviderBinding binding = tokenProviderAdapterFactory.forConnectorWithBinding(connector);
        TokenProviderAdapter adapter = binding.adapter();

        attributeEngine.validateCustomAttributesContent(Resource.TOKEN, request.getCustomAttributes());
        validateAndMergeTokenRequestAttributes(connector, adapter, request.getAttributes(), request.getKind());

        com.otilm.api.model.connector.cryptography.token.TokenInstanceDto creationResult = null;
        if (adapter instanceof RemoteTokenLifecycleCapability cap) {
            var dataAttributes = attributeEngine.getDataAttributesByContent(connector.uuid(), request.getAttributes());
            credentialService.loadFullCredentialData(dataAttributes);
            resourceService.loadResourceObjectContentData(dataAttributes);

            com.otilm.api.model.connector.cryptography.token.TokenInstanceRequestDto remoteRequest = new com.otilm.api.model.connector.cryptography.token.TokenInstanceRequestDto();
            remoteRequest.setName(request.getName());
            remoteRequest.setKind(request.getKind());
            remoteRequest.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
            creationResult = cap.createRemoteToken(remoteRequest);
        }

        TokenInstanceBasicModel tokenInstance = createNewTokenInstance(request, connector, binding, creationResult);
        tokenInstanceReferenceWriter.save(tokenInstance);

        tokenInstanceReferenceWriter
                .updateAttributes(tokenInstance.uuid(), tokenInstance.connectorUuid(), request.getCustomAttributes(),
                        request.getAttributes(), creationResult == null ? List.of() : creationResult.getMetadata());

        TokenInstanceStatusDetailDto refreshedStatus = refreshTokenInstanceStatus(tokenInstance, adapter);
        tokenInstanceReferenceWriter.updateStatus(tokenInstance.uuid(), refreshedStatus.getStatus());

        logger.debug("Token Instance Reference: '{}'", tokenInstance);
        return assembleTokenInstanceDetail(tokenInstance, refreshedStatus);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.UPDATE)
    public TokenInstanceDetailDto updateTokenInstance(SecuredUUID uuid, TokenInstanceRequestDto request)
            throws ConnectorException, ValidationException, AttributeException, NotFoundException {
        logger.info("Updating token instance with uuid: '{}'", uuid);
        TokenInstanceFullModel tokenInstance = getTokenInstanceModel(uuid);

        ImmutableConnectorFullModel connector = connectorExternalService
                .getConnectorFullModel(SecuredUUID.fromUUID(tokenInstance.connectorUuid()));
        TokenProviderAdapter adapter = tokenProviderAdapterFactory.forToken(tokenInstance);

        attributeEngine.validateCustomAttributesContent(Resource.TOKEN, request.getCustomAttributes());
        validateAndMergeTokenRequestAttributes(connector, adapter, request.getAttributes(), request.getKind());

        com.otilm.api.model.connector.cryptography.token.TokenInstanceDto remoteResult = null;
        if (adapter instanceof RemoteTokenLifecycleCapability cap) {
            var dataAttributes = attributeEngine
                    .getDataAttributesByContent(tokenInstance.connectorUuid(), request.getAttributes());

            credentialService.loadFullCredentialData(dataAttributes);
            resourceService.loadResourceObjectContentData(dataAttributes);

            String tokenName = request.getName() == null ? tokenInstance.name() : request.getName();
            com.otilm.api.model.connector.cryptography.token.TokenInstanceRequestDto remoteRequest = new com.otilm.api.model.connector.cryptography.token.TokenInstanceRequestDto();
            remoteRequest.setName(tokenName);
            remoteRequest.setKind(request.getKind());
            remoteRequest.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
            remoteResult = cap.updateRemoteToken(tokenInstance, remoteRequest);
        }
        tokenInstanceReferenceWriter
                .updateAttributes(tokenInstance.uuid(), tokenInstance.connectorUuid(), request.getCustomAttributes(),
                        request.getAttributes(), remoteResult == null ? List.of() : remoteResult.getMetadata());

        TokenInstanceStatusDetailDto refreshedStatus = refreshTokenInstanceStatus(tokenInstance, adapter);
        tokenInstanceReferenceWriter.updateStatus(tokenInstance.uuid(), refreshedStatus.getStatus());

        return assembleTokenInstanceDetail(tokenInstance, refreshedStatus);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DELETE)
    public void deleteTokenInstance(SecuredUUID uuid) throws NotFoundException {
        logger.trace("Deleting token instance with uuid: '{}'", uuid);
        TokenInstanceFullModel tokenInstance = getTokenInstanceModel(uuid);
        deleteTokenInstance(tokenInstance);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ACTIVATE)
    public void activateTokenInstance(SecuredUUID uuid, List<RequestAttribute> attributes)
            throws ConnectorException, NotFoundException {
        logger.info("Activating token instance with uuid: '{}'", uuid);
        TokenInstanceFullModel tokenInstanceReference = getTokenInstanceModel(uuid);
        TokenProviderAdapter adapter = tokenProviderAdapterFactory.forToken(tokenInstanceReference);

        if (adapter instanceof TokenActivationCapability cap) {
            cap.activate(tokenInstanceReference, attributes);
            tokenInstanceReferenceWriter.updateStatus(tokenInstanceReference.uuid(), TokenInstanceStatus.ACTIVATED);
            logger.info("Token instance activated");
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ACTIVATE)
    public void deactivateTokenInstance(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        logger.info("Deactivating token instance with uuid: '{}'", uuid);
        TokenInstanceFullModel tokenInstanceReference = getTokenInstanceModel(uuid);
        TokenProviderAdapter adapter = tokenProviderAdapterFactory.forToken(tokenInstanceReference);

        if (adapter instanceof TokenActivationCapability cap) {
            cap.deactivate(tokenInstanceReference);
            tokenInstanceReferenceWriter.updateStatus(tokenInstanceReference.uuid(), TokenInstanceStatus.DEACTIVATED);
            logger.info("Token instance deactivated");
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DELETE)
    public void deleteTokenInstance(List<SecuredUUID> uuids) {
        logger.info("Deleting token instances with uuids: '{}'", uuids);
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            TokenInstanceFullModel tokenInstanceReference = null;
            try {
                tokenInstanceReference = getTokenInstanceModel(uuid);
                deleteTokenInstance(tokenInstanceReference);
            } catch (NotFoundException e) {
                logger.error("Token Instance not found: '{}'", uuid);
            } catch (Exception e) {
                logger.warn(e.getMessage());
                messages
                        .add(BulkActionMessageDto
                                .failure(uuid.toString(),
                                        tokenInstanceReference != null ? tokenInstanceReference.name() : "", e,
                                        "Delete failed"));
            }
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DETAIL)
    public TokenInstanceDetailDto reloadStatus(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        logger.info("Reloading status of token instance with uuid: '{}'", uuid);
        TokenInstanceFullModel tokenInstance = getTokenInstanceModel(uuid);
        TokenProviderAdapter adapter = tokenProviderAdapterFactory.forToken(tokenInstance);
        TokenInstanceStatusDetailDto refreshedStatus = adapter.getStatus(tokenInstance);
        tokenInstanceReferenceWriter.updateStatus(tokenInstance.uuid(), refreshedStatus.getStatus());
        logger.info("Token instance status reloaded. Status of the token instance: '{}'", refreshedStatus.getStatus());
        return assembleTokenInstanceDetail(tokenInstance, refreshedStatus);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ANY)
    public List<BaseAttribute> listTokenProfileAttributes(SecuredUUID uuid)
            throws ConnectorException, NotFoundException {
        logger.info("Listing token profile attributes of token instance with uuid: '{}'", uuid);
        TokenInstanceFullModel tokenInstanceReference = getTokenInstanceModel(uuid);
        return tokenProviderAdapterFactory
                .forToken(tokenInstanceReference)
                .listTokenProfileAttributes(tokenInstanceReference);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ANY)
    public List<KeyUsage> listSupportedKeyUsages(SecuredUUID tokenInstanceUuid)
            throws NotFoundException, ConnectorException {
        logger.info("Listing supported Key Usages of token instance with uuid: '{}'", tokenInstanceUuid);
        TokenInstanceFullModel tokenInstanceReference = getTokenInstanceModel(tokenInstanceUuid);
        return tokenProviderAdapterFactory
                .forToken(tokenInstanceReference)
                .listSupportedKeyUsages(tokenInstanceReference);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ANY)
    public List<BaseAttribute> listTokenInstanceActivationAttributes(SecuredUUID uuid)
            throws ConnectorException, NotFoundException {
        logger.info("Listing token instance activation attributes of token instance with uuid: '{}'", uuid);
        TokenInstanceFullModel tokenInstanceReference = getTokenInstanceModel(uuid);
        TokenProviderAdapter adapter = tokenProviderAdapterFactory.forToken(tokenInstanceReference);

        if (adapter instanceof TokenActivationCapability cap) {
            return cap.listActivationAttributes(tokenInstanceReference);
        }
        return List.of();
    }

    @Override
    // Internal Use Only. Not exposed in controller
    public TokenInstanceReference getTokenInstanceEntity(SecuredUUID uuid) throws NotFoundException {
        return tokenInstanceReferenceRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(TokenInstanceReference.class, uuid.toString()));
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.ANY)
    public void validateTokenProfileAttributes(SecuredUUID uuid, List<RequestAttribute> attributes)
            throws ConnectorException, AttributeException, NotFoundException {
        logger.info("Validating token profile attributes of token instance with uuid: '{}'", uuid);

        TokenInstanceFullModel tokenInstanceReference = getTokenInstanceModel(uuid);
        logger.debug("Token instance detail: '{}'", tokenInstanceReference);

        TokenProviderAdapter adapter = tokenProviderAdapterFactory.forToken(tokenInstanceReference);
        List<RequestAttribute> safeAttributes = attributes == null ? List.of() : attributes;

        // validate first by connector
        if (adapter instanceof TokenProfileValidationCapability cap) {
            cap.validateTokenProfileAttributes(tokenInstanceReference, safeAttributes);
        }
        // list definitions
        List<BaseAttribute> definitions = adapter.listTokenProfileAttributes(tokenInstanceReference);

        // validate and update definitions with attribute engine
        attributeEngine
                .validateUpdateDataAttributes(tokenInstanceReference.connectorUuid(), null, definitions,
                        safeAttributes);
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return tokenInstanceReferenceRepository.findResourceObject(objectUuid, TokenInstanceReference_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return getResourceObjectInternal(objectUuid.getValue());
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        return tokenInstanceReferenceRepository.listResourceObjects(filter, TokenInstanceReference_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.TOKEN, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getTokenInstanceEntity(uuid);
        // Since there are is no parent to the Group, exclusive parent permission evaluation need not be done
    }

    private TokenInstanceFullModel getTokenInstanceModel(SecuredUUID uuid) throws NotFoundException {
        TokenInstanceFullModel tokenInstance = tokenInstanceReferenceRepository
                .findFullModelByUuid(uuid.getValue())
                .orElseThrow(() -> new NotFoundException(TokenInstanceBasicModel.class, uuid));
        logger.trace("Token Instance Reference: '{}'", tokenInstance);
        return tokenInstance;
    }

    private TokenInstanceDetailDto assembleTokenInstanceDetail(TokenInstanceBasicModel tokenInstanceReference,
            @Nullable TokenInstanceStatusDetailDto statusDetail) {
        TokenInstanceDetailDto detail = assembleTokenInstanceDetailBase(tokenInstanceReference);
        if (statusDetail != null) {
            detail.setStatus(statusDetail);
        }
        detail
                .setAttributes(attributeEngine
                        .getObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(Resource.TOKEN, tokenInstanceReference.uuid())
                                .connector(tokenInstanceReference.connectorUuid())
                                .build()));
        detail
                .setCustomAttributes(attributeEngine
                        .getObjectCustomAttributesContent(Resource.TOKEN, tokenInstanceReference.uuid()));
        logger.debug("Token Instance detail: '{}'", detail);
        return detail;
    }

    private TokenInstanceDetailDto assembleTokenInstanceDetailBase(TokenInstanceBasicModel tokenInstanceReference) {
        TokenInstanceDetailDto detail = TokenInstanceDtoMapper.mapToDetailDto(tokenInstanceReference);
        if (tokenInstanceReference.connectorUuid() == null) {
            String connectorName = tokenInstanceReference.connectorName();
            detail.setConnectorName(connectorName == null ? "(Deleted)" : connectorName + " (Deleted)");
            detail.setConnectorUuid("");
        } else {
            detail.setConnectorName(tokenInstanceReference.connectorName());
            detail.setConnectorUuid(tokenInstanceReference.connectorUuid().toString());
        }
        detail
                .setMetadata(attributeEngine
                        .getMappedMetadataContent(ObjectAttributeContentInfo
                                .builder(Resource.TOKEN, tokenInstanceReference.uuid())
                                .build()));
        return detail;
    }

    private void validateAndMergeTokenRequestAttributes(ImmutableConnectorFullModel connector,
            TokenProviderAdapter adapter, List<RequestAttribute> attributes, @Nullable String kind)
            throws ConnectorException, AttributeException {
        List<RequestAttribute> safeAttributes = attributes == null ? List.of() : attributes;

        // validate first by connector
        if (adapter instanceof TokenConfigurationValidationCapability cap) {
            cap.validateTokenAttributes(kind, safeAttributes);
        }

        // get definitions from connector
        List<BaseAttribute> definitions = adapter.listTokenAttributes(kind);

        // validate and update definitions with attribute engine
        attributeEngine.validateUpdateDataAttributes(connector.uuid(), null, definitions, safeAttributes);
    }

    private TokenInstanceStatusDetailDto refreshTokenInstanceStatus(TokenInstanceBasicModel tokenInstance,
            TokenProviderAdapter adapter) {
        TokenInstanceStatusDetailDto status;
        try {
            status = adapter.getStatus(tokenInstance);
        } catch (Exception e) {
            logger
                    .warn("Unable to communicate with connector while refreshing status of token instance '{}' ({})",
                            tokenInstance.name(), tokenInstance.uuid(), e);
            status = new TokenInstanceStatusDetailDto(TokenInstanceStatus.WARNING);
        }
        return status;
    }

    private void deleteTokenInstance(TokenInstanceFullModel tokenInstanceReference)
            throws ValidationException, NotFoundException {
        logger
                .info("Deleting token instance '{}' ('{}')", tokenInstanceReference.name(),
                        tokenInstanceReference.uuid());
        logger.trace("Token instance to delete: '{}'", tokenInstanceReference);
        ValidationError error = null;
        if (tokenInstanceReference.tokenProfiles() != null && !tokenInstanceReference.tokenProfiles().isEmpty()) {
            error = ValidationError
                    .create("Dependent Token Profiles: {}",
                            String
                                    .join(" ,",
                                            tokenInstanceReference
                                                    .tokenProfiles()
                                                    .stream()
                                                    .map(TokenProfileBasicModel::name)
                                                    .collect(Collectors.toSet())));
        }

        if (error != null) {
            logger.error("Token Instances has associations and cannot be deleted: '{}'", error);
            throw new ValidationException(error);
        }
        if (tokenInstanceReference.connectorUuid() != null) {
            TokenProviderAdapter adapter = tokenProviderAdapterFactory.forToken(tokenInstanceReference);
            if (adapter instanceof RemoteTokenLifecycleCapability cap) {
                try {
                    logger.debug("Deleting token instance with connector: '{}'", tokenInstanceReference);
                    cap.removeRemoteToken(tokenInstanceReference);
                } catch (Exception e) {
                    logger.error("Connector failed to remove token instance '{}'", tokenInstanceReference.name(), e);
                    throw new ValidationException(ValidationError
                            .create("Unable to remove token instance '{}' from its connector.",
                                    tokenInstanceReference.name()));
                }
            }
        } else {
            logger.debug("Deleting token instance without connector: '{}'", tokenInstanceReference);
        }
        tokenInstanceReferenceWriter.delete(tokenInstanceReference);

        logger
                .debug("Token instance '{}': ('{}') has been deleted", tokenInstanceReference.name(),
                        tokenInstanceReference.uuid());
    }
}
