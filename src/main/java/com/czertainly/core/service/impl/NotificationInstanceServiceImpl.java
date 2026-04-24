package com.czertainly.core.service.impl;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.common.attribute.common.DataAttribute;
import com.czertainly.api.model.connector.notification.NotificationProviderInstanceDto;
import com.czertainly.api.model.connector.notification.NotificationProviderInstanceRequestDto;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorApiClientDto;
import com.czertainly.api.model.core.connector.ConnectorDto;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.notification.AttributeMappingDto;
import com.czertainly.api.model.core.notification.NotificationInstanceDto;
import com.czertainly.api.model.core.notification.NotificationInstanceRequestDto;
import com.czertainly.api.model.core.notification.NotificationInstanceUpdateRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.notifications.NotificationInstanceMappedAttributes;
import com.czertainly.core.dao.entity.notifications.NotificationInstanceReference;
import com.czertainly.core.dao.repository.notifications.NotificationInstanceMappedAttributeRepository;
import com.czertainly.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.czertainly.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.ConnectorService;
import com.czertainly.core.service.CredentialService;
import com.czertainly.core.service.NotificationInstanceService;
import com.czertainly.core.service.ResourceService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class NotificationInstanceServiceImpl implements NotificationInstanceService {
    private static final Logger logger = LoggerFactory.getLogger(NotificationInstanceServiceImpl.class);

    private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;
    private NotificationInstanceMappedAttributeRepository notificationInstanceMappedAttributeRepository;
    private NotificationProfileVersionRepository notificationProfileVersionRepository;

    private ConnectorService connectorService;
    private CredentialService credentialService;
    private ConnectorApiFactory connectorApiFactory;
    private AttributeEngine attributeEngine;

    private ResourceService resourceService;

    @Autowired
    public void setResourceService(ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setNotificationInstanceReferenceRepository(NotificationInstanceReferenceRepository notificationInstanceReferenceRepository) {
        this.notificationInstanceReferenceRepository = notificationInstanceReferenceRepository;
    }

    @Autowired
    public void setNotificationInstanceMappedAttributeRepository(NotificationInstanceMappedAttributeRepository notificationInstanceMappedAttributeRepository) {
        this.notificationInstanceMappedAttributeRepository = notificationInstanceMappedAttributeRepository;
    }

    @Autowired
    public void setNotificationProfileVersionRepository(NotificationProfileVersionRepository notificationProfileVersionRepository) {
        this.notificationProfileVersionRepository = notificationProfileVersionRepository;
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

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_INSTANCE, action = ResourceAction.LIST)
    public List<NotificationInstanceDto> listNotificationInstances() {
        return notificationInstanceReferenceRepository.findAll()
                .stream()
                .map(NotificationInstanceReference::mapToDto).toList();
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_INSTANCE, action = ResourceAction.DETAIL)
    public NotificationInstanceDto getNotificationInstance(UUID uuid) throws ConnectorException, NotFoundException {
        NotificationInstanceReference notificationInstanceReference = getNotificationInstanceReferenceEntity(uuid);

        List<ResponseAttribute> attributes = attributeEngine.getObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.NOTIFICATION_INSTANCE, notificationInstanceReference.getUuid()).connector(notificationInstanceReference.getConnectorUuid()).build());

        NotificationInstanceDto notificationInstanceDto = notificationInstanceReference.mapToDto();
        notificationInstanceDto.setAttributeMappings(notificationInstanceReference.getMappedAttributes()
                .stream()
                .map(NotificationInstanceMappedAttributes::mapToDto).toList());

        if (notificationInstanceReference.getConnector() == null) {
            notificationInstanceDto.setConnectorName(notificationInstanceReference.getConnectorName() + " (Deleted)");
            notificationInstanceDto.setConnectorUuid("");
            notificationInstanceDto.setAttributes(attributes);
            logger.warn("Connector associated with the Notification: {} is not found. Unable to show details", notificationInstanceReference.getName());
            return notificationInstanceDto;
        }

        ConnectorApiClientDto connectorDto = notificationInstanceReference.getConnector().mapToApiClientDtoV1();
        NotificationProviderInstanceDto notificationProviderInstanceDto = connectorApiFactory.getNotificationInstanceApiClient(connectorDto).getNotificationInstance(
                connectorDto,
                notificationInstanceReference.getNotificationInstanceUuid().toString());

        if (attributes.isEmpty() && notificationProviderInstanceDto.getAttributes() != null && !notificationProviderInstanceDto.getAttributes().isEmpty()) {
            try {
                List<RequestAttribute> requestAttributes = AttributeDefinitionUtils.getClientAttributes(notificationProviderInstanceDto.getAttributes());
                attributeEngine.updateDataAttributeDefinitions(notificationInstanceReference.getConnectorUuid(), null, notificationProviderInstanceDto.getAttributes());
                attributes = attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.NOTIFICATION_INSTANCE, notificationInstanceReference.getUuid()).connector(notificationInstanceReference.getConnectorUuid()).build(), requestAttributes);
            } catch (AttributeException e) {
                logger.warn("Could not update data attributes for notification instance {} retrieved from connector", notificationInstanceReference.getName());
            }
        }

        notificationInstanceDto.setAttributes(attributes);

        return notificationInstanceDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_INSTANCE, action = ResourceAction.CREATE)
    public NotificationInstanceDto createNotificationInstance(NotificationInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        if (notificationInstanceReferenceRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(NotificationInstanceReference.class, request.getName());
        }

        ConnectorDto connector = connectorService.getConnector(SecuredUUID.fromString(request.getConnectorUuid()));

        NotificationProviderInstanceDto response = saveNotificationProviderInstance(null,
                request,
                request.getKind(),
                request.getName(),
                connector);

        NotificationInstanceReference notificationInstanceRef = new NotificationInstanceReference();
        notificationInstanceRef.setNotificationInstanceUuid(UUID.fromString(response.getUuid()));
        notificationInstanceRef.setName(request.getName());
        notificationInstanceRef.setDescription(request.getDescription());
        notificationInstanceRef.setKind(request.getKind());
        notificationInstanceRef.setConnectorName(connector.getName());
        notificationInstanceRef.setConnectorUuid(UUID.fromString(connector.getUuid()));
        notificationInstanceReferenceRepository.save(notificationInstanceRef);

        updateMappedAttributes(notificationInstanceRef, request.getAttributeMappings());
        notificationInstanceReferenceRepository.save(notificationInstanceRef);

        NotificationInstanceDto dto = notificationInstanceRef.mapToDto();
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.NOTIFICATION_INSTANCE, notificationInstanceRef.getUuid()).connector(notificationInstanceRef.getConnectorUuid()).build(), request.getAttributes()));

        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_INSTANCE, action = ResourceAction.UPDATE)
    public NotificationInstanceDto editNotificationInstance(UUID uuid, NotificationInstanceUpdateRequestDto request) throws ConnectorException, AttributeException, NotFoundException {
        NotificationInstanceReference notificationInstanceRef = getNotificationInstanceReferenceEntity(uuid);

        saveNotificationProviderInstance(notificationInstanceRef.getNotificationInstanceUuid(),
                request,
                notificationInstanceRef.getKind(),
                notificationInstanceRef.getName(),
                notificationInstanceRef.getConnector().mapToApiClientDtoV1());

        notificationInstanceRef.setDescription(request.getDescription());

        for (NotificationInstanceMappedAttributes mappedAttribute : notificationInstanceRef.getMappedAttributes()) {
            notificationInstanceMappedAttributeRepository.delete(mappedAttribute);
        }
        notificationInstanceRef.getMappedAttributes().clear();

        updateMappedAttributes(notificationInstanceRef, request.getAttributeMappings());

        NotificationInstanceDto dto = notificationInstanceReferenceRepository.save(notificationInstanceRef).mapToDto();
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.NOTIFICATION_INSTANCE, notificationInstanceRef.getUuid()).connector(notificationInstanceRef.getConnectorUuid()).build(), request.getAttributes()));

        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.NOTIFICATION_INSTANCE, action = ResourceAction.DELETE)
    public void deleteNotificationInstance(UUID uuid) throws NotFoundException {
        NotificationInstanceReference notificationInstanceRef = getNotificationInstanceReferenceEntity(uuid);
        removeNotificationInstance(notificationInstanceRef);
    }

    @Override
    public List<DataAttribute> listMappingAttributes(String connectorUuid, String kind) throws ConnectorException, NotFoundException {
        ConnectorDto connector = connectorService.getConnector(SecuredUUID.fromString(connectorUuid));
        return connectorApiFactory.getNotificationInstanceApiClient(connector).listMappingAttributes(connector, kind);
    }

    private NotificationInstanceReference getNotificationInstanceReferenceEntity(UUID uuid) throws NotFoundException {
        return notificationInstanceReferenceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(NotificationInstanceReference.class, uuid));
    }

    private NotificationProviderInstanceDto saveNotificationProviderInstance(UUID uuid, NotificationInstanceUpdateRequestDto request, String kind, String name, ConnectorApiClientDto connector) throws ConnectorException, AttributeException, NotFoundException {
        connectorService.mergeAndValidateAttributes(SecuredUUID.fromString(connector.getUuid()), FunctionGroupCode.NOTIFICATION_PROVIDER, request.getAttributes(), kind);

        // Load complete credential data
        var dataAttributes = attributeEngine.getDataAttributesByContent(UUID.fromString(connector.getUuid()), request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);

        NotificationProviderInstanceRequestDto notificationInstanceDto = new NotificationProviderInstanceRequestDto();
        notificationInstanceDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
        notificationInstanceDto.setKind(kind);
        notificationInstanceDto.setName(name);

        return uuid == null ? connectorApiFactory.getNotificationInstanceApiClient(connector).createNotificationInstance(connector,
                notificationInstanceDto) : connectorApiFactory.getNotificationInstanceApiClient(connector).updateNotificationInstance(connector,
                uuid.toString(),
                notificationInstanceDto);
    }

    private void updateMappedAttributes(NotificationInstanceReference savedInstance, List<AttributeMappingDto> attributeMappings) {
        List<NotificationInstanceMappedAttributes> mappedAttributes = new ArrayList<>();

        if (attributeMappings != null) {
            for (AttributeMappingDto attributeMapping : attributeMappings) {
                NotificationInstanceMappedAttributes mappedAttribute = new NotificationInstanceMappedAttributes();
                mappedAttribute.setNotificationInstanceRefUuid(savedInstance.getUuid());
                mappedAttribute.setAttributeDefinitionUuid(UUID.fromString(attributeMapping.getCustomAttributeUuid()));
                mappedAttribute.setMappingAttributeUuid(UUID.fromString(attributeMapping.getMappingAttributeUuid()));
                mappedAttribute.setMappingAttributeName(attributeMapping.getMappingAttributeName());
                mappedAttributes.add(mappedAttribute);
            }
        }

        savedInstance.setMappedAttributes(mappedAttributes);
    }

    private void removeNotificationInstance(NotificationInstanceReference notificationInstanceRef) throws ValidationException {
        if (notificationInstanceRef.getConnector() != null) {
            try {
                ConnectorApiClientDto connectorDto = notificationInstanceRef.getConnector().mapToApiClientDtoV1();
                connectorApiFactory.getNotificationInstanceApiClient(connectorDto).removeNotificationInstance(connectorDto,
                        notificationInstanceRef.getNotificationInstanceUuid().toString());
            } catch (ConnectorEntityNotFoundException notFoundException) {
                logger.warn("Notification is already deleted in the connector. Proceeding to remove it from the core");
            } catch (Exception e) {
                throw new ValidationException("Error in delete of notification instance: " + e.getMessage());
            }
        } else {
            logger.debug("Deleting notification without connector: {}", notificationInstanceRef);
        }

        // check notification profiles referencing notification instance
        Long referencesCount = notificationProfileVersionRepository.countByNotificationInstanceRefUuid(notificationInstanceRef.getUuid());
        if (referencesCount > 0) {
            throw new ValidationException("Cannot delete notification instance. %d notification profile version(s) are referencing this notification instance".formatted(referencesCount));
        }

        notificationInstanceReferenceRepository.delete(notificationInstanceRef);
    }
}
