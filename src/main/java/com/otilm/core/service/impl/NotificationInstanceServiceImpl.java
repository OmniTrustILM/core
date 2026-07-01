package com.otilm.core.service.impl;

import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.connector.notification.NotificationProviderInstanceDto;
import com.otilm.api.model.connector.notification.NotificationProviderInstanceRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.notification.AttributeMappingDto;
import com.otilm.api.model.core.notification.NotificationInstanceDto;
import com.otilm.api.model.core.notification.NotificationInstanceRequestDto;
import com.otilm.api.model.core.notification.NotificationInstanceUpdateRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.notifications.NotificationInstanceMappedAttributes;
import com.otilm.core.dao.entity.notifications.NotificationInstanceReference;
import com.otilm.core.dao.repository.notifications.NotificationInstanceMappedAttributeRepository;
import com.otilm.core.dao.repository.notifications.NotificationInstanceReferenceRepository;
import com.otilm.core.dao.repository.notifications.NotificationProfileVersionRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.AnyPrincipalEndpoint;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.ConnectorExternalService;
import com.otilm.core.service.ConnectorInternalService;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.NotificationInstanceExternalService;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.service.writer.NotificationProfileVersionWriter;
import com.otilm.core.util.AttributeDefinitionUtils;
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
public class NotificationInstanceServiceImpl implements NotificationInstanceExternalService {
    private static final Logger logger = LoggerFactory.getLogger(NotificationInstanceServiceImpl.class);

    private NotificationInstanceReferenceRepository notificationInstanceReferenceRepository;
    private NotificationInstanceMappedAttributeRepository notificationInstanceMappedAttributeRepository;
    private NotificationProfileVersionRepository notificationProfileVersionRepository;

    private ConnectorExternalService connectorService;
    private ConnectorInternalService connectorInternalService;
    private CredentialInternalService credentialService;
    private ConnectorApiFactory connectorApiFactory;
    private AttributeEngine attributeEngine;
    private NotificationProfileVersionWriter notificationProfileVersionWriter;

    private ResourceInternalService resourceService;

    @Autowired
    public void setNotificationProfileVersionWriter(NotificationProfileVersionWriter notificationProfileVersionWriter) {
        this.notificationProfileVersionWriter = notificationProfileVersionWriter;
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
    public void setConnectorService(ConnectorExternalService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setConnectorInternalService(ConnectorInternalService connectorInternalService) {
        this.connectorInternalService = connectorInternalService;
    }

    @Autowired
    public void setCredentialService(CredentialInternalService credentialService) {
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

        ApiClientConnectorInfo connectorDto = connectorInternalService.getConnectorForApiClient(notificationInstanceReference.getConnectorUuid());
        NotificationProviderInstanceDto notificationProviderInstanceDto;
        try {
            notificationProviderInstanceDto = connectorApiFactory.getNotificationInstanceApiClient(connectorDto).getNotificationInstance(
                    connectorDto,
                    notificationInstanceReference.getNotificationInstanceUuid().toString());
        } catch (ConnectorEntityNotFoundException e) {
            notificationInstanceDto.setName(notificationInstanceReference.getName() + " (Orphaned)");
            notificationInstanceDto.setAttributes(attributes);
            logger.warn("Notification Instance {} is not present in the connector.", notificationInstanceReference.getName());
            return notificationInstanceDto;
        }

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
                connectorInternalService.getConnectorForApiClient(notificationInstanceRef.getConnectorUuid()));

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
    @AnyPrincipalEndpoint
    public List<DataAttribute> listMappingAttributes(String connectorUuid, String kind) throws ConnectorException, NotFoundException {
        ConnectorDto connector = connectorService.getConnector(SecuredUUID.fromString(connectorUuid));
        return connectorApiFactory.getNotificationInstanceApiClient(connector).listMappingAttributes(connector, kind);
    }

    private NotificationInstanceReference getNotificationInstanceReferenceEntity(UUID uuid) throws NotFoundException {
        return notificationInstanceReferenceRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(NotificationInstanceReference.class, uuid));
    }

    private NotificationProviderInstanceDto saveNotificationProviderInstance(UUID uuid, NotificationInstanceUpdateRequestDto request, String kind, String name, ApiClientConnectorInfo connector) throws ConnectorException, AttributeException, NotFoundException {
        connectorInternalService.mergeAndValidateAttributes(SecuredUUID.fromString(connector.getUuid()), FunctionGroupCode.NOTIFICATION_PROVIDER, request.getAttributes(), kind);

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
        // Read before writing: check current-version references that block deletion.
        List<String> blockingProfiles = notificationProfileVersionRepository
                .findCurrentVersionProfileNamesByNotificationInstanceRefUuid(notificationInstanceRef.getUuid());
        if (!blockingProfiles.isEmpty()) {
            throw new ValidationException(
                    "Cannot delete notification instance. Notification profile(s) referencing this notification instance: "
                            + String.join(", ", blockingProfiles));
        }

        if (notificationInstanceRef.getConnector() != null) {
            try {
                ApiClientConnectorInfo connectorDto = connectorInternalService.getConnectorForApiClient(notificationInstanceRef.getConnectorUuid());
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

        // At this point, the notification instance is orphaned and no longer linked to any current profile version, but there might still be historical profile versions linked to it.
        // Detach the instance from all historical versions to maintain data integrity, since there is no way to update previous versions to remove the instance.
        int detachedCount = notificationProfileVersionWriter.detachNotificationInstanceRefUuid(notificationInstanceRef.getUuid());
        logger.debug("Detached {} notification profile version(s) from notification instance {}", detachedCount, notificationInstanceRef.getName());

        notificationInstanceReferenceRepository.delete(notificationInstanceRef);
    }
}
