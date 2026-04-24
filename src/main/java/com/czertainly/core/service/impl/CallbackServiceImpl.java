package com.czertainly.core.service.impl;

import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.cryptography.key.KeyRequestType;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.common.DataAttribute;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallback;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.czertainly.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.core.auth.AttributeResource;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.api.model.core.connector.ConnectorApiClientDto;
import com.czertainly.api.model.core.connector.v2.ConnectorDetailDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeVersionHelper;
import com.czertainly.core.dao.entity.AuthorityInstanceReference;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.EntityInstanceReference;
import com.czertainly.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.czertainly.core.dao.repository.EntityInstanceReferenceRepository;
import com.czertainly.core.logging.LoggingHelper;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.*;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Transactional
public class CallbackServiceImpl implements CallbackService {

    private static final Logger logger = LoggerFactory.getLogger(CallbackServiceImpl.class);

    private ConnectorService connectorService;
    private ConnectorApiFactory connectorApiFactory;
    private CoreCallbackService coreCallbackService;
    private CredentialService credentialService;
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    private CryptographicKeyService cryptographicKeyService;
    private TokenProfileService tokenProfileService;
    private AttributeEngine attributeEngine;
    private ResourceService resourceService;

    @Autowired
    public void setResourceService(ResourceService resourceService) {
        this.resourceService = resourceService;
    }

    @Autowired
    public void setConnectorService(ConnectorService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setCoreCallbackService(CoreCallbackService coreCallbackService) {
        this.coreCallbackService = coreCallbackService;
    }

    @Autowired
    public void setCredentialService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @Autowired
    public void setAuthorityInstanceReferenceRepository(AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository) {
        this.authorityInstanceReferenceRepository = authorityInstanceReferenceRepository;
    }

    @Autowired
    public void setEntityInstanceReferenceRepository(EntityInstanceReferenceRepository entityInstanceReferenceRepository) {
        this.entityInstanceReferenceRepository = entityInstanceReferenceRepository;
    }

    @Autowired
    public void setCryptographicKeyService(CryptographicKeyService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @Autowired
    public void setTokenProfileService(TokenProfileService tokenProfileService) {
        this.tokenProfileService = tokenProfileService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.ANY)
    public Object callback(String uuid, FunctionGroupCode functionGroup, String kind, RequestAttributeCallback callback) throws ConnectorException, ValidationException, NotFoundException, AttributeException {
        ConnectorDetailDto connector = connectorService.getConnector(SecuredUUID.fromString(uuid));
        List<BaseAttribute> definitions = connectorApiFactory.getAttributeApiClient(connector).listAttributeDefinitions(connector, functionGroup, kind);
        return getCallbackObject(callback, definitions, connector);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.ANY)
    public Object callback(UUID connectorUuid, RequestAttributeCallback callback) throws NotFoundException, ConnectorException, AttributeException {
        ConnectorDetailDto connector = connectorService.getConnector(SecuredUUID.fromUUID(connectorUuid));
        return getCallbackObject(callback, null, connector);
    }

    private Object getCallbackObject(RequestAttributeCallback callback, List<BaseAttribute> definitions, ConnectorDetailDto connector) throws NotFoundException, ConnectorException, AttributeException {
        UUID connectorUuid = UUID.fromString(connector.getUuid());
        BaseAttribute attribute = getBaseAttribute(callback, definitions, connectorUuid);

        AttributeCallback attributeCallback = getAttributeCallback(attribute);

        AttributeResource attributeResource = getAttributeResource(attribute);
        AttributeDefinitionUtils.validateCallback(attributeCallback, callback, attributeResource != null);

        if (Objects.equals(attributeCallback.getCallbackContext(), "core/getCredentials")) {
            return coreCallbackService.coreGetCredentials(callback);
        }

        if (attribute instanceof DataAttribute dataAttribute && dataAttribute.getContentType() == AttributeContentType.RESOURCE) {
            return coreCallbackService.coreGetResources(callback, attributeResource);
        }

        // Load complete credential data for mapping of type credential
        credentialService.loadFullCredentialData(attributeCallback, callback);
        if (attribute.getType() == AttributeType.DATA && callback.getBody() != null) {
            Map<String, AttributeResource> toResource = new HashMap<>();
            for (String to : callback.getBody().keySet()) {
                AttributeCallbackMapping callbackMapping = attributeCallback.getMappings().stream().filter(attributeCallbackMapping -> attributeCallbackMapping.getTo().equals(to)).findFirst().orElse(null);
                if (callbackMapping != null && callbackMapping.getFrom() != null) {
                    String fromAttributeName = callbackMapping.getFrom().split("\\.", 2)[0];
                    DataAttribute fromAttribute = getFromAttribute(definitions, connectorUuid, fromAttributeName);
                    toResource.put(to, fromAttribute.getProperties().getResource());
                }
            }
            resourceService.loadResourceObjectContentData(attributeCallback, callback, toResource);
        }

        Object response = connectorApiFactory.getAttributeApiClient(connector).attributeCallback(connector, attributeCallback, callback);
        if (attribute.getType().equals(AttributeType.GROUP)) {
            processGroupAttributes(connectorUuid, response);
        }
        return response;
    }

    private DataAttribute getFromAttribute(List<BaseAttribute> definitions, UUID connectorUuid, String fromAttributeName) throws NotFoundException {
        DataAttribute fromAttribute;
        if (definitions == null || definitions.isEmpty()) {
            fromAttribute = attributeEngine.getDataAttributeDefinition(connectorUuid, fromAttributeName);
            if (fromAttribute == null) {
                throw new NotFoundException("Attribute definition '" + fromAttributeName + "' not found for connector " + connectorUuid);
            }
        } else {
            fromAttribute = (DataAttribute) getAttributeByName(fromAttributeName, definitions, connectorUuid);
        }
        return fromAttribute;
    }

    private BaseAttribute getBaseAttribute(RequestAttributeCallback callback, List<BaseAttribute> definitions, UUID connectorUuid) throws NotFoundException {
        BaseAttribute attribute;
        if (definitions != null && !definitions.isEmpty()) {
            attribute = getAttributeByName(callback.getName(), definitions, connectorUuid);
        } else {
            attribute = getBaseAttributeFromExistingDefinition(callback, connectorUuid);
        }
        return attribute;
    }

    private BaseAttribute getBaseAttributeFromExistingDefinition(RequestAttributeCallback callback, UUID connectorUuid) throws NotFoundException {
        BaseAttribute attribute;
        attribute = attributeEngine.getDataAttributeDefinition(connectorUuid, callback.getName());
        if (attribute == null) {
            attribute = attributeEngine.getGroupAttributeDefinition(connectorUuid, callback.getName());
            if (attribute == null) {
                throw new NotFoundException(BaseAttribute.class, callback.getName());
            }
        }
        return attribute;
    }

    private AttributeResource getAttributeResource(BaseAttribute attribute) {
        return attribute instanceof DataAttribute dataAttribute ? dataAttribute.getProperties().getResource() : null;
    }

    @Override
    public Object resourceCallback(Resource resource, String resourceUuid, RequestAttributeCallback callback) throws ConnectorException, ValidationException, NotFoundException, AttributeException {
        List<BaseAttribute> definitions = null;
        Connector connector = null;
        switch (resource) {
            case RA_PROFILE:
                AuthorityInstanceReference authorityInstance = authorityInstanceReferenceRepository.findByUuid(
                                UUID.fromString(resourceUuid))
                        .orElseThrow(
                                () -> new NotFoundException(
                                        AuthorityInstanceReference.class,
                                        resourceUuid
                                )
                        );
                connector = authorityInstance.getConnector();
                ConnectorApiClientDto raProfileConnectorDto = connector.mapToApiClientDtoV1();
                definitions = connectorApiFactory.getAuthorityInstanceApiClient(raProfileConnectorDto).listRAProfileAttributes(
                        raProfileConnectorDto,
                        authorityInstance.getAuthorityInstanceUuid()
                );
                break;

            case CRYPTOGRAPHIC_KEY:
                connector =
                        tokenProfileService.getTokenProfileEntity(
                                SecuredUUID.fromString(
                                        resourceUuid
                                )
                        ).getTokenInstanceReference().getConnector();
                definitions = cryptographicKeyService.listCreateKeyAttributes(
                        null,
                        SecuredParentUUID.fromString(
                                resourceUuid
                        ),
                        KeyRequestType.KEY_PAIR
                );
                break;

            case LOCATION:
                EntityInstanceReference entityInstance = entityInstanceReferenceRepository.findByUuid(UUID.fromString(resourceUuid))
                        .orElseThrow(
                                () -> new NotFoundException(
                                        EntityInstanceReference.class,
                                        resourceUuid
                                )
                        );
                connector = entityInstance.getConnector();
                ConnectorApiClientDto locationConnectorDto = connector.mapToApiClientDtoV1();
                definitions = connectorApiFactory.getEntityInstanceApiClient(locationConnectorDto).listLocationAttributes(locationConnectorDto, entityInstance.getEntityInstanceUuid());
                break;

            default:
                throw new ValidationException(
                        ValidationError.create(
                                "Callback for the requested resource is not supported"
                        )
                );
        }

        LoggingHelper.putLogResourceInfo(Resource.CONNECTOR, true, connector.getUuid().toString(), connector.getName());
        return getCallbackObject(callback, definitions, connector.mapToDetailDto());
    }

    private AttributeCallback getAttributeCallback(BaseAttribute attribute) {
        AttributeType type = attribute.getType();
        if (Objects.requireNonNull(type) == AttributeType.DATA) {
            return ((DataAttribute) attribute).getAttributeCallback();
        } else if (type == AttributeType.GROUP) {
            return AttributeVersionHelper.getGroupAttributeCallback(attribute);
        }
        throw new IllegalArgumentException("Attribute %s is not of type DATA or GROUP, cannot get callback for this attribute".formatted(attribute.getName()));
    }

    private BaseAttribute getAttributeByName(String name, List<BaseAttribute> attributes, UUID connectorUuid) throws NotFoundException {
        for (BaseAttribute attributeDefinition : attributes) {
            if (attributeDefinition.getName().equals(name)) {
                return attributeDefinition;
            }
        }

        // if not present in definitions from connector, search in reference attributes in DB
        DataAttribute referencedAttribute = attributeEngine.getDataAttributeDefinition(connectorUuid, name);
        if (referencedAttribute != null) {
            return referencedAttribute;
        }

        throw new NotFoundException(BaseAttribute.class, name);
    }

    /**
     * Function to check the response for callback and store the data in the database.
     */
    private void processGroupAttributes(UUID connectorUuid, Object callbackResponse) {
        // When the callback is retrieved from the connector, and of the type of the attribute triggering the
        // callback is GROUP, then the response is expected to be list of other attributes. In that case,
        // We are not able to merge the attributes since these attributes will not be available as part of the list attribute
        // response.
        // This method will take the attribute definition and store it in the database. In the other methods where there
        // group attributes, we can retrieve them and merge them with the code.
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        try {
            List<BaseAttribute> callbackAttributes = mapper.convertValue(callbackResponse, mapper.getTypeFactory().constructCollectionType(List.class, BaseAttribute.class));
            attributeEngine.updateDataAttributeDefinitions(connectorUuid, null, callbackAttributes);
        } catch (Exception e) {
            logger.debug("Failed to create the reference attributes. Exception is {}", e.getMessage());
        }
    }
}
