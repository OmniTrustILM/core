package com.otilm.core.service.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.api.exception.*;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallback;
import com.otilm.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.otilm.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.core.auth.AttributeResource;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.client.connector.v2.attribute.ScopedAttributes;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeReferenceExpander;
import com.otilm.core.attribute.engine.AttributeVersionHelper;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.EntityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.EntityInstanceReferenceRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.service.callback.AttributeCallbackScopeResolver;
import com.otilm.core.service.callback.NgCallbackDispatcher;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.*;
import com.otilm.core.service.v2.ConnectorService;
import com.otilm.core.util.AttributeDefinitionUtils;
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
public class CallbackServiceImpl implements CallbackExternalService {

    private static final Logger logger = LoggerFactory.getLogger(CallbackServiceImpl.class);

    private ConnectorService connectorService;
    private ConnectorApiFactory connectorApiFactory;
    private CoreCallbackService coreCallbackService;
    private CredentialInternalService credentialService;
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    private RaProfileRepository raProfileRepository;
    private CryptographicKeyService cryptographicKeyService;
    private TokenProfileInternalService tokenProfileService;
    private AttributeEngine attributeEngine;
    private ResourceInternalService resourceService;
    private AttributeCallbackScopeResolver scopeResolver;
    private NgCallbackDispatcher ngCallbackDispatcher;
    private AttributeReferenceExpander attributeReferenceExpander;

    @Autowired
    public void setScopeResolver(AttributeCallbackScopeResolver scopeResolver) {
        this.scopeResolver = scopeResolver;
    }

    @Autowired
    public void setNgCallbackDispatcher(NgCallbackDispatcher ngCallbackDispatcher) {
        this.ngCallbackDispatcher = ngCallbackDispatcher;
    }

    @Autowired
    public void setAttributeReferenceExpander(AttributeReferenceExpander attributeReferenceExpander) {
        this.attributeReferenceExpander = attributeReferenceExpander;
    }

    @Autowired
    public void setResourceService(ResourceInternalService resourceService) {
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
    public void setCredentialService(CredentialInternalService credentialService) {
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
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setCryptographicKeyService(CryptographicKeyService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @Autowired
    public void setTokenProfileService(TokenProfileInternalService tokenProfileService) {
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
        // Connector-level entrypoints carry no form/resource context, so no scope coordinates and no
        // connectorInterface to stamp. The form-context NG paths (resourceCallback) stamp connectorInterface per
        // resource. NG callbacks are a form-driven flow (resourceCallback), not the bare connector-level path.
        return getCallbackObject(callback, definitions, connector, null, null, null, null);
    }

    private Object getCallbackObject(RequestAttributeCallback callback, List<BaseAttribute> definitions, ConnectorDetailDto connector,
                                     Resource scopeResource, UUID scopeResourceUuid, ConnectorInterface connectorInterface,
                                     String interfaceVersion) throws NotFoundException, ConnectorException, AttributeException {
        UUID connectorUuid = UUID.fromString(connector.getUuid());
        BaseAttribute attribute = getBaseAttribute(callback, definitions, connectorUuid);

        AttributeCallback attributeCallback = getAttributeCallback(attribute);

        AttributeResource attributeResource = getAttributeResource(attribute);

        // NG (dependsOn) dispatch: routed only when the definition declares a dependsOn callback and carries no
        // legacy callbackContext. It is checked BEFORE the legacy callback validation because the NG shape has no
        // callbackContext/callbackMethod (which AttributeDefinitionUtils.validateCallback requires); the NG
        // declaration is validated at ingest instead (#1622 Task 4b). Both-set is rejected at ingest, so the
        // callbackContext == null conjunct here is defensive. Legacy callbacks fall through unchanged.
        if (isNgCallback(attributeCallback)) {
            return dispatchNg(connector, attribute, callback, scopeResource, scopeResourceUuid, connectorInterface, interfaceVersion);
        }

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
        // Prefer the referenced attributeUuid when it actually identifies a stored (attributeUuid, name) row: a
        // non-unique (type, connector, name) must not silently pick the wrong row on the initial dispatch (C6).
        // Fall back to deterministic name-only resolution when no uuid is given OR the uuid does not match a row
        // (RequestAttributeCallback.uuid is overloaded — some legacy callers put the connector uuid there).
        String name = callback.getName();
        UUID attributeUuid = parseUuidOrNull(callback.getUuid());
        BaseAttribute attribute = null;
        if (attributeUuid != null) {
            attribute = attributeEngine.getDataAttributeDefinitionStrict(connectorUuid, attributeUuid, name);
            if (attribute == null) {
                attribute = attributeEngine.getGroupAttributeDefinitionStrict(connectorUuid, attributeUuid, name);
            }
        }
        if (attribute == null) {
            attribute = attributeEngine.getDataAttributeDefinition(connectorUuid, name);
            if (attribute == null) {
                attribute = attributeEngine.getGroupAttributeDefinition(connectorUuid, name);
            }
        }
        if (attribute == null) {
            throw new NotFoundException(BaseAttribute.class, name);
        }
        return attribute;
    }

    private static UUID parseUuidOrNull(String value) {
        if (value == null) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private AttributeResource getAttributeResource(BaseAttribute attribute) {
        return attribute instanceof DataAttribute dataAttribute ? dataAttribute.getProperties().getResource() : null;
    }

    private static boolean isNgCallback(AttributeCallback attributeCallback) {
        return attributeCallback.getDependsOn() != null && !attributeCallback.getDependsOn().isEmpty()
                && attributeCallback.getCallbackContext() == null;
    }

    /**
     * Assemble the NG dispatch context and hand off to the {@link NgCallbackDispatcher} collaborator bean,
     * which performs the connector POST outside any transaction. {@code currentAttributes} are the values
     * supplied with the callback (the dependsOn-named attributes), expanded per the calling user via the same
     * {@link AttributeReferenceExpander} used for the scope chain.
     */
    private Object dispatchNg(ConnectorDetailDto connector, BaseAttribute attribute,
                              RequestAttributeCallback callback, Resource scopeResource, UUID scopeResourceUuid,
                              ConnectorInterface connectorInterface, String interfaceVersion)
            throws NotFoundException, ConnectorException, AttributeException {
        // The scope chain is resolved HERE (not in resourceCallback) so legacy callbacks never pay its per-object
        // DETAIL authorization. One accumulator spans the scope chain + currentAttributes expansion so the
        // dispatcher can reject a connector echoing any server-expanded secret back toward the FE (#1624 containment).
        Set<String> expandedSecrets = new HashSet<>();
        List<ScopedAttributes> contextAttributes = scopeResource == null
                ? List.of()
                : scopeResolver.resolveScopeChain(scopeResource, scopeResourceUuid, expandedSecrets);
        List<RequestAttribute> currentAttributes = callback.getAttributes();
        if (currentAttributes != null && !currentAttributes.isEmpty()) {
            attributeReferenceExpander.expandForCaller(currentAttributes, expandedSecrets);
        }
        NgCallbackDispatcher.NgDispatchContext context = new NgCallbackDispatcher.NgDispatchContext(
                attribute, connectorInterface, interfaceVersion, contextAttributes, currentAttributes);
        AttributeCallbackResponseDto response = ngCallbackDispatcher.dispatchNgCallback(connector, context, callback, expandedSecrets);
        return response.getContent() != null ? response.getContent() : response.getAttributes();
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.LIST)
    public Object resourceCallback(Resource resource, String resourceUuid, RequestAttributeCallback callback) throws ConnectorException, ValidationException, NotFoundException, AttributeException {
        List<BaseAttribute> definitions = null;
        Connector connector = null;
        ConnectorInterface connectorInterface = null;
        String interfaceVersion = null;
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
                connectorInterface = interfaceCodeOf(authorityInstance);
                interfaceVersion = interfaceVersionOf(authorityInstance);
                // v3 authorities have a null authorityInstanceUuid (never set on the v3 create path), so the v1
                // listRAProfileAttributes call would pass null and break. Route them through the NG scope
                // resolver + dispatcher instead; legacy (v1/v2) authorities keep the exact v1 call below.
                if (!isV3Authority(authorityInstance)) {
                    ApiClientConnectorInfo raProfileConnectorDto = connectorService.getConnectorForApiClient(connector.getUuid());
                    definitions = connectorApiFactory.getAuthorityInstanceApiClient(raProfileConnectorDto).listRAProfileAttributes(
                            raProfileConnectorDto,
                            authorityInstance.getAuthorityInstanceUuid()
                    );
                }
                break;

            case CERTIFICATE:
                // Issuance scope (NG-only): the FE issuance form sends (CERTIFICATE, raProfile). Resolve the
                // connector via the raProfile -> authority chain, consistent with the scope walker
                // (walkCertificateIssuance). Inert until FE #1764; the scope chain is resolved by the NG path below.
                RaProfile issuanceRaProfile = raProfileRepository.findByUuid(UUID.fromString(resourceUuid))
                        .orElseThrow(() -> new NotFoundException(RaProfile.class, resourceUuid));
                AuthorityInstanceReference issuanceAuthority = issuanceRaProfile.getAuthorityInstanceReference();
                if (issuanceAuthority == null) {
                    throw new NotFoundException(AuthorityInstanceReference.class, resourceUuid);
                }
                connector = issuanceAuthority.getConnector();
                connectorInterface = interfaceCodeOf(issuanceAuthority);
                interfaceVersion = interfaceVersionOf(issuanceAuthority);
                break;

            case TOKEN_PROFILE:
                // TOKEN_PROFILE is sent by the FE today but had no switch arm (it threw "not supported"). Route
                // it via the token-profile -> token-instance FK like CRYPTOGRAPHIC_KEY; the NG scope chain (when
                // the definition declares dependsOn) is resolved below.
                connector = tokenProfileService.getTokenProfileEntity(SecuredUUID.fromString(resourceUuid))
                        .getTokenInstanceReference().getConnector();
                connectorInterface = ConnectorInterface.CRYPTOGRAPHY;
                break;

            case CRYPTOGRAPHIC_KEY:
                connector =
                        tokenProfileService.getTokenProfileEntity(
                                SecuredUUID.fromString(
                                        resourceUuid
                                )
                        ).getTokenInstanceReference().getConnector();
                connectorInterface = ConnectorInterface.CRYPTOGRAPHY;
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
                connectorInterface = ConnectorInterface.ENTITY;
                ApiClientConnectorInfo locationConnectorDto = connectorService.getConnectorForApiClient(connector.getUuid());
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
        // The scope chain is resolved lazily inside the NG branch (dispatchNg) so legacy callbacks never pay its
        // per-object DETAIL authorization; pass the scope coordinates rather than a pre-resolved chain.
        return getCallbackObject(callback, definitions, connector.mapToDetailDto(), resource, UUID.fromString(resourceUuid), connectorInterface, interfaceVersion);
    }

    /**
     * Local v3-authority predicate. Mirrors {@code AuthorityInstanceServiceImpl.isV3} byte-for-byte but lives
     * here so #1621 does not have to edit the authority-v3 team's file (avoids a merge conflict on in-flight
     * work). Reads the connector-interface version directly off the reference entity.
     */
    private static boolean isV3Authority(AuthorityInstanceReference ref) {
        ConnectorInterfaceEntity iface = ref.getConnectorInterface();
        return iface != null && "v3".equals(iface.getVersion());
    }

    private static String interfaceVersionOf(AuthorityInstanceReference ref) {
        ConnectorInterfaceEntity iface = ref.getConnectorInterface();
        return iface == null ? null : iface.getVersion();
    }

    /**
     * The connector-interface code the authority's attributes belong to (Core-stamped envelope context, not
     * routing). The envelope DTO marks {@code connectorInterface} required; sourcing it from the authority's
     * own {@link ConnectorInterfaceEntity} keeps it accurate for the authority-backed NG paths.
     */
    private static ConnectorInterface interfaceCodeOf(AuthorityInstanceReference ref) {
        ConnectorInterfaceEntity iface = ref.getConnectorInterface();
        return iface == null ? null : iface.getInterfaceCode();
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
