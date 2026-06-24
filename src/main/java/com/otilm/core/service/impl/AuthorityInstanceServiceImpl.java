package com.otilm.core.service.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.api.exception.*;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.authority.AuthorityInstanceRequestDto;
import com.otilm.api.model.client.authority.AuthorityInstanceUpdateRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndIdDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;

import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.connector.authority.AuthorityProviderInstanceDto;
import com.otilm.api.model.connector.authority.AuthorityProviderInstanceRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.authority.AuthorityInstanceDto;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.connector.FunctionGroupDto;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.*;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import com.otilm.core.util.AttributeDefinitionUtils;
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
public class AuthorityInstanceServiceImpl implements AuthorityInstanceExternalService, AuthorityInstanceInternalService, AttributeResourceService {
    private static final Logger logger = LoggerFactory.getLogger(AuthorityInstanceServiceImpl.class);

    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    private ConnectorService connectorService;
    private CredentialInternalService credentialService;
    private ConnectorApiFactory connectorApiFactory;
    private RaProfileService raProfileService;
    private AttributeEngine attributeEngine;
    private ResourceInternalService resourceService;
    private ConnectorRepository connectorRepository;
    private AuthorityProviderAdapterFactory adapterFactory;

    @Autowired
    public void setResourceService(ResourceInternalService resourceService) {
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
    public void setCredentialService(CredentialInternalService credentialService) {
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

    @Autowired
    public void setConnectorRepository(ConnectorRepository connectorRepository) {
        this.connectorRepository = connectorRepository;
    }

    @Autowired
    public void setAdapterFactory(AuthorityProviderAdapterFactory adapterFactory) {
        this.adapterFactory = adapterFactory;
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.LIST)
    public List<AuthorityInstanceDto> listAuthorityInstances(SecurityFilter filter) {
        // fetch-join connectorInterface so mapToDto does not lazy-load it per row (avoids N+1)
        return authorityInstanceReferenceRepository.findUsingSecurityFilter(filter, List.of(AuthorityInstanceReference_.CONNECTOR_INTERFACE), null)
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

        if (isV3(authorityInstanceReference.getConnectorInterface())) {
            // v3 is stateless — no connector-side instance to fetch; local data attributes are authoritative
            authorityInstanceDto.setAttributes(attributes);
            return authorityInstanceDto;
        }

        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(authorityInstanceReference.getConnectorUuid());
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
    public AuthorityInstanceDto createAuthorityInstance(AuthorityInstanceRequestDto request) throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
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
        // Resolve the interface BEFORE attribute validation so v3 authorities validate against
        // the v3 attribute endpoint, not the legacy v1 function-group path.
        ConnectorInterfaceEntity iface = resolveAuthorityInterface(connectorUuid.getValue(), request.getInterfaceUuid());
        AuthorityInstanceReference probeRef = transientAuthorityRef(connectorUuid, connector, iface, request.getKind());
        attributeEngine.validateCustomAttributesContent(Resource.AUTHORITY, request.getCustomAttributes());
        mergeAndValidateAuthorityAttributes(probeRef, iface, codeToSearch, request.getAttributes(), request.getKind());

        // Load complete credential data and resource data
        var dataAttributes = attributeEngine.getDataAttributesByContent(connectorUuid.getValue(), request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);

        if (isV3(iface)) {
            return createV3Authority(request, probeRef, dataAttributes);
        }

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
        if (iface != null) {
            authorityInstanceRef.setConnectorInterface(iface);
        }
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
        ConnectorInterfaceEntity iface = authorityInstanceRef.getConnectorInterface();
        attributeEngine.validateCustomAttributesContent(Resource.AUTHORITY, request.getCustomAttributes());
        mergeAndValidateAuthorityAttributes(authorityInstanceRef, iface, codeToSearch, request.getAttributes(), ref.getKind());

        // Load complete credential data
        var dataAttributes = attributeEngine.getDataAttributesByContent(authorityInstanceRef.getConnectorUuid(), request.getAttributes());
        credentialService.loadFullCredentialData(dataAttributes);
        resourceService.loadResourceObjectContentData(dataAttributes);

        if (isV3(iface)) {
            // v3 is stateless: no updateAuthorityInstance endpoint — re-probe connectivity with
            // the new attributes; persisting the attribute content below is the actual update.
            adapterFactory.forAuthority(authorityInstanceRef)
                    .checkAuthorityConnection(authorityInstanceRef, AttributeDefinitionUtils.getClientAttributes(dataAttributes));
        } else {
            AuthorityProviderInstanceRequestDto authorityInstanceDto = new AuthorityProviderInstanceRequestDto();
            authorityInstanceDto.setKind(ref.getKind());
            authorityInstanceDto.setName(ref.getName());
            authorityInstanceDto.setAttributes(AttributeDefinitionUtils.getClientAttributes(dataAttributes));
            connectorApiFactory.getAuthorityInstanceApiClient(connector).updateAuthorityInstance(connector,
                    authorityInstanceRef.getAuthorityInstanceUuid(), authorityInstanceDto);
        }
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
        if (isV3(authorityInstanceRef.getConnectorInterface())) {
            return List.of(); // v3 authorities do not use the EJBCA end-entity-profile model
        }
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(authorityInstanceRef.getConnectorUuid());

        return connectorApiFactory.getEndEntityProfileApiClient(connectorDto).listEndEntityProfiles(connectorDto,
                authorityInstanceRef.getAuthorityInstanceUuid());
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DETAIL)
    public List<NameAndIdDto> listCertificateProfiles(SecuredUUID uuid, Integer endEntityProfileId) throws ConnectorException, NotFoundException {
        AuthorityInstanceReference authorityInstanceRef = getAuthorityInstanceReferenceEntity(uuid);
        if (isV3(authorityInstanceRef.getConnectorInterface())) {
            return List.of();
        }
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(authorityInstanceRef.getConnectorUuid());

        return connectorApiFactory.getEndEntityProfileApiClient(connectorDto).listCertificateProfiles(connectorDto,
                authorityInstanceRef.getAuthorityInstanceUuid(), endEntityProfileId);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.DETAIL)
    public List<NameAndIdDto> listCAsInProfile(SecuredUUID uuid, Integer endEntityProfileId) throws ConnectorException, NotFoundException {
        AuthorityInstanceReference authorityInstanceRef = getAuthorityInstanceReferenceEntity(uuid);
        if (isV3(authorityInstanceRef.getConnectorInterface())) {
            return List.of();
        }
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(authorityInstanceRef.getConnectorUuid());

        return connectorApiFactory.getEndEntityProfileApiClient(connectorDto).listCAsInProfile(connectorDto,
                authorityInstanceRef.getAuthorityInstanceUuid(), endEntityProfileId);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.ANY)
    public List<BaseAttribute> listRAProfileAttributes(SecuredUUID uuid) throws ConnectorException, NotFoundException {
        AuthorityInstanceReference authorityInstance = getAuthorityInstanceReferenceEntity(uuid);
        return adapterFactory.forAuthority(authorityInstance).listRaProfileAttributes(authorityInstance);
    }

    @Override
    @ExternalAuthorization(resource = Resource.AUTHORITY, action = ResourceAction.ANY)
    public Boolean validateRAProfileAttributes(SecuredUUID uuid, List<RequestAttribute> attributes) throws ConnectorException, AttributeException, NotFoundException {
        AuthorityInstanceReference authorityInstance = getAuthorityInstanceReferenceEntity(uuid);
        if (isV3(authorityInstance.getConnectorInterface())) {
            // v3 is stateless: validate locally against the listed RA-profile definitions. Invalid
            // content throws ValidationException and a definition/schema failure throws
            // AttributeException — both surface to the caller, matching the v2 connector-validate path.
            List<BaseAttribute> definitions = adapterFactory.forAuthority(authorityInstance).listRaProfileAttributes(authorityInstance);
            attributeEngine.validateUpdateDataAttributes(authorityInstance.getConnectorUuid(), null, definitions,
                    attributes != null ? attributes : List.of());
            return true;
        }
        ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(authorityInstance.getConnectorUuid());

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
                messages.add(BulkActionMessageDto.failure(uuid.toString(), authorityInstanceRef != null ? authorityInstanceRef.getName() : "", e, "Delete failed"));
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
                messages.add(BulkActionMessageDto.failure(uuid.toString(), authorityInstanceRef != null ? authorityInstanceRef.getName() : "", e, "Delete failed"));
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

    private static boolean isV3(ConnectorInterfaceEntity iface) {
        return iface != null && "v3".equals(iface.getVersion());
    }

    /**
     * Builds an unpersisted {@link AuthorityInstanceReference} carrying just enough state
     * (connector UUID, kind, connector interface) for {@link AuthorityProviderAdapterFactory}
     * to pick the version-correct adapter and for that adapter to reach the connector. Used to
     * validate attributes and probe the connection during create, before the row is saved.
     */
    private AuthorityInstanceReference transientAuthorityRef(SecuredUUID connectorUuid, ConnectorDto connector,
                                                             ConnectorInterfaceEntity iface, String kind) {
        AuthorityInstanceReference ref = new AuthorityInstanceReference();
        ref.setConnectorUuid(connectorUuid.getValue());
        ref.setConnectorName(connector.getName());
        ref.setKind(kind);
        if (iface != null) {
            ref.setConnectorInterface(iface);
        }
        return ref;
    }

    /**
     * Validate + merge authority-instance attribute definitions for the connector version.
     * v1/v2 use the legacy function-group attribute path (connector /validate + /attributes by
     * kind). v3 is stateless: definitions come from GET /v3/authorityProvider/authorities/attributes
     * (no kind) and there is no connector-side /validate — Core validates locally
     * against the listed definitions.
     */
    private void mergeAndValidateAuthorityAttributes(AuthorityInstanceReference authorityRef, ConnectorInterfaceEntity iface,
                                                     FunctionGroupCode codeToSearch, List<RequestAttribute> attributes,
                                                     String kind)
            throws ConnectorException, AttributeException, NotFoundException {
        if (isV3(iface)) {
            List<RequestAttribute> attrs = attributes != null ? attributes : List.of();
            List<BaseAttribute> definitions = adapterFactory.forAuthority(authorityRef).listAuthorityInstanceAttributes(authorityRef);
            attributeEngine.validateUpdateDataAttributes(authorityRef.getConnectorUuid(), null, definitions, attrs);
        } else {
            connectorService.mergeAndValidateAttributes(SecuredUUID.fromUUID(authorityRef.getConnectorUuid()),
                    codeToSearch, attributes, kind);
        }
    }

    /**
     * Resolve the AUTHORITY connector interface to bind a new authority to. When the request
     * carries an explicit interfaceUuid (mirrors VaultInstanceRequestDto), validate it belongs
     * to the connector and is an AUTHORITY interface, then use it — this is how an operator
     * selects v3 on a connector that exposes both v2 and v3. When absent (older callers, or
     * legacy connectors that declare no interface), fall back to the sole AUTHORITY interface;
     * if the connector exposes more than one, require an explicit interfaceUuid rather than
     * picking a non-deterministic one.
     */
    private ConnectorInterfaceEntity resolveAuthorityInterface(UUID connectorUuid, UUID interfaceUuid) {
        var interfaces = connectorRepository.findByUuid(connectorUuid)
                .map(c -> c.getInterfaces().stream()
                        .filter(i -> i.getInterfaceCode() == ConnectorInterface.AUTHORITY)
                        .toList())
                .orElse(List.of());
        if (interfaceUuid != null) {
            return interfaces.stream()
                    .filter(i -> interfaceUuid.equals(i.getUuid()))
                    .findFirst()
                    .orElseThrow(() -> new ValidationException(
                            "Connector " + connectorUuid + " has no AUTHORITY interface with UUID " + interfaceUuid));
        }
        if (interfaces.size() > 1) {
            throw new ValidationException(
                    "Connector " + connectorUuid + " exposes multiple AUTHORITY interfaces; supply interfaceUuid to select one.");
        }
        return interfaces.stream().findFirst().orElse(null);
    }

    private AuthorityInstanceDto createV3Authority(
            AuthorityInstanceRequestDto request,
            AuthorityInstanceReference authorityInstanceRef,
            List<?> dataAttributes)
            throws ConnectorException, AttributeException, ValidationException, NotFoundException {
        authorityInstanceRef.setName(request.getName());
        authorityInstanceRef.setStatus("connected");

        AuthorityProviderAdapter adapter = adapterFactory.forAuthority(authorityInstanceRef);
        adapter.checkAuthorityConnection(authorityInstanceRef, AttributeDefinitionUtils.getClientAttributes(dataAttributes));

        authorityInstanceReferenceRepository.save(authorityInstanceRef);

        AuthorityInstanceDto dto = authorityInstanceRef.mapToDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.AUTHORITY, authorityInstanceRef.getUuid(), request.getCustomAttributes()));
        dto.setAttributes(attributeEngine.updateObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.AUTHORITY, authorityInstanceRef.getUuid()).connector(authorityInstanceRef.getConnectorUuid()).build(), request.getAttributes()));
        return dto;
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
        if (authorityInstanceRef.getConnector() != null && !isV3(authorityInstanceRef.getConnectorInterface())) {
            try {
                ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(authorityInstanceRef.getConnectorUuid());
                connectorApiFactory.getAuthorityInstanceApiClient(connectorDto).removeAuthorityInstance(connectorDto, authorityInstanceRef.getAuthorityInstanceUuid());
            } catch (ConnectorEntityNotFoundException notFoundException) {
                logger.warn("Authority is already deleted in the connector. Proceeding to remove it from the core");
            } catch (Exception e) {
                logger.error(e.getMessage());
                throw new ValidationException(e.getMessage());
            }
        } else {
            // v3 is stateless (no connector-side instance) or the connector is gone — local cleanup only
            logger.debug("Deleting authority without a connector-side instance: {}", authorityInstanceRef);
        }
        attributeEngine.deleteObjectAttributeContent(Resource.AUTHORITY, authorityInstanceRef.getUuid());
        authorityInstanceReferenceRepository.delete(authorityInstanceRef);
    }

    @Override
    public ResourceObjectContentData getResourceObjectContent(UUID uuid) {
        return null;
    }
}
