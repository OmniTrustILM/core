package com.czertainly.core.service.v2.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.model.client.certificate.SearchFilterRequestDto;
import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.connector.ConnectRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorInfo;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.connector.v2.HealthInfo;
import com.czertainly.api.model.common.BulkActionMessageDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.ConnectorApiClientDto;
import com.czertainly.api.model.core.connector.v2.*;
import com.czertainly.api.model.core.scheduler.PaginationRequestDto;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.search.SearchFieldDataByGroupDto;
import com.czertainly.api.model.core.search.SearchFieldDataDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.comparator.SearchFieldDataComparator;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.events.transaction.TransactionHandler;
import com.czertainly.core.model.auth.ResourceAction;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.ConnectorAuthService;
import com.czertainly.core.service.handler.ConnectorAdapter;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.FilterPredicatesBuilder;
import com.czertainly.core.util.RequestValidatorHelper;
import com.czertainly.core.util.SearchHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.transaction.Transactional;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import reactor.core.Exceptions;

import java.util.*;
import java.util.stream.Collectors;

@Service(Resource.Codes.CONNECTOR)
@Transactional
public class ConnectorServiceImpl implements ConnectorService {

    private static final Logger logger = LoggerFactory.getLogger(ConnectorServiceImpl.class);

    private Map<String, ConnectorAdapter> connectorAdapters;

    private ConnectorRepository connectorRepository;
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    private CredentialRepository credentialRepository;
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    private EntityInstanceReferenceRepository entityInstanceReferenceRepository;
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    private VaultInstanceRepository vaultInstanceRepository;
    private ComplianceProfileRepository complianceProfileRepository;
    private ComplianceProfileRuleRepository complianceProfileRuleRepository;
    private ProxyRepository proxyRepository;

    private ConnectorAuthService connectorAuthService;

    private AttributeEngine attributeEngine;
    private TransactionHandler transactionHandler;

    @Autowired
    public void setVaultInstanceRepository(VaultInstanceRepository vaultInstanceRepository) {
        this.vaultInstanceRepository = vaultInstanceRepository;
    }

    @Autowired
    public void setConnectorAdapters(Map<String, ConnectorAdapter> connectorAdapters) {
        this.connectorAdapters = connectorAdapters;
    }

    @Autowired
    public void setConnectorRepository(ConnectorRepository connectorRepository) {
        this.connectorRepository = connectorRepository;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setTransactionHandler(TransactionHandler transactionHandler) {
        this.transactionHandler = transactionHandler;
    }

    @Autowired
    public void setCredentialRepository(CredentialRepository credentialRepository) {
        this.credentialRepository = credentialRepository;
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
    public void setTokenInstanceReferenceRepository(TokenInstanceReferenceRepository tokenInstanceReferenceRepository) {
        this.tokenInstanceReferenceRepository = tokenInstanceReferenceRepository;
    }

    @Autowired
    public void setComplianceProfileRepository(ComplianceProfileRepository complianceProfileRepository) {
        this.complianceProfileRepository = complianceProfileRepository;
    }

    @Autowired
    public void setComplianceProfileRuleRepository(ComplianceProfileRuleRepository complianceProfileRuleRepository) {
        this.complianceProfileRuleRepository = complianceProfileRuleRepository;
    }

    @Autowired
    public void setConnector2FunctionGroupRepository(Connector2FunctionGroupRepository connector2FunctionGroupRepository) {
        this.connector2FunctionGroupRepository = connector2FunctionGroupRepository;
    }

    @Autowired
    public void setProxyRepository(ProxyRepository proxyRepository) {
        this.proxyRepository = proxyRepository;
    }

    @Autowired
    public void setConnectorAuthService(ConnectorAuthService connectorAuthService) {
        this.connectorAuthService = connectorAuthService;
    }


    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.LIST)
    public PaginationResponseDto<ConnectorDto> listConnectors(SecurityFilter filter, SearchRequestDto request) {
        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        final TriFunction<Root<Connector>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root, cb, cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, request.getFilters());
        final List<ConnectorDto> connectorDtos = connectorRepository.findUsingSecurityFilter(filter, List.of(), additionalWhereClause, p, (root, cb) -> cb.desc(root.get("created")))
                .stream()
                .map(Connector::mapToListDto).toList();
        final Long maxItems = connectorRepository.countUsingSecurityFilter(filter, additionalWhereClause);

        PaginationResponseDto<ConnectorDto> response = new PaginationResponseDto<>();
        response.setItems(connectorDtos);
        response.setPageNumber(request.getPageNumber());
        response.setItemsPerPage(request.getItemsPerPage());
        response.setTotalItems(maxItems);
        response.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return response;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.DETAIL)
    public ConnectorDetailDto getConnector(SecuredUUID uuid) throws NotFoundException, ConnectorException {
        Connector connector = getConnectorEntity(uuid);

        ConnectorDetailDto dto = connector.mapToDetailDto();
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.CONNECTOR, uuid.getValue()));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.CREATE)
    public ConnectorDetailDto createConnector(ConnectorRequestDto request) throws ConnectorException, NotFoundException, AlreadyExistException, AttributeException {
        return createNewConnector(request, ConnectorStatus.CONNECTED);
    }

    //Internal and anonymous user only - Should not use as replacement for createConnector method, as it will create connector in waiting for approval status without any authorization check
    @Override
    public ConnectorDetailDto createNewWaitingConnector(ConnectorRequestDto request) throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        return createNewConnector(request, ConnectorStatus.WAITING_FOR_APPROVAL);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.UPDATE)
    public ConnectorDetailDto editConnector(SecuredUUID uuid, ConnectorUpdateRequestDto request) throws NotFoundException, ConnectorException, AttributeException {
        Connector connector = getConnectorEntity(uuid);

        Proxy proxy = resolveProxy(request.getProxyUuid(), null);
        attributeEngine.validateCustomAttributesContent(Resource.CONNECTOR, request.getCustomAttributes());
        List<BaseAttribute> authAttributes = connectorAuthService.mergeAndValidateAuthAttributes(
                request.getAuthType(),
                AttributeEngine.getResponseAttributesFromRequestAttributes(request.getAuthAttributes()));

        connector.setUrl(request.getUrl());
        connector.setAuthType(request.getAuthType());
        connector.setAuthAttributes(AttributeDefinitionUtils.serialize(authAttributes));
        connector.setProxy(proxy);
        connectorRepository.save(connector);

        ConnectorAdapter connectorAdapter = getAdapter(connector.getVersion());
        ConnectInfo connectInfo = connectorAdapter.validateConnection(connector.mapToApiClientDtoV2());
        connectorAdapter.updateConnectorFunctions(connector, connectInfo);

        ConnectorDetailDto dto = connector.mapToDetailDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.CONNECTOR, connector.getUuid(), request.getCustomAttributes()));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.DELETE)
    public void deleteConnector(SecuredUUID uuid) throws NotFoundException {
        Connector connector = getConnectorEntity(uuid);
        deleteConnector(connector);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> bulkDeleteConnector(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            Connector connector = null;
            try {
                connector = getConnectorEntity(uuid);
                deleteConnector(connector);
            } catch (Exception e) {
                logger.error("Unable to delete Connector", e);
                messages.add(new BulkActionMessageDto(uuid.toString(), connector != null ? connector.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.DELETE)
    public List<BulkActionMessageDto> forceDeleteConnector(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            Connector connector = null;
            try {
                connector = getConnectorEntity(uuid);
                removeConnectorAssociations(connector);
                deleteConnector(connector);
            } catch (Exception e) {
                logger.error("Unable to force delete Connector", e);
                messages.add(new BulkActionMessageDto(uuid.toString(), connector != null ? connector.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.CONNECT)
    public List<ConnectInfo> connect(ConnectRequestDto request) throws ConnectorException {
        List<ConnectInfo> connectInfos = new ArrayList<>();

        ConnectorApiClientDto apiClientDto = new ConnectorApiClientDto();
        apiClientDto.setUuid(request.getUuid());
        apiClientDto.setUrl(request.getUrl());
        apiClientDto.setAuthType(request.getAuthType());
        apiClientDto.setAuthAttributes(AttributeEngine.getResponseAttributesFromRequestAttributes(request.getAuthAttributes()));
        apiClientDto.setProxy(request.getProxy());
        for (ConnectorAdapter connectorAdapter : connectorAdapters.values()) {
            ConnectInfo connectInfo = null;
            try {
                connectInfo = connectorAdapter.checkConnection(apiClientDto);
                connectorAdapter.validateConnection(connectInfo);
            } catch (ConnectorException | ValidationException e) {
                if (e instanceof ConnectorCommunicationException || e instanceof ConnectorEntityNotFoundException || e instanceof ConnectorServerException) {
                    logger.debug("No connector of version {} is running on the provided URL '{}'.", connectorAdapter.getVersion().getLabel(), request.getUrl());
                    continue;
                }

                if (e instanceof ValidationException) {
                    logger.error("Validation error when connecting to connector of version {} with the provided URL '{}': {}", connectorAdapter.getVersion().getLabel(), request.getUrl(), e.getMessage());
                } else {
                    logger.error("Unable to connect to connector of version {} running on the provided URL '{}': {}", connectorAdapter.getVersion().getLabel(), request.getUrl(), e.getMessage(), e);
                }

                if (connectInfo == null) {
                    connectInfo = ConnectInfo.fromError(connectorAdapter.getVersion(), e.getMessage());
                } else {
                    connectInfo.setErrorMessage(e.getMessage());
                }
            }

            var connector = connectorRepository.findByUrlAndVersion(request.getUrl(), connectorAdapter.getVersion());
            if (connector.isPresent()) {
                connectInfo.setConnectorUuid(connector.get().getUuid());
            }
            connectInfos.add(connectInfo);
        }

        if (connectInfos.isEmpty()) {
            throw new ConnectorCommunicationException("Unable to connect to any connector on the provided URL '%s' with the provided credentials.".formatted(request.getUrl()), null);
        }

        connectInfos.sort(Comparator.comparing(ConnectInfo::getVersion));
        return connectInfos;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.CONNECT)
    public ConnectInfo reconnect(SecuredUUID uuid) throws NotFoundException, ConnectorException {
        Connector connector = getConnectorEntity(uuid);
        return reconnect(connector);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.CONNECT)
    public List<BulkActionMessageDto> bulkReconnect(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            Connector connector = null;
            try {
                connector = getConnectorEntity(uuid);
                reconnect(connector);
            } catch (Exception e) {
                logger.error("Unable to reconnect connector", e);
                messages.add(new BulkActionMessageDto(uuid.toString(), connector != null ? connector.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.APPROVE)
    public void approve(SecuredUUID uuid) throws NotFoundException {
        Connector connector = getConnectorEntity(uuid);
        approve(connector);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.APPROVE)
    public List<BulkActionMessageDto> bulkApprove(List<SecuredUUID> uuids) {
        List<BulkActionMessageDto> messages = new ArrayList<>();
        for (SecuredUUID uuid : uuids) {
            Connector connector = null;
            try {
                connector = getConnectorEntity(uuid);
                approve(connector);
            } catch (Exception e) {
                logger.error("Unable to approve connector", e);
                messages.add(new BulkActionMessageDto(uuid.toString(), connector != null ? connector.getName() : "", e.getMessage()));
            }
        }
        return messages;
    }

    @Override
    public HealthInfo checkHealth(SecuredUUID uuid) throws NotFoundException, ConnectorException {
        Connector connector = getConnectorEntity(uuid);
        ConnectorAdapter connectorAdapter = getAdapter(connector.getVersion());
        return connectorAdapter.checkHealth(connector.mapToApiClientDtoV2());
    }

    @Override
    public ConnectorInfo getInfo(SecuredUUID uuid) throws NotFoundException, ConnectorException {
        Connector connector = getConnectorEntity(uuid);
        ConnectorAdapter connectorAdapter = getAdapter(connector.getVersion());
        return connectorAdapter.getInfo(connector.mapToApiClientDtoV2());
    }

    @Override
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine.getResourceSearchableFields(Resource.CONNECTOR, false);

        List<SearchFieldDataDto> fields = List.of(
                SearchHelper.prepareSearch(FilterField.CONNECTOR_NAME),
                SearchHelper.prepareSearch(FilterField.CONNECTOR_URL),
                SearchHelper.prepareSearch(FilterField.CONNECTOR_VERSION),
                SearchHelper.prepareSearch(FilterField.CONNECTOR_STATUS),
                SearchHelper.prepareSearch(FilterField.CONNECTOR_AUTH_TYPE),
                SearchHelper.prepareSearch(FilterField.CONNECTOR_INTERFACE),
                SearchHelper.prepareSearch(FilterField.CONNECTOR_FUNCTION_GROUP)
        );

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        return searchFieldDataByGroupDtos;
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return connectorRepository.findResourceObject(objectUuid, Connector_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return connectorRepository.findResourceObject(objectUuid.getValue(), Connector_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.LIST)
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters, PaginationRequestDto pagination) {
        return connectorRepository.listResourceObjects(filter, Connector_.name, null, pagination);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getConnectorEntity(uuid);
    }

    private Connector getConnectorEntity(SecuredUUID uuid) throws NotFoundException {
        return connectorRepository.findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(Connector.class, uuid));
    }


    private ConnectorDetailDto createNewConnector(ConnectorRequestDto request, ConnectorStatus connectorStatus) throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        if (StringUtils.isBlank(request.getName())) {
            throw new ValidationException(ValidationError.create("Connector name must not be empty"));
        }
        if (connectorRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(Connector.class, request.getName());
        }
        if (connectorRepository.findByUrlAndVersion(request.getUrl(), request.getVersion()).isPresent()) {
            throw new AlreadyExistException(Connector.class, "URL %s with version %s".formatted(request.getUrl(), request.getVersion().getLabel()));
        }

        Proxy proxy = resolveProxy(request.getProxyUuid(), request.getProxyCode());
        List<BaseAttribute> authAttributes = connectorAuthService.mergeAndValidateAuthAttributes(request.getAuthType(), AttributeEngine.getResponseAttributesFromRequestAttributes(request.getAuthAttributes()));
        attributeEngine.validateCustomAttributesContent(Resource.CONNECTOR, request.getCustomAttributes());

        Connector connector = new Connector();
        connector.setName(request.getName());
        connector.setVersion(request.getVersion());
        connector.setUrl(request.getUrl());
        connector.setAuthType(request.getAuthType());
        connector.setAuthAttributes(AttributeDefinitionUtils.serialize(authAttributes));
        connector.setProxy(proxy);

        if (proxy != null) {
            // Proxy connector: always CONNECTED (it registered itself via proxy, so it's reachable).
            // Must save first so mapToApiClientDto() includes UUID and proxy info for MQ routing.
            connector.setStatus(ConnectorStatus.CONNECTED);
            connectorRepository.save(connector);

            ConnectorAdapter connectorAdapter = getAdapter(request.getVersion());
            ConnectInfo connectInfo = connectorAdapter.validateConnection(connector.mapToApiClientDtoV2());
            connectorAdapter.updateConnectorFunctions(connector, connectInfo);
        } else {
            ConnectorApiClientDto connectorApiDto = new ConnectorApiClientDto();
            connectorApiDto.setName(request.getName());
            connectorApiDto.setUrl(request.getUrl());
            connectorApiDto.setAuthType(request.getAuthType());
            connectorApiDto.setAuthAttributes(AttributeEngine.getResponseAttributesFromBaseAttributes(authAttributes));

            ConnectorAdapter connectorAdapter = getAdapter(request.getVersion());
            ConnectInfo connectInfo = connectorAdapter.validateConnection(connectorApiDto);

            connector.setStatus(connectorStatus);
            connectorRepository.save(connector);

            connectorAdapter.updateConnectorFunctions(connector, connectInfo);
        }

        ConnectorDetailDto dto = connector.mapToDetailDto();
        dto.setCustomAttributes(attributeEngine.updateObjectCustomAttributesContent(Resource.CONNECTOR, connector.getUuid(), request.getCustomAttributes()));
        return dto;
    }

    private void removeConnectorAssociations(Connector connector) {
        if (!connector.getCredentials().isEmpty()) {
            for (Credential credential : connector.getCredentials()) {
                credential.setConnectorUuid(null);
                credentialRepository.save(credential);
            }
            connector.getCredentials().removeAll(connector.getCredentials());
            connectorRepository.save(connector);
        }

        if (!connector.getAuthorityInstanceReferences().isEmpty()) {
            for (AuthorityInstanceReference ref : connector.getAuthorityInstanceReferences()) {
                ref.setConnector(null);
                ref.setConnectorUuid(null);
                authorityInstanceReferenceRepository.save(ref);
            }
            connector.getAuthorityInstanceReferences().removeAll(connector.getAuthorityInstanceReferences());
            connectorRepository.save(connector);
        }

        if (!connector.getEntityInstanceReferences().isEmpty()) {
            for (EntityInstanceReference ref : connector.getEntityInstanceReferences()) {
                ref.setConnector(null);
                ref.setConnectorUuid(null);
                entityInstanceReferenceRepository.save(ref);
            }
            connector.getEntityInstanceReferences().removeAll(connector.getEntityInstanceReferences());
            connectorRepository.save(connector);
        }

        if (!connector.getTokenInstanceReferences().isEmpty()) {
            for (TokenInstanceReference ref : connector.getTokenInstanceReferences()) {
                ref.setConnector(null);
                ref.setConnectorUuid(null);
                tokenInstanceReferenceRepository.save(ref);
            }
            connector.getTokenInstanceReferences().removeAll(connector.getTokenInstanceReferences());
            connectorRepository.save(connector);
        }

        if (!connector.getVaultInstances().isEmpty()) {
            for (VaultInstance vaultInstance : connector.getVaultInstances()) {
                vaultInstance.setConnector(null);
                vaultInstance.setConnectorInterface(null);
                vaultInstanceRepository.save(vaultInstance);
            }
            connector.getVaultInstances().clear();
            connectorRepository.save(connector);
        }

        // delete connector associations to compliance profiles rules
        complianceProfileRuleRepository.deleteByConnectorUuid(connector.getUuid());
    }

    private ConnectInfo reconnect(Connector connector) throws ConnectorException {
        ConnectorAdapter connectorAdapter = getAdapter(connector.getVersion());

        try {
            ConnectInfo connectInfo = connectorAdapter.validateConnection(connector.mapToApiClientDtoV2());
            connectorAdapter.updateConnectorFunctions(connector, connectInfo);
            return connectInfo;
        } catch (ConnectorCommunicationException | NotFoundException e) {
            String message = String.format("Unable to reconnect to connector %s. Error in communication or no connector of version %s is running on the provided URL '%s'.", connector.getName(), connectorAdapter.getVersion().getLabel(), connector.getUrl());
            logger.error(message, Exceptions.unwrap(e));
            transactionHandler.runInNewTransaction(() -> {
                connector.setStatus(ConnectorStatus.OFFLINE);
                connectorRepository.save(connector);
            });

            throw new ConnectorException(message);
        }
    }

    private void approve(Connector connector) {
        if (connector.getStatus() == ConnectorStatus.WAITING_FOR_APPROVAL) {
            connector.setStatus(ConnectorStatus.CONNECTED);
            connectorRepository.save(connector);
        } else {
            throw new ValidationException(ValidationError.create("Connector '{}' has unexpected status {}", connector.getName(), connector.getStatus().getLabel()));
        }
    }

    private void deleteConnector(Connector connector) {
        List<String> errors = new ArrayList<>();
        if (!connector.getCredentials().isEmpty()) {
            errors.add("Dependent credentials: " + String.join(", ", connector.getCredentials().stream().map(Credential::getName).collect(Collectors.toSet())));
        }

        if (!connector.getAuthorityInstanceReferences().isEmpty()) {
            errors.add("Dependent Authority Instances: " + String.join(", ", connector.getAuthorityInstanceReferences().stream().map(AuthorityInstanceReference::getName).collect(Collectors.toSet())));
        }

        if (!connector.getEntityInstanceReferences().isEmpty()) {
            errors.add("Dependent Entity Instances: " + String.join(", ", connector.getEntityInstanceReferences().stream().map(EntityInstanceReference::getName).collect(Collectors.toSet())));
        }

        if (!connector.getTokenInstanceReferences().isEmpty()) {
            errors.add("Dependent Token Instances: " + String.join(", ", connector.getTokenInstanceReferences().stream().map(TokenInstanceReference::getName).collect(Collectors.toSet())));
        }

        if (!connector.getVaultInstances().isEmpty()) {
            errors.add("Dependent Vault Instances: " + String.join(", ", connector.getVaultInstances().stream().map(VaultInstance::getName).collect(Collectors.toSet())));
        }

        Set<String> complianceProfileNames = complianceProfileRepository.findDistinctByComplianceRulesConnectorUuid(connector.getUuid()).stream().map(ComplianceProfile::getName).collect(Collectors.toSet());
        if (!complianceProfileNames.isEmpty()) {
            errors.add("Dependent Compliance Profiles: " + String.join(", ", complianceProfileNames));
        }

        if (!errors.isEmpty()) {
            throw new ValidationException(ValidationError.create(String.join("\n", errors)));
        }

        // remove connector attribute definitions and content if they are only dependent resources
        attributeEngine.deleteConnectorAttributeDefinitionsContent(connector.getUuid());

        List<Connector2FunctionGroup> connector2FunctionGroups = connector2FunctionGroupRepository.findAllByConnector(connector);
        connector2FunctionGroupRepository.deleteAll(connector2FunctionGroups);

        attributeEngine.deleteObjectAttributeContent(Resource.CONNECTOR, connector.getUuid());
        connectorRepository.delete(connector);
    }

    private Proxy resolveProxy(String proxyUuid, String proxyCode) throws NotFoundException {
        if (proxyUuid != null && !proxyUuid.isBlank()) {
            return proxyRepository.findByUuid(SecuredUUID.fromString(proxyUuid))
                    .orElseThrow(() -> new NotFoundException(Proxy.class, proxyUuid));
        }
        if (proxyCode != null && !proxyCode.isBlank()) {
            return proxyRepository.findByCode(proxyCode)
                    .orElseThrow(() -> new NotFoundException(Proxy.class, proxyCode));
        }
        return null;
    }

    private ConnectorAdapter getAdapter(ConnectorVersion version) {
        ConnectorAdapter adapter = connectorAdapters.get(version.getCode());
        if (adapter == null) {
            throw new IllegalStateException("No adapter registered for connector version: " + version);
        }
        return adapter;
    }

}
