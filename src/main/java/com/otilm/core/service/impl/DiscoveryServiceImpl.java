package com.otilm.core.service.impl;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.DiscoverySyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.DiscoveryResponseDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.discovery.DiscoveryCertificateResponseDto;
import com.otilm.api.model.client.discovery.DiscoveryDetailDto;
import com.otilm.api.model.client.discovery.DiscoveryDto;
import com.otilm.api.model.client.discovery.DiscoveryListDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemPayloadDto;
import com.otilm.api.model.connector.discovery.v2.DiscoverySupportedResourceDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.discovery.DiscoveryItemDto;
import com.otilm.api.model.core.discovery.DiscoveryMessageDto;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.scheduler.PaginationRequestDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataByGroupDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.attribute.engine.AttributeColumnProjector;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.attribute.engine.ListingSortResolver;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.comparator.SearchFieldDataComparator;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryCertificate;
import com.otilm.core.dao.entity.DiscoveryMessage;
import com.otilm.core.dao.entity.Discovery_;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryCertificateRepository;
import com.otilm.core.dao.repository.DiscoveryItemRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.events.data.DiscoveryResult;
import com.otilm.core.events.handlers.DiscoveryFinishedEventHandler;
import com.otilm.core.exception.UnsupportedDiscoveryVersionException;
import com.otilm.core.mapper.discovery.DiscoveryDtoMapper;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.messaging.model.NotificationRecipient;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.discovery.DiscoveryRunLifecycle;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CommentInternalService;
import com.otilm.core.service.ConnectorInternalService;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.DiscoveryInternalService;
import com.otilm.core.service.TriggerInternalService;
import com.otilm.core.service.handler.discovery.DiscoveryDetailCounts;
import com.otilm.core.service.handler.discovery.DiscoveryProviderAdapter;
import com.otilm.core.service.handler.discovery.DiscoveryProviderAdapterFactory;
import com.otilm.core.service.writer.DiscoveryWriter;
import com.otilm.core.service.writer.discovery.DiscoveryRunWriter;
import com.otilm.core.tasks.ScheduledJobInfo;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.FilterPredicatesBuilder;
import com.otilm.core.util.RequestValidatorHelper;
import com.otilm.core.util.SearchHelper;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.apache.commons.lang3.function.TriFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service(Resource.Codes.DISCOVERY)
@Transactional
public class DiscoveryServiceImpl implements DiscoveryExternalService, DiscoveryInternalService {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryServiceImpl.class);

    /**
     * The largest page size the frontend offers ({@code DEFAULT_ITEMS_PER_PAGE_OPTIONS}). Clamping below it would
     * answer a user who picked 1000 with 100 rows and an itemsPerPage that disagrees with the control they used.
     * {@code WebAppConfig}'s own ceiling does not reach here — it binds Spring-resolved Pageables, and these arrive as
     * raw ints.
     */
    private static final int MAX_ITEMS_PER_PAGE = 1000;

    private static final String DISCOVERY_V2 = "v2";

    private static final String UNSUPPORTED_VERSION_MESSAGE = "The discovery's connector interface version is not supported.";

    private AttributeEngine attributeEngine;
    private AttributeColumnProjector attributeColumnProjector;

    private ListingSortResolver listingSortResolver;

    private TriggerInternalService triggerInternalService;
    private DiscoveryRepository discoveryRepository;
    private ConnectorApiFactory connectorApiFactory;
    private ConnectorInternalService connectorService;
    private DiscoveryCertificateRepository discoveryCertificateRepository;
    private DiscoveryDetailCounts detailCounts;
    private CertificateContentRepository certificateContentRepository;

    private DiscoveryProviderAdapterFactory discoveryProviderAdapterFactory;
    private DiscoveryWriter discoveryWriter;
    private DiscoveryRunWriter discoveryRunWriter;
    private ConnectorRepository connectorRepository;
    private EventProducer eventProducer;
    private NotificationProducer notificationProducer;

    private CommentInternalService commentService;
    private DiscoveryMessageRepository discoveryMessageRepository;
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    private DiscoveryItemRepository discoveryItemRepository;

    @Autowired
    public void setDiscoveryItemRepository(DiscoveryItemRepository discoveryItemRepository) {
        this.discoveryItemRepository = discoveryItemRepository;
    }

    @Autowired
    public void setConnectorInterfaceRepository(ConnectorInterfaceRepository connectorInterfaceRepository) {
        this.connectorInterfaceRepository = connectorInterfaceRepository;
    }

    @Autowired
    public void setCommentService(CommentInternalService commentService) {
        this.commentService = commentService;
    }

    @Autowired
    public void setDiscoveryMessageRepository(DiscoveryMessageRepository discoveryMessageRepository) {
        this.discoveryMessageRepository = discoveryMessageRepository;
    }

    @Autowired
    public void setConnectorRepository(ConnectorRepository connectorRepository) {
        this.connectorRepository = connectorRepository;
    }

    @Autowired
    public void setDiscoveryWriter(DiscoveryWriter discoveryWriter) {
        this.discoveryWriter = discoveryWriter;
    }

    @Autowired
    public void setEventProducer(EventProducer eventProducer) {
        this.eventProducer = eventProducer;
    }

    @Autowired
    public void setNotificationProducer(NotificationProducer notificationProducer) {
        this.notificationProducer = notificationProducer;
    }

    @Autowired
    public void setDiscoveryRunWriter(DiscoveryRunWriter discoveryRunWriter) {
        this.discoveryRunWriter = discoveryRunWriter;
    }

    @Autowired
    public void setDiscoveryProviderAdapterFactory(DiscoveryProviderAdapterFactory discoveryProviderAdapterFactory) {
        this.discoveryProviderAdapterFactory = discoveryProviderAdapterFactory;
    }

    @Autowired
    public void setTriggerInternalService(TriggerInternalService triggerInternalService) {
        this.triggerInternalService = triggerInternalService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setAttributeColumnProjector(AttributeColumnProjector attributeColumnProjector) {
        this.attributeColumnProjector = attributeColumnProjector;
    }

    @Autowired
    public void setListingSortResolver(ListingSortResolver listingSortResolver) {
        this.listingSortResolver = listingSortResolver;
    }

    @Autowired
    public void setDiscoveryRepository(DiscoveryRepository discoveryRepository) {
        this.discoveryRepository = discoveryRepository;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    @Autowired
    public void setConnectorService(ConnectorInternalService connectorService) {
        this.connectorService = connectorService;
    }

    @Autowired
    public void setDiscoveryCertificateRepository(DiscoveryCertificateRepository discoveryCertificateRepository) {
        this.discoveryCertificateRepository = discoveryCertificateRepository;
    }

    @Autowired
    public void setDetailCounts(DiscoveryDetailCounts detailCounts) {
        this.detailCounts = detailCounts;
    }

    @Autowired
    public void setCertificateContentRepository(CertificateContentRepository certificateContentRepository) {
        this.certificateContentRepository = certificateContentRepository;
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.LIST)
    public DiscoveryResponseDto listDiscoveries(final SecurityFilter filter, final SearchRequestDto request) {

        RequestValidatorHelper.revalidateSearchRequestDto(request);
        final Pageable p = PageRequest.of(request.getPageNumber() - 1, request.getItemsPerPage());

        final Supplier<CustomAttributeContentFilter> contentFilter = attributeEngine.customAttributeContentFilterOnce();
        final TriFunction<Root<Discovery>, CriteriaBuilder, CriteriaQuery<?>, Predicate> additionalWhereClause = (root,
                cb,
                cr) -> FilterPredicatesBuilder.getFiltersPredicate(cb, cr, root, request.getFilters(), contentFilter);
        final List<DiscoveryListDto> listedDiscoveriesDTOs = discoveryRepository
                .findUsingSecurityFilter(filter, List.of("connectorInterface"), additionalWhereClause, p,
                        (root, cb) -> cb.desc(root.get("created")),
                        listingSortResolver.resolve(Resource.DISCOVERY, request.getSort(), contentFilter))
                .stream()
                .map(DiscoveryDtoMapper::toListDto)
                .toList();
        attributeColumnProjector
                .project(Resource.DISCOVERY, request.getColumns(), listedDiscoveriesDTOs,
                        discovery -> AttributeColumnProjector.parseUuid(discovery.getUuid()), contentFilter);

        final Long maxItems = discoveryRepository.countUsingSecurityFilter(filter, additionalWhereClause);

        final DiscoveryResponseDto responseDto = new DiscoveryResponseDto();
        responseDto.setDiscoveries(listedDiscoveriesDTOs);
        responseDto.setItemsPerPage(request.getItemsPerPage());
        responseDto.setPageNumber(request.getPageNumber());
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / request.getItemsPerPage()));
        return responseDto;
    }

    // The relays below are keyed and gated on the CONNECTOR, not the run: DISCOVERY has no object access,
    // so gating there would silently skip the per-connector ACL. NOT_SUPPORTED because each one goes on to call
    // the connector, which must never happen inside a transaction.

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.ANY)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<DiscoverySupportedResourceDto> listDiscoveryResources(SecuredUUID connectorUuid)
            throws NotFoundException, ConnectorException {
        ApiClientConnectorInfo connector = connectorService.getConnectorForApiClient(connectorUuid.getValue());
        if (discoveryV2Interface(connectorUuid.getValue()).isEmpty()) {
            // A v1 connector discovers certificates and nothing else, so the answer is known without asking it.
            // Synthesized rather than empty: a client renders one shape for both generations.
            DiscoverySupportedResourceDto certificates = new DiscoverySupportedResourceDto();
            certificates.setResource(Resource.CERTIFICATE);
            return List.of(certificates);
        }
        return connectorApiFactory.getDiscoveryApiClientV2(connector).listSupportedResources(connector);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.ANY)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> getDiscoveryAttributes(SecuredUUID connectorUuid)
            throws NotFoundException, ConnectorException {
        ApiClientConnectorInfo connector = requireDiscoveryV2(connectorUuid);
        return connectorApiFactory.getDiscoveryApiClientV2(connector).listRunAttributes(connector);
    }

    @Override
    @ExternalAuthorization(resource = Resource.CONNECTOR, action = ResourceAction.ANY)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<BaseAttribute> getDiscoveryResourceAttributes(SecuredUUID connectorUuid, Resource resource)
            throws NotFoundException, ConnectorException {
        ApiClientConnectorInfo connector = requireDiscoveryV2(connectorUuid);
        // Checked before the connector is called at all: the client throws IllegalArgumentException for a
        // resource the contract defines no payload for, which would surface as a 500 rather than a 422.
        if (!DiscoveredItemPayloadDto.DISCOVERABLE.contains(resource)) {
            throw new ValidationException("Resource " + resource.getLabel() + " is not discoverable");
        }
        // Discoverable in general is not the same as discoverable by this connector, and the supported set is
        // never persisted -- it is relayed live -- so answering that question costs a call.
        if (!liveSupportedResources(connectorUuid.getValue()).contains(resource)) {
            throw new ValidationException(
                    "Connector " + connectorUuid.getValue() + " does not discover " + resource.getLabel());
        }
        return connectorApiFactory.getDiscoveryApiClientV2(connector).listResourceAttributes(connector, resource);
    }

    /** The connector, once its v2 discovery interface is known to exist — the only generation with a schema. */
    private ApiClientConnectorInfo requireDiscoveryV2(SecuredUUID connectorUuid) throws NotFoundException {
        ApiClientConnectorInfo connector = connectorService.getConnectorForApiClient(connectorUuid.getValue());
        if (discoveryV2Interface(connectorUuid.getValue()).isEmpty()) {
            throw new ValidationException(
                    "Connector " + connectorUuid.getValue() + " does not implement the v2 discovery interface");
        }
        return connector;
    }

    /**
     * Validates the run's own attributes against the schema its connector actually publishes.
     *
     * <p>
     * The two generations publish it in different places. A v1 connector serves kind-scoped definitions from the legacy
     * function-group endpoints, which is what {@code mergeAndValidateAttributes} reads. A v2 connector does not expose
     * those at all — it answers {@code listRunAttributes} — so a v2 run cannot go through the v1 path, which would
     * validate it against endpoints its connector never implements.
     */
    private void validateRunAttributes(DiscoveryDto request, Connector connector,
            ConnectorInterfaceEntity discoveryInterface)
            throws ConnectorException, AttributeException, NotFoundException {
        if (discoveryInterface == null) {
            connectorService
                    .mergeAndValidateAttributes(SecuredUUID.fromUUID(connector.getUuid()),
                            FunctionGroupCode.DISCOVERY_PROVIDER, request.getAttributes(), request.getKind());
            return;
        }
        ApiClientConnectorInfo connectorInfo = connectorService.getConnectorForApiClient(connector.getUuid());
        attributeEngine
                .validateUpdateDataAttributes(connector.getUuid(), null,
                        connectorApiFactory.getDiscoveryApiClientV2(connectorInfo).listRunAttributes(connectorInfo),
                        request.getAttributes());
    }

    /**
     * Reads the attribute definitions behind each resource the request files content against, in request order.
     *
     * <p>
     * Separated from the writing of them so that every connector call a create makes happens here, outside any
     * transaction — {@link DiscoveryRunWriter} then commits the definitions and their content together.
     */
    private Map<Resource, List<BaseAttribute>> fetchResourceDefinitions(DiscoveryDto request, Connector connector)
            throws ConnectorException, NotFoundException, AttributeException {
        if (request.getResources() == null || request.getResources().isEmpty()) {
            return Map.of();
        }
        ApiClientConnectorInfo connectorInfo = connectorService.getConnectorForApiClient(connector.getUuid());
        Map<Resource, List<RequestAttribute>> submitted = request.getResourceAttributes() == null
                ? Map.of()
                : request.getResourceAttributes();
        Map<Resource, List<BaseAttribute>> definitions = new LinkedHashMap<>();
        // Every targeted resource, not only those the request filed content against: a resource whose schema
        // declares a required attribute is refused for omitting it, and the submitted keys alone cannot show that.
        // Validated through the same engine call the run-level attributes go through.
        for (Resource resource : request.getResources()) {
            List<BaseAttribute> declared = connectorApiFactory
                    .getDiscoveryApiClientV2(connectorInfo)
                    .listResourceAttributes(connectorInfo, resource);
            attributeEngine
                    .validateUpdateDataAttributes(connector.getUuid(), resource.getCode(), declared,
                            submitted.getOrDefault(resource, List.of()));
            definitions.put(resource, declared);
        }
        return definitions;
    }

    /**
     * Decides what a run may target, before anything is written.
     *
     * <p>
     * The two generations are mirror images: a v2 connector needs {@code resources}, since it discovers several kinds
     * and cannot guess which the caller meant, while a v1 connector must not be given any — it discovers certificates
     * and nothing else, so accepting the field would let a caller believe they had selected something. An empty list or
     * a null element never reaches here; bean validation refuses both.
     */
    private void validateRequestedResources(DiscoveryDto request, Connector connector,
            ConnectorInterfaceEntity discoveryInterface) throws NotFoundException, ConnectorException {
        if (discoveryInterface == null) {
            if (request.getResources() != null) {
                throw new ValidationException("Connector " + connector.getUuid()
                        + " implements only the v1 discovery interface, which discovers certificates only");
            }
            // Refused rather than ignored. Per-resource attributes are collected against definitions only a v2
            // connector publishes, so honouring them would send Core to a v2 endpoint this connector does not
            // implement, and dropping them silently would accept a run configured differently from what was asked.
            if (request.getResourceAttributes() != null && !request.getResourceAttributes().isEmpty()) {
                throw new ValidationException("Connector " + connector.getUuid()
                        + " implements only the v1 discovery interface, which has no per-resource attributes");
            }
            return;
        }
        // Refused at create, where a caller is present to be told, rather than by a run that is accepted and then
        // fails at dispatch. Everything below speaks the v2 protocol, so a version Core has no client for cannot be
        // validated against, let alone driven.
        if (!DISCOVERY_V2.equals(discoveryInterface.getVersion())) {
            throw new ValidationException("Connector " + connector.getUuid() + " exposes discovery interface version "
                    + discoveryInterface.getVersion() + ", which this version of the platform cannot drive");
        }
        if (request.getResources() == null) {
            throw new ValidationException(
                    "resources is required for connector " + connector.getUuid() + ", which discovers several kinds");
        }
        // Asked inline, as the create path already asks the connector to validate attributes. Catching an
        // unsupported resource now costs one call; catching it at start costs a run that opens and immediately fails.
        List<Resource> supported = liveSupportedResources(connector.getUuid());
        List<Resource> unsupported = request
                .getResources()
                .stream()
                .filter(resource -> !supported.contains(resource))
                .toList();
        if (!unsupported.isEmpty()) {
            throw new ValidationException("Connector " + connector.getUuid() + " does not discover "
                    + unsupported.stream().map(Resource::getLabel).toList());
        }
        // What the connector claims to discover is its own answer, and a run may only target what this platform can
        // represent an item of. Without this a connector advertising anything else opens a run that fails later, at
        // ingest, where there is no caller left to tell.
        List<Resource> unrepresentable = request
                .getResources()
                .stream()
                .filter(resource -> !DiscoveredItemPayloadDto.DISCOVERABLE.contains(resource))
                .toList();
        if (!unrepresentable.isEmpty()) {
            throw new ValidationException(
                    "Discovery cannot report " + unrepresentable.stream().map(Resource::getLabel).toList());
        }
        // Each key must name a resource the run targets. Checked against resources rather than against what the
        // connector supports, because resources was just checked against that: keys are a subset of a subset. A key
        // outside it would send Core for a schema the run has no use for and file content nothing ever reads back.
        if (request.getResourceAttributes() != null) {
            List<Resource> untargeted = request
                    .getResourceAttributes()
                    .keySet()
                    .stream()
                    .filter(resource -> !request.getResources().contains(resource))
                    .toList();
            if (!untargeted.isEmpty()) {
                throw new ValidationException("resourceAttributes carries attributes for "
                        + untargeted.stream().map(Resource::getLabel).toList()
                        + ", which this discovery does not target");
            }
        }
    }

    /** What the connector says it can discover right now. Never persisted, so every caller asks. */
    private List<Resource> liveSupportedResources(UUID connectorUuid) throws NotFoundException, ConnectorException {
        ApiClientConnectorInfo connector = connectorService.getConnectorForApiClient(connectorUuid);
        return connectorApiFactory
                .getDiscoveryApiClientV2(connector)
                .listSupportedResources(connector)
                .stream()
                .map(DiscoverySupportedResourceDto::getResource)
                .toList();
    }

    /**
     * The discovery interface a run is driven through, resolved the way an authority instance resolves its own: the
     * caller names one, or a connector exposing exactly one has it chosen for it. Null means the connector declares no
     * discovery interface at all — a framework-v1 connector, and a v1 run.
     *
     * <p>
     * The adapter factory is the one place that maps a version onto a generation, so nothing here names one.
     */
    private ConnectorInterfaceEntity resolveDiscoveryInterface(UUID connectorUuid, UUID interfaceUuid) {
        List<ConnectorInterfaceEntity> interfaces = connectorInterfaceRepository
                .findByConnectorUuidAndInterfaceCode(connectorUuid, ConnectorInterface.DISCOVERY);
        if (interfaceUuid != null) {
            return interfaces
                    .stream()
                    .filter(iface -> interfaceUuid.equals(iface.getUuid()))
                    .findFirst()
                    .orElseThrow(() -> new ValidationException(
                            "Connector " + connectorUuid + " has no DISCOVERY interface with UUID " + interfaceUuid));
        }
        if (interfaces.size() > 1) {
            throw new ValidationException("Connector " + connectorUuid
                    + " exposes multiple DISCOVERY interfaces; supply interfaceUuid to select one.");
        }
        return interfaces.stream().findFirst().orElse(null);
    }

    /**
     * The connector's v2 discovery interface specifically, for the relays — they speak to it through the v2 API client,
     * so a different generation is not a matter of routing but of a client that does not exist yet.
     */
    private Optional<ConnectorInterfaceEntity> discoveryV2Interface(UUID connectorUuid) {
        return connectorInterfaceRepository
                .findByConnectorUuidAndInterfaceCodeAndVersion(connectorUuid, ConnectorInterface.DISCOVERY,
                        DISCOVERY_V2);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DETAIL)
    public DiscoveryDetailDto getDiscovery(SecuredUUID uuid) throws NotFoundException {
        Discovery discovery = getDiscoveryEntity(uuid);
        DiscoveryDetailDto dto = DiscoveryDtoMapper.toDetailDto(discovery, detailCounts.forRun(discovery));
        dto
                .setMetadata(attributeEngine
                        .getMappedMetadataContent(
                                ObjectAttributeContentInfo.builder(Resource.DISCOVERY, discovery.getUuid()).build()));
        dto
                .setAttributes(attributeEngine
                        .getObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(Resource.DISCOVERY, discovery.getUuid())
                                .connector(discovery.getConnectorUuid())
                                .build()));
        dto.setCustomAttributes(attributeEngine.getObjectCustomAttributesContent(Resource.DISCOVERY, uuid.getValue()));
        return dto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DETAIL)
    public DiscoveryCertificateResponseDto getDiscoveryCertificates(SecuredUUID uuid, Boolean newlyDiscovered,
            int itemsPerPage, int pageNumber) throws NotFoundException {
        Discovery discovery = getDiscoveryEntity(uuid);
        // Page number for the user always starts from 1. But for JPA, page number starts from 0
        Pageable p = PageRequest.of(pageNumber > 1 ? pageNumber - 1 : 0, itemsPerPage);
        List<DiscoveryCertificate> certificates;
        Long maxItems;
        if (newlyDiscovered == null) {
            certificates = discoveryCertificateRepository.findByDiscovery(discovery, p);
            maxItems = discoveryCertificateRepository.countByDiscovery(discovery);
        } else {
            certificates = discoveryCertificateRepository
                    .findByDiscoveryUuidAndNewlyDiscovered(discovery.getUuid(), newlyDiscovered, p);
            maxItems = discoveryCertificateRepository.countByDiscoveryAndNewlyDiscovered(discovery, newlyDiscovered);
        }

        final DiscoveryCertificateResponseDto responseDto = new DiscoveryCertificateResponseDto();
        responseDto.setCertificates(certificates.stream().map(DiscoveryCertificate::mapToDto).toList());
        responseDto.setItemsPerPage(itemsPerPage);
        responseDto.setPageNumber(pageNumber);
        responseDto.setTotalItems(maxItems);
        responseDto.setTotalPages((int) Math.ceil((double) maxItems / itemsPerPage));
        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DETAIL)
    public PaginationResponseDto<DiscoveryMessageDto> getDiscoveryRunMessages(SecuredUUID uuid, int itemsPerPage,
            int pageNumber) throws NotFoundException {
        Discovery discovery = getDiscoveryEntity(uuid);
        int pageSize = Math.clamp(itemsPerPage, 1, MAX_ITEMS_PER_PAGE);
        Pageable p = PageRequest.of(pageNumber > 1 ? pageNumber - 1 : 0, pageSize);

        Page<DiscoveryMessage> page = discoveryMessageRepository
                .findByDiscoveryUuidOrderByIdAsc(discovery.getUuid(), p);

        PaginationResponseDto<DiscoveryMessageDto> responseDto = new PaginationResponseDto<>();
        responseDto.setItems(page.getContent().stream().map(DiscoveryDtoMapper::toMessageDto).toList());
        responseDto.setItemsPerPage(pageSize);
        responseDto.setPageNumber(pageNumber);
        responseDto.setTotalItems(page.getTotalElements());
        responseDto.setTotalPages(page.getTotalPages());
        return responseDto;
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DETAIL)
    public PaginationResponseDto<DiscoveryItemDto> getDiscoveryItems(SecuredUUID uuid, Resource resource,
            Boolean newlyDiscovered, int itemsPerPage, int pageNumber) throws NotFoundException {
        Discovery discovery = getDiscoveryEntity(uuid);
        int pageSize = Math.clamp(itemsPerPage, 1, MAX_ITEMS_PER_PAGE);
        long offset = (long) (pageNumber > 1 ? pageNumber - 1 : 0) * pageSize;
        // Both stores hold the enum member name, not the wire code the request carries.
        String resourceName = resource == null ? null : resource.name();

        List<DiscoveryItemDto> items = discoveryItemRepository
                .listItems(discovery.getUuid(), resourceName, newlyDiscovered, pageSize, offset)
                .stream()
                .map(DiscoveryDtoMapper::toItemDto)
                .toList();
        long totalItems = discoveryItemRepository.countItems(discovery.getUuid(), resourceName, newlyDiscovered);

        PaginationResponseDto<DiscoveryItemDto> responseDto = new PaginationResponseDto<>();
        responseDto.setItems(items);
        responseDto.setItemsPerPage(pageSize);
        responseDto.setPageNumber(pageNumber);
        responseDto.setTotalItems(totalItems);
        responseDto.setTotalPages((int) Math.ceil((double) totalItems / pageSize));
        return responseDto;
    }

    // Lifecycle operations. NOT_SUPPORTED because each one calls the connector, which must never happen
    // inside a transaction; the adapter opens its own around each state change.

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.STOP)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void stopDiscovery(SecuredUUID uuid) throws NotFoundException, ConnectorException {
        lifecycle(uuid, "stopped", DiscoveryProviderAdapter::stop);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.RESUME)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void resumeDiscovery(SecuredUUID uuid) throws NotFoundException, ConnectorException {
        lifecycle(uuid, "resumed", DiscoveryProviderAdapter::resume);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.CANCEL)
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void cancelDiscovery(SecuredUUID uuid) throws NotFoundException, ConnectorException {
        lifecycle(uuid, "cancelled", DiscoveryProviderAdapter::cancel);
    }

    /**
     * Routes one lifecycle operation to the adapter for the run's connector generation.
     *
     * <p>
     * A v1 adapter refuses with {@link UnsupportedOperationException}, which has no handler and would reach the client
     * as a 500. Translated here into the same 422 an illegal transition answers with: from a caller's side both mean
     * the same thing — this run cannot be asked to do this.
     */
    private void lifecycle(SecuredUUID uuid, String verb, DiscoveryLifecycleOperation operation)
            throws NotFoundException, ConnectorException {
        Discovery discovery = getDiscoveryEntity(uuid);
        try {
            operation.perform(discoveryProviderAdapterFactory.forDiscovery(discovery), discovery);
        } catch (UnsupportedOperationException | UnsupportedDiscoveryVersionException e) {
            // The adapter's own words say which generation refused and why; they stay in the log rather than on the
            // wire, where a connector-reported version string would be unvalidated input.
            logger.debug("Discovery {} cannot be {}", uuid.getValue(), verb, e);
            throw new ValidationException(
                    "Discovery " + uuid.getValue() + " cannot be " + verb + ": not supported by its connector version");
        }
    }

    /** What {@link #lifecycle} routes: an adapter operation that may fail at the connector. */
    @FunctionalInterface
    private interface DiscoveryLifecycleOperation {
        void perform(DiscoveryProviderAdapter adapter, Discovery discovery) throws ConnectorException;
    }

    // S8989 wants explicit rollbackFor on the class-level @Transactional for this checked exception; changing
    // rollback semantics is behavior, not cleanup, and the platform-wide convention is the default rollback.
    @SuppressWarnings("java:S8989")
    public Discovery getDiscoveryEntity(SecuredUUID uuid) throws NotFoundException {
        return discoveryRepository.findByUuid(uuid).orElseThrow(() -> new NotFoundException(Discovery.class, uuid));
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DELETE)
    public void deleteDiscovery(SecuredUUID uuid) throws NotFoundException {
        Discovery discovery = discoveryRepository
                .findByUuid(uuid)
                .orElseThrow(() -> new NotFoundException(Discovery.class, uuid));
        // A v2 run still at its connector is driven by agenda rows this delete would cascade away, so nothing would
        // ever end it: no terminal transition, no DISCOVERY_FINISHED, a connector still scanning, and a scheduled
        // job left open forever now that the task waits for that event. Cancel ends it properly first.
        //
        // Terminal, so PROCESSING is refused too: the connector is done with such a run but Core is not, and the
        // delete would cascade away the agenda rows its import runs on, leaving a scheduled run's history never
        // told it ended. Nothing needs rescuing from PROCESSING -- the process worker ends it. A v1 run has no
        // agenda and its provider call is already over, so it can be deleted directly.
        if (discovery.getConnectorInterfaceUuid() != null && !DiscoveryRunLifecycle.isTerminal(discovery.getStatus())) {
            throw new ValidationException("Discovery " + uuid.getValue() + " is " + discovery.getStatus().getLabel()
                    + " and cannot be deleted; cancel it first");
        }
        Long certsDeleted = discoveryCertificateRepository.deleteByDiscovery(discovery);
        logger.debug("Deleted {} discovery certificates", certsDeleted);

        Integer certContentsDeleted = certificateContentRepository.deleteUnusedCertificateContents();
        logger.debug("Deleted {} unused certificate contents", certContentsDeleted);

        attributeEngine.deleteObjectAttributeContent(Resource.DISCOVERY, discovery.getUuid());
        commentService.removeObjectComments(Resource.DISCOVERY, discovery.getUuid());
        discoveryRepository.delete(discovery);
        triggerInternalService.deleteTriggerAssociations(Resource.DISCOVERY, discovery.getUuid());

        try {
            String referenceUuid = discovery.getDiscoveryConnectorReference();
            if (referenceUuid != null && !referenceUuid.isEmpty()) {
                Connector connector = connectorRepository
                        .findByUuid(discovery.getConnectorUuid())
                        .orElseThrow(() -> new NotFoundException(Connector.class, discovery.getConnectorUuid()));
                ApiClientConnectorInfo connectorDto = connectorService.getConnectorForApiClient(connector.getUuid());
                DiscoverySyncApiClient client = connectorApiFactory.getDiscoveryApiClient(connectorDto);
                client.removeDiscovery(connectorDto, referenceUuid);
            }
        } catch (ConnectorException e) {
            logger.warn("Failed to delete discovery in the connector. But core history is deleted");
            logger.warn(e.getMessage());
        } catch (Exception e) {
            logger.warn(e.getMessage());
        }
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DELETE)
    @Async
    public void bulkRemoveDiscovery(List<SecuredUUID> discoveryUuids) throws NotFoundException {
        UUID loggedUserUuid = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
        List<UUID> refused = new ArrayList<>();
        for (SecuredUUID uuid : discoveryUuids) {
            try {
                deleteDiscovery(uuid);
            } catch (ValidationException | NotFoundException e) {
                // A v2 run still at its connector refuses deletion until it is cancelled, and a run someone else
                // deleted between the selection and this async pass is already gone. Neither may decide the fate of
                // the rest of the batch, which would otherwise stop here and leave the caller a single error.
                refused.add(uuid.getValue());
                logger.debug("Discovery {} was not deleted in the bulk request: {}", uuid.getValue(), e.getMessage());
            }
        }
        notificationProducer
                .produceInternalNotificationMessage(Resource.DISCOVERY, null,
                        NotificationRecipient.buildUserNotificationRecipient(loggedUserUuid),
                        refused.isEmpty()
                                ? "Discovery histories have been deleted."
                                : "Discovery histories have been deleted, except " + refused.size()
                                        + " that are still running. Cancel those first.",
                        null);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.LIST)
    public Long statisticsDiscoveryCount(SecurityFilter filter) {
        return discoveryRepository.countUsingSecurityFilter(filter, null);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.CREATE)
    // NOT_SUPPORTED because validation asks the connector what it can discover, and a connector call must never
    // hold a transaction open -- a slow or hostile connector would pin a pooled connection for its whole timeout.
    // Everything this method then persists commits as one unit, in DiscoveryRunWriter's own transaction.
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DiscoveryDetailDto createDiscovery(final DiscoveryDto request, final boolean saveEntity)
            throws AlreadyExistException, ConnectorException, AttributeException, NotFoundException {
        if (discoveryRepository.findByName(request.getName()).isPresent()) {
            throw new AlreadyExistException(Discovery.class, request.getName());
        }
        if (request.getConnectorUuid() == null) {
            throw new ValidationException(ValidationError.create("Connector UUID is empty"));
        }
        Connector connector = connectorRepository
                .findByUuid(UUID.fromString(request.getConnectorUuid()))
                .orElseThrow(() -> new NotFoundException(Connector.class, request.getConnectorUuid()));

        attributeEngine.validateCustomAttributesContent(Resource.DISCOVERY, request.getCustomAttributes());

        ConnectorInterfaceEntity discoveryInterface = resolveDiscoveryInterface(connector.getUuid(),
                request.getInterfaceUuid());
        validateRequestedResources(request, connector, discoveryInterface);
        validateRunAttributes(request, connector, discoveryInterface);

        Discovery discovery = new Discovery();
        discovery.setName(request.getName());
        discovery.setConnectorName(connector.getName());
        // The association is what routes every later operation to the v2 adapter; without it the run is a v1 run
        // no matter what the connector implements.
        if (discoveryInterface != null) {
            discovery.setConnectorInterface(discoveryInterface);
            discovery.setResources(List.copyOf(request.getResources()));
        }
        // Captured here rather than at start: this is where a caller is still on the thread. A v2 run's import
        // runs from an agenda tick with no principal of its own, and authorization refuses CERTIFICATE:CREATE
        // without one, so the run has to remember who to act as.
        discovery.setStartedByUserUuid(AuthHelper.getActingUserUuidOrNull());
        discovery.setStartTime(OffsetDateTime.now(ZoneOffset.UTC));
        discovery.setStatus(DiscoveryStatus.IN_PROGRESS);
        discovery.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        discovery.setConnectorUuid(connector.getUuid());
        discovery.setKind(request.getKind());

        if (saveEntity) {
            // Everything the connector has to say is read here, before a transaction exists, so the writes below can
            // commit as one unit without a connector call inside them.
            return discoveryRunWriter
                    .createRun(discovery, request, connector.getUuid(), fetchResourceDefinitions(request, connector));
        }

        return null;
    }

    @Override
    @Async
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.CREATE)
    public void runDiscoveryAsync(UUID discoveryUuid) {
        runDiscovery(discoveryUuid, null);
    }

    @Override
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.CREATE)
    public DiscoveryDetailDto runDiscovery(UUID discoveryUuid, ScheduledJobInfo scheduledJobInfo) {
        // Routed on the association alone. Loading the run here would park it in the first-level cache this
        // NOT_SUPPORTED scope shares across every read, where a later read answers from the stale copy.
        UUID connectorInterfaceUuid = discoveryRepository.findConnectorInterfaceUuid(discoveryUuid).orElse(null);
        try {
            return discoveryProviderAdapterFactory
                    .forConnectorInterface(connectorInterfaceUuid, discoveryUuid)
                    .start(discoveryUuid, scheduledJobInfo);
        } catch (UnsupportedDiscoveryVersionException e) {
            // A routing refusal must still end as a terminal, user-visible run state: the async caller swallows
            // whatever escapes here, and the scheduler expects a result rather than an exception.
            logger.warn("Discovery {} cannot be dispatched: {}", discoveryUuid, e.getMessage());
            // Resolved before the terminal write, so a failed lookup cannot leave the run FAILED without its event.
            UUID actingUserUuid = AuthHelper.getActingUserUuidOrNull();
            // The curated text, not e.getMessage(): the raw message carries the connector-reported version
            // string, which is unvalidated input — it stays in the log, like the REST handler's fixed body.
            // The writer maps the detail — see its javadoc for why this scope cannot re-read it.
            DiscoveryDetailDto failedDetail = discoveryWriter
                    .markDispatchRefused(discoveryUuid, UNSUPPORTED_VERSION_MESSAGE)
                    .orElseThrow(() -> e);
            eventProducer
                    .produceMessage(DiscoveryFinishedEventHandler
                            .constructEventMessage(discoveryUuid, actingUserUuid, null,
                                    new DiscoveryResult(DiscoveryStatus.FAILED, UNSUPPORTED_VERSION_MESSAGE)));
            return failedDetail;
        }
    }

    @Override
    public NameAndUuidDto getResourceObjectInternal(UUID objectUuid) throws NotFoundException {
        return discoveryRepository.findResourceObject(objectUuid, Discovery_.name);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.DETAIL)
    public NameAndUuidDto getResourceObjectExternal(SecuredUUID objectUuid) throws NotFoundException {
        return discoveryRepository.findResourceObject(objectUuid.getValue(), Discovery_.name);
    }

    @Override
    public List<NameAndUuidDto> listResourceObjects(SecurityFilter filter, List<SearchFilterRequestDto> filters,
            PaginationRequestDto pagination) {
        throw new NotSupportedException("Listing of resource objects is not supported for resource discoveries.");
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.UPDATE)
    public void evaluatePermissionChain(SecuredUUID uuid) throws NotFoundException {
        getDiscoveryEntity(uuid);
    }

    @Override
    @ExternalAuthorization(resource = Resource.DISCOVERY, action = ResourceAction.LIST)
    public List<SearchFieldDataByGroupDto> getSearchableFieldInformationByGroup() {
        final List<SearchFieldDataByGroupDto> searchFieldDataByGroupDtos = attributeEngine
                .getResourceSearchableFields(Resource.DISCOVERY, false);

        List<SearchFieldDataDto> fields = List
                .of(SearchHelper.prepareSearch(FilterField.DISCOVERY_NAME),
                        SearchHelper
                                .prepareSearch(FilterField.DISCOVERY_STATUS,
                                        Arrays.stream(DiscoveryStatus.values()).map(DiscoveryStatus::getCode).toList()),
                        SearchHelper.prepareSearch(FilterField.DISCOVERY_START_TIME),
                        SearchHelper.prepareSearch(FilterField.DISCOVERY_END_TIME),
                        SearchHelper.prepareSearch(FilterField.DISCOVERY_TOTAL_CERT_DISCOVERED),
                        SearchHelper
                                .prepareSearch(FilterField.DISCOVERY_CONNECTOR_NAME,
                                        discoveryRepository.findDistinctConnectorName()),
                        SearchHelper.prepareSearch(FilterField.DISCOVERY_KIND)

                );

        fields = new ArrayList<>(fields);
        fields.sort(new SearchFieldDataComparator());

        searchFieldDataByGroupDtos.add(new SearchFieldDataByGroupDto(fields, FilterFieldSource.PROPERTY));

        logger.debug("Searchable Fields by Groups: {}", searchFieldDataByGroupDtos);
        return searchFieldDataByGroupDtos;
    }

}
