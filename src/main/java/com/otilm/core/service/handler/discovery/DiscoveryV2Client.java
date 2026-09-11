package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStopResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoverySupportedResourceDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryV2ScopedRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.service.CredentialInternalService;
import com.otilm.core.service.ResourceInternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.AuthHelper;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The discovery v2 connector calls the tick workers make, with the request every one of them shares built in one place.
 *
 * <p>
 * <b>Why the request is rebuilt every time:</b> a discovery v2 connector keeps no Core-visible state, so identity, the
 * connector's own run handle and the run's whole attribute configuration are replayed on every call. The handle is read
 * from the run each time — it changes as the run progresses, and a stale one addresses a run the connector has moved on
 * from.
 *
 * <p>
 * <b>{@code NOT_SUPPORTED}:</b> reading the run's attributes touches the database, but the connector call must never
 * run inside a transaction or hold a row lock — the platform-wide rule the {@code ConnectorApiClientArchTest} and
 * {@code TransactionalBoundaryArchTest} fences protect. Suspending any ambient transaction here makes that hold even
 * when a caller forgets.
 */
@Component
public class DiscoveryV2Client {

    /** Scope key the run's own attributes sit under; a resource's sit under its wire code. */
    static final String RUN_SCOPE = "";

    private final ConnectorApiFactory connectorApiFactory;
    private final ConnectorRepository connectorRepository;
    private final AttributeEngine attributeEngine;
    private final CredentialInternalService credentialService;
    private final ResourceInternalService resourceService;
    private final AuthHelper authHelper;

    public DiscoveryV2Client(ConnectorApiFactory connectorApiFactory, ConnectorRepository connectorRepository,
            AttributeEngine attributeEngine, CredentialInternalService credentialService,
            ResourceInternalService resourceService, AuthHelper authHelper) {
        this.connectorApiFactory = connectorApiFactory;
        this.connectorRepository = connectorRepository;
        this.attributeEngine = attributeEngine;
        this.credentialService = credentialService;
        this.resourceService = resourceService;
        this.authHelper = authHelper;
    }

    /** What this connector can discover, as it reports right now. Never persisted, so it is always asked. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public List<Resource> supportedResources(Discovery run) throws ConnectorException, NotFoundException {
        ConnectorDto connector = connectorOf(run);
        return connectorApiFactory
                .getDiscoveryApiClientV2(connector)
                .listSupportedResources(connector)
                .stream()
                .map(DiscoverySupportedResourceDto::getResource)
                .toList();
    }

    /** Opens the run at the connector, minting the handle every later call replays. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DiscoveryInitiateResponseDto initiate(Discovery run)
            throws ConnectorException, NotFoundException, AttributeException {
        ConnectorDto connector = connectorOf(run);
        DiscoveryInitiateRequestDto request = new DiscoveryInitiateRequestDto();
        populate(request, run, connector);
        return connectorApiFactory.getDiscoveryApiClientV2(connector).initiate(connector, request);
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DiscoveryStatusResponseDto status(Discovery run)
            throws ConnectorException, NotFoundException, AttributeException {
        ConnectorDto connector = connectorOf(run);
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        populate(request, run, connector);
        return connectorApiFactory.getDiscoveryApiClientV2(connector).status(connector, request);
    }

    /**
     * Pulls one page of results after the run's ingestion cursor.
     *
     * @param maxItems and {@code maxBytes} bound the page so a single response stays inside what the platform's
     * tunneled transport carries
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DiscoveryResultsResponseDto results(Discovery run, int maxItems, long maxBytes)
            throws ConnectorException, NotFoundException, AttributeException {
        return drain(run, run.getLastAppliedSequence(), maxItems, maxBytes);
    }

    /**
     * The contract's full acknowledgement — a drain positioned past the last item the connector counted, which tells it
     * every item was received and its run state may be discarded. Asks for a single item because the response body is
     * not the point; the cursor it carries is.
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void acknowledge(Discovery run, long highestSequence)
            throws ConnectorException, NotFoundException, AttributeException {
        drain(run, highestSequence, 1, 1024L);
    }

    /** Asks the connector to checkpoint and pause. Returns the refreshed handle, which replaces the stored one. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DiscoveryStopResponseDto stop(Discovery run)
            throws ConnectorException, NotFoundException, AttributeException {
        ConnectorDto connector = connectorOf(run);
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        populate(request, run, connector);
        return connectorApiFactory.getDiscoveryApiClientV2(connector).stop(connector, request);
    }

    /** Restarts a stopped run from its checkpoint. Answers the same shape as initiate: a handle and stoppability. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DiscoveryInitiateResponseDto resume(Discovery run)
            throws ConnectorException, NotFoundException, AttributeException {
        ConnectorDto connector = connectorOf(run);
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        populate(request, run, connector);
        return connectorApiFactory.getDiscoveryApiClientV2(connector).resume(connector, request);
    }

    /**
     * Tells the connector to drop the run.
     *
     * @return the raw response, because its status is the answer: {@code 204} cancelled, {@code 404} the connector no
     * longer tracks the run — which is the state cancel asked for, so the caller reads it as success rather than
     * catching it
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<Void> cancel(Discovery run) throws ConnectorException, NotFoundException, AttributeException {
        ConnectorDto connector = connectorOf(run);
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        populate(request, run, connector);
        return connectorApiFactory.getDiscoveryApiClientV2(connector).cancel(connector, request);
    }

    private DiscoveryResultsResponseDto drain(Discovery run, long afterSequence, int maxItems, long maxBytes)
            throws ConnectorException, NotFoundException, AttributeException {
        ConnectorDto connector = connectorOf(run);
        DiscoveryDrainRequestDto request = new DiscoveryDrainRequestDto();
        populate(request, run, connector);
        request.setAfterSequence(afterSequence);
        request.setMaxItems(maxItems);
        // Clamped to the contract's cap: a configured value above it would produce a request the connector
        // rejects on every single drain.
        request.setMaxBytes(Math.min(maxBytes, DiscoveryDrainRequestDto.MAX_BYTES_CAP));
        return connectorApiFactory.getDiscoveryApiClientV2(connector).results(connector, request);
    }

    /**
     * Fills the identity and configuration every v2 request carries. Run-level attributes sit under {@link #RUN_SCOPE};
     * per-resource ones under the resource's wire code, which is how the create path separates them.
     *
     * <p>
     * The resource set goes on every request, not only initiate: a stateless connector rebuilding a resumed run cannot
     * recover it from {@code resourceAttributes}, which omits any resource declaring no attributes of its own.
     */
    private void populate(DiscoveryV2ScopedRequestDto request, Discovery run, ConnectorDto connector)
            throws ConnectorException, NotFoundException, AttributeException {
        request.setRunId(run.getUuid());
        request.setMeta(run.getRunMeta());
        request.setResources(resourcesOf(run));
        Map<String, List<DataAttribute>> scopes = resolvedScopes(run, connector);
        request.setAttributes(AttributeDefinitionUtils.getClientAttributes(scopes.getOrDefault(RUN_SCOPE, List.of())));
        Map<Resource, List<RequestAttribute>> byResource = new EnumMap<>(Resource.class);
        for (Resource resource : resourcesOf(run)) {
            List<RequestAttribute> attributes = AttributeDefinitionUtils
                    .getClientAttributes(scopes.getOrDefault(resource.getCode(), List.of()));
            if (!attributes.isEmpty()) {
                byResource.put(resource, attributes);
            }
        }
        request.setResourceAttributes(byResource);
    }

    /**
     * Every scope's definitions with their credential and referenced-object content loaded, exactly as the v1 flow
     * resolves it before its own call.
     */
    private Map<String, List<DataAttribute>> resolvedScopes(Discovery run, ConnectorDto connector)
            throws ConnectorException, NotFoundException, AttributeException {
        Map<String, List<DataAttribute>> scopes = definitionScopes(run, connector);
        // Resolved across all scopes at once, and only once per distinct definition: a credential the run and a
        // resource both declare is one lookup, not two, and for a SECRET reference a lookup is a connector round
        // trip. Duplicates take the resolved content from the instance that was actually resolved.
        List<DataAttribute> toResolve = new ArrayList<>();
        Map<String, DataAttribute> firstOfEach = new LinkedHashMap<>();
        Map<DataAttribute, DataAttribute> duplicates = new IdentityHashMap<>();
        for (List<DataAttribute> scope : scopes.values()) {
            for (DataAttribute definition : scope) {
                DataAttribute first = firstOfEach
                        .putIfAbsent(AttributeDefinitionUtils.serialize(definition), definition);
                if (first == null) {
                    toResolve.add(definition);
                } else {
                    duplicates.put(definition, first);
                }
            }
        }
        if (referencesAnything(toResolve)) {
            dereferenceAsSystem(toResolve);
        }
        duplicates.forEach((duplicate, resolved) -> duplicate.setContent(resolved.getContent()));
        return scopes;
    }

    /**
     * Whether any definition points at another object. When none does, both loaders and the elevation's auth-service
     * round trip are skipped — a STATUS or DRAIN tick walks this path for the whole life of every run.
     */
    private static boolean referencesAnything(List<DataAttribute> definitions) {
        return definitions.stream().anyMatch(definition -> {
            AttributeContentType contentType = definition.getContentType();
            return contentType == AttributeContentType.CREDENTIAL || contentType == AttributeContentType.RESOURCE;
        });
    }

    /**
     * Dereferences under the {@code attribute-content-resolver} system identity, as {@code OperationAttributeResolver}
     * does. A tick worker and the reaper's sweep hold no principal, and {@code loadFullCredentialData} is gated on
     * {@code CREDENTIAL:DETAIL} at method entry — so they are refused before the loader can see whether there is a
     * credential to load.
     *
     * <p>
     * The elevation narrows nothing: these are the resource-level list loaders, which have no per-object gate (that is
     * {@code CredentialServiceImpl.getAuthorizedObjectAttributes}). It also drops an accidental requirement that an
     * operator hold {@code CREDENTIAL:DETAIL} to stop or resume a run. Collapsing into {@link ConnectorException} is
     * forced: the elevated body may declare only one checked type.
     */
    private void dereferenceAsSystem(List<DataAttribute> toResolve) throws ConnectorException {
        authHelper.runAsSystem(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME, () -> {
            try {
                credentialService.loadFullCredentialData(toResolve);
                resourceService.loadResourceObjectContentData(toResolve);
                return null;
            } catch (AttributeException | NotFoundException e) {
                // A dangling reference — a deleted credential or secret — is not a missing run, so it surfaces as
                // the connector call it prevents rather than a 404.
                throw new ConnectorException("Unable to resolve stored attribute references for the discovery run", e);
            }
        });
    }

    /** The run's own definitions under {@link #RUN_SCOPE}, then each targeted resource's under its wire code. */
    private Map<String, List<DataAttribute>> definitionScopes(Discovery run, ConnectorDto connector)
            throws NotFoundException, AttributeException {
        Map<String, List<DataAttribute>> scopes = new LinkedHashMap<>();
        scopes.put(RUN_SCOPE, fromEngine(run, connector, null));
        for (Resource resource : resourcesOf(run)) {
            scopes.put(resource.getCode(), fromEngine(run, connector, resource.getCode()));
        }
        return scopes;
    }

    private List<DataAttribute> fromEngine(Discovery run, ConnectorDto connector, String operation)
            throws NotFoundException, AttributeException {
        return attributeEngine
                .getDefinitionObjectAttributeContent(AttributeType.DATA, UUID.fromString(connector.getUuid()),
                        operation, Resource.DISCOVERY, run.getUuid());
    }

    private static List<Resource> resourcesOf(Discovery run) {
        return run.getResources() == null ? List.of() : run.getResources();
    }

    private ConnectorDto connectorOf(Discovery run) throws NotFoundException {
        Connector connector = connectorRepository
                .findByUuid(run.getConnectorUuid())
                .orElseThrow(() -> new NotFoundException(Connector.class, run.getConnectorUuid()));
        return connector.mapToDto();
    }
}
