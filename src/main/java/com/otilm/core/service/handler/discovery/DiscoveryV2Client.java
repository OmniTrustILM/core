package com.otilm.core.service.handler.discovery;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
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
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.OutboundSecretLeakException;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.service.handler.OperationAttributeResolver;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
    private final OperationAttributeResolver operationAttributeResolver;
    private final OutboundSecretContainment outboundContainment;
    private final DiscoveryDeliveryModeOffer deliveryModeOffer;

    public DiscoveryV2Client(ConnectorApiFactory connectorApiFactory, ConnectorRepository connectorRepository,
            AttributeEngine attributeEngine, OperationAttributeResolver operationAttributeResolver,
            OutboundSecretContainment outboundContainment, DiscoveryDeliveryModeOffer deliveryModeOffer) {
        this.connectorApiFactory = connectorApiFactory;
        this.connectorRepository = connectorRepository;
        this.attributeEngine = attributeEngine;
        this.operationAttributeResolver = operationAttributeResolver;
        this.outboundContainment = outboundContainment;
        this.deliveryModeOffer = deliveryModeOffer;
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
        Set<String> sentSecrets = populateForRunReason(request, run, connector);
        return withoutWordsWhenRefused(
                () -> connectorApiFactory.getDiscoveryApiClientV2(connector).initiate(connector, request), sentSecrets);
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DiscoveryStatusResponseDto status(Discovery run)
            throws ConnectorException, NotFoundException, AttributeException {
        ConnectorDto connector = connectorOf(run);
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        Set<String> sentSecrets = populateForRunReason(request, run, connector);
        DiscoveryStatusResponseDto status = withoutWordsWhenRefused(
                () -> connectorApiFactory.getDiscoveryApiClientV2(connector).status(connector, request), sentSecrets);
        return contained(status, sentSecrets, "status");
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
        Set<String> sentSecrets = populate(request, run, connector);
        return withoutWordsWhenRefused(
                () -> connectorApiFactory.getDiscoveryApiClientV2(connector).stop(connector, request), sentSecrets);
    }

    /** Restarts a stopped run from its checkpoint. Answers the same shape as initiate: a handle and stoppability. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DiscoveryInitiateResponseDto resume(Discovery run)
            throws ConnectorException, NotFoundException, AttributeException {
        ConnectorDto connector = connectorOf(run);
        DiscoveryRunRequestDto request = new DiscoveryRunRequestDto();
        Set<String> sentSecrets = populate(request, run, connector);
        return withoutWordsWhenRefused(
                () -> connectorApiFactory.getDiscoveryApiClientV2(connector).resume(connector, request), sentSecrets);
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
        Set<String> sentSecrets = populate(request, run, connector);
        return withoutWordsWhenRefused(
                () -> connectorApiFactory.getDiscoveryApiClientV2(connector).cancel(connector, request), sentSecrets);
    }

    private DiscoveryResultsResponseDto drain(Discovery run, long afterSequence, int maxItems, long maxBytes)
            throws ConnectorException, NotFoundException, AttributeException {
        ConnectorDto connector = connectorOf(run);
        DiscoveryDrainRequestDto request = new DiscoveryDrainRequestDto();
        Set<String> sentSecrets = populateForRunReason(request, run, connector);
        request.setDeliveryModes(drainOffer(run));
        request.setAfterSequence(afterSequence);
        request.setMaxItems(maxItems);
        request.setMaxBytes(Math.min(maxBytes, pageCeiling(run)));
        DiscoveryResultsResponseDto page = withoutWordsWhenRefused(
                () -> connectorApiFactory.getDiscoveryApiClientV2(connector).results(connector, request), sentSecrets);
        return contained(page, sentSecrets, "results");
    }

    /**
     * The most item bytes a page may ask for. The contract's cap, since a configured value above it produces a request
     * the connector rejects on every drain; for a checkpointed run less the room its response keeps for the page's
     * checkpoint and the rest of the envelope, so a full page still fits the transport.
     */
    private static long pageCeiling(Discovery run) {
        if (run.getDeliveryMode() == DiscoveryDeliveryMode.CHECKPOINTED) {
            return DiscoveryDrainRequestDto.MAX_BYTES_CAP - DiscoveryDrainRequestDto.CHECKPOINTED_RESPONSE_RESERVE;
        }
        return DiscoveryDrainRequestDto.MAX_BYTES_CAP;
    }

    /**
     * Runs a connector call whose refusal reaches the API caller or the log: without the connector's words when the
     * request carried a secret, which the caller may not be allowed to read.
     */
    private <T> T withoutWordsWhenRefused(ConnectorCall<T> call, Set<String> sentSecrets) throws ConnectorException {
        try {
            return call.execute();
        } catch (ConnectorException e) {
            throw outboundContainment.withoutWords(e, sentSecrets, "run");
        } catch (ValidationException e) {
            throw outboundContainment.withoutWords(e, sentSecrets, "run");
        }
    }

    @FunctionalInterface
    private interface ConnectorCall<T> {
        T execute() throws ConnectorException;
    }

    /**
     * Fails closed on a response that echoes a secret Core resolved into the request, or carries a secret-bearing shape
     * at all.
     *
     * <p>
     * Applied to {@code status} and {@code results}, whose metadata and items the API serves. A mutating call is not:
     * the connector has already acted by the time it answers, so refusing would strand an initiate Core cannot cancel
     * or keep a resumed run STOPPED, and its response carries only a checkpoint nobody is shown.
     * {@code AuthorityProviderV3Adapter} draws the same line.
     */
    private <T> T contained(T response, Set<String> sentSecrets, String operation) throws ConnectorException {
        try {
            outboundContainment.assertNoExpandedSecretOutbound(response, sentSecrets);
        } catch (OutboundSecretLeakException e) {
            throw new ConnectorException(
                    "The connector's %s response was refused: it carries secret material Core resolved for this run"
                            .formatted(operation),
                    e);
        }
        return response;
    }

    /**
     * As {@link #populate}, for the calls whose failure becomes the run's reason: start, status and results. A resolver
     * refusal surfaces as a {@link DiscoveryReferenceException}, which spends a checkpointed run's retries rather than
     * ending it at once, and which the run's reason names.
     */
    private Set<String> populateForRunReason(DiscoveryV2ScopedRequestDto request, Discovery run, ConnectorDto connector)
            throws ConnectorException {
        try {
            return populate(request, run, connector);
        } catch (ValidationException e) {
            throw DiscoveryReferenceException.refused(e);
        }
    }

    /**
     * Fills the identity and configuration every v2 request carries. Run-level attributes sit under {@link #RUN_SCOPE};
     * per-resource ones under the resource's wire code, which is how the create path separates them.
     *
     * <p>
     * The resource set goes on every request, not only initiate: a stateless connector rebuilding a resumed run cannot
     * recover it from {@code resourceAttributes}, which omits any resource declaring no attributes of its own. So do
     * the offered delivery modes, which a connector checks before it accepts a run and again before it resumes one.
     *
     * @return the secret values resolved into the request, for {@link #contained} to catch on the way back
     */
    private Set<String> populate(DiscoveryV2ScopedRequestDto request, Discovery run, ConnectorDto connector)
            throws ConnectorException {
        request.setRunId(run.getUuid());
        request.setCheckpoint(run.getCheckpoint());
        request.setResources(resourcesOf(run));
        request.setDeliveryModes(deliveryModeOffer.offered());
        Map<String, List<RequestAttribute>> scopes = resolvedScopes(run, connector);
        request.setAttributes(scopes.getOrDefault(RUN_SCOPE, List.of()));
        Map<Resource, List<RequestAttribute>> byResource = new EnumMap<>(Resource.class);
        for (Resource resource : resourcesOf(run)) {
            List<RequestAttribute> attributes = scopes.getOrDefault(resource.getCode(), List.of());
            if (!attributes.isEmpty()) {
                byResource.put(resource, attributes);
            }
        }
        request.setResourceAttributes(byResource);
        Set<String> sentSecrets = new HashSet<>();
        outboundContainment.recordExpandedSecretsFromRequest(request.getAttributes(), sentSecrets);
        byResource.values().forEach(sent -> outboundContainment.recordExpandedSecretsFromRequest(sent, sentSecrets));
        return sentSecrets;
    }

    /**
     * The configured offer, with checkpointed prepended when it lacks it and the run is already in checkpointed
     * delivery: such a run can only continue that way, and a connector answers a drain that does not offer it as busy.
     */
    private List<DiscoveryDeliveryMode> drainOffer(Discovery run) {
        List<DiscoveryDeliveryMode> configured = deliveryModeOffer.offered();
        if (run.getDeliveryMode() != DiscoveryDeliveryMode.CHECKPOINTED
                || configured.contains(DiscoveryDeliveryMode.CHECKPOINTED)) {
            return configured;
        }
        List<DiscoveryDeliveryMode> withCheckpointed = new ArrayList<>(configured.size() + 1);
        withCheckpointed.add(DiscoveryDeliveryMode.CHECKPOINTED);
        withCheckpointed.addAll(configured);
        return withCheckpointed;
    }

    /**
     * Every scope's attributes as the connector receives them: with their credentials and referenced objects resolved,
     * including the references nested inside those objects, through the resolver an authority's own operations use.
     */
    private Map<String, List<RequestAttribute>> resolvedScopes(Discovery run, ConnectorDto connector)
            throws ConnectorException {
        Map<String, List<DataAttribute>> definitions = definitionScopes(run, connector);
        // Resolved once per distinct definition across all scopes: a SECRET lookup is a connector round trip.
        Map<String, DataAttribute> distinct = new LinkedHashMap<>();
        Map<DataAttribute, String> keys = new IdentityHashMap<>();
        for (List<DataAttribute> scope : definitions.values()) {
            for (DataAttribute definition : scope) {
                String key = AttributeDefinitionUtils.serialize(definition);
                keys.put(definition, key);
                distinct.putIfAbsent(key, definition);
            }
        }
        List<DataAttribute> toResolve = List.copyOf(distinct.values());
        List<RequestAttribute> sent = AttributeDefinitionUtils.getClientAttributes(toResolve);
        if (referencesAnything(toResolve)) {
            sent = resolveAsSystem(connector, sent);
        }
        List<String> distinctKeys = List.copyOf(distinct.keySet());
        if (sent.size() != distinctKeys.size()) {
            throw new IllegalStateException("Resolving the run's attributes returned %d attributes for %d"
                    .formatted(sent.size(), distinctKeys.size()));
        }
        Map<String, RequestAttribute> sentByKey = new HashMap<>();
        for (int i = 0; i < distinctKeys.size(); i++) {
            sentByKey.put(distinctKeys.get(i), sent.get(i));
        }
        Map<String, List<RequestAttribute>> scopes = new LinkedHashMap<>();
        definitions
                .forEach((scope, scopeDefinitions) -> scopes
                        .put(scope,
                                scopeDefinitions
                                        .stream()
                                        .map(definition -> sentByKey.get(keys.get(definition)))
                                        .toList()));
        return scopes;
    }

    /**
     * The run's attributes as the connector receives them. A reference the resolver refuses, such as one to an object
     * that is gone, is a {@link ValidationException} naming it, which reaches the user who stops, resumes or cancels
     * the run. So is stored data Core rejects while resolving, such as a malformed reference or a vault profile
     * attribute the vault's current definitions no longer accept. A failure of another connector the resolver asks,
     * such as a secret's vault, becomes a server failure, so it is never read as the discovery connector's own answer.
     */
    private List<RequestAttribute> resolveAsSystem(ConnectorDto connector, List<RequestAttribute> attributes)
            throws ConnectorException {
        try {
            return operationAttributeResolver
                    .resolveWithNestedReferencesAsSystem(UUID.fromString(connector.getUuid()), attributes);
        } catch (ConnectorException e) {
            if (e.getCause() instanceof AttributeException || e.getCause() instanceof NotFoundException) {
                throw new ValidationException(e.getCause().getMessage());
            }
            throw DiscoveryReferenceException.failed(e);
        }
    }

    /**
     * Whether any definition points at another object. When none does, the resolver and its elevation's auth-service
     * round trip are skipped — a STATUS or DRAIN tick walks this path for the whole life of every run.
     */
    private static boolean referencesAnything(List<DataAttribute> definitions) {
        return definitions.stream().anyMatch(definition -> {
            AttributeContentType contentType = definition.getContentType();
            return contentType == AttributeContentType.CREDENTIAL || contentType == AttributeContentType.RESOURCE;
        });
    }

    /** The run's own definitions under {@link #RUN_SCOPE}, then each targeted resource's under its wire code. */
    private Map<String, List<DataAttribute>> definitionScopes(Discovery run, ConnectorDto connector) {
        Map<String, List<DataAttribute>> scopes = new LinkedHashMap<>();
        scopes.put(RUN_SCOPE, fromEngine(run, connector, null));
        for (Resource resource : resourcesOf(run)) {
            scopes.put(resource.getCode(), fromEngine(run, connector, resource.getCode()));
        }
        return scopes;
    }

    private List<DataAttribute> fromEngine(Discovery run, ConnectorDto connector, String operation) {
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
