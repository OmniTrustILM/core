package com.otilm.core.signing.formatting;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.AttributeVersionHelper;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.config.cache.ReadThroughCache;
import com.otilm.core.events.ConnectorChangedEvent;
import com.otilm.core.model.signing.workflow.ManagedContentSigningWorkflow;
import com.otilm.core.model.signing.workflow.ManagedTimestampingWorkflow;
import com.otilm.core.model.signing.workflow.SigningWorkflow;
import com.otilm.core.signing.contentsigning.formatting.ContentSigningFormattingAttributes;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.CacheManager;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Signature formatters' attribute definitions, cached for each load of a signing profile until the entry expires, the
 * profile is reloaded or the connector changes. A cache fill also stores what it read.
 */
@Component
public class FormattingAttributeDefinitions {

    private static final Logger logger = LoggerFactory.getLogger(FormattingAttributeDefinitions.class);
    private static final List<UUID> WHOLE_REGISTRY = null;
    private static final String CLIENT_MESSAGE = "Internal error during signature formatting";

    private final ConnectorApiFactory connectorApiFactory;
    private final ContentSigningFormattingAttributes contentSigningFormattingAttributes;
    private final AttributeEngine attributeEngine;
    private final CacheEvictor cacheEvictor;
    private final ReadThroughCache definitionsCache;

    public FormattingAttributeDefinitions(ConnectorApiFactory connectorApiFactory,
            ContentSigningFormattingAttributes contentSigningFormattingAttributes, AttributeEngine attributeEngine,
            CacheManager cacheManager, CacheEvictor cacheEvictor) {
        this.connectorApiFactory = connectorApiFactory;
        this.contentSigningFormattingAttributes = contentSigningFormattingAttributes;
        this.attributeEngine = attributeEngine;
        this.cacheEvictor = cacheEvictor;
        this.definitionsCache = ReadThroughCache.from(cacheManager, CacheConfig.FORMATTING_ATTRIBUTE_DEFINITIONS_CACHE);
    }

    /**
     * A timestamp formatter's definitions: the whole registry on its Attributes interface. Timestamping is the
     * formatter's only operation.
     */
    public List<BaseAttribute> forTimestamping(ApiClientConnectorInfo formatter, ManagedTimestampingWorkflow workflow)
            throws SigningEngineException {
        DefinitionsKey key = DefinitionsKey.of(formatter, workflow);
        return definitionsCache
                .getOrLoad(key, () -> fetchedAndStored(key.connectorUuid(), () -> liveForTimestamping(formatter)));
    }

    /** The same definitions, read from the formatter past the cache. */
    public List<BaseAttribute> liveForTimestamping(ApiClientConnectorInfo formatter)
            throws ConnectorException, ValidationException {
        AttributeDefinitionsDto published = connectorApiFactory
                .getAttributesApiClientV2(formatter)
                .listDefinitions(formatter, WHOLE_REGISTRY);
        if (published == null || published.getDefinitions() == null) {
            throw new ConnectorException("Signature formatting connector returned no attribute definitions", formatter);
        }
        return published.getDefinitions();
    }

    /** A content-signing formatter's definitions for the operations reached by the workflow's maximum level. */
    public List<BaseAttribute> forContentSigning(ApiClientConnectorInfo formatter,
            ManagedContentSigningWorkflow workflow) throws SigningEngineException {
        DefinitionsKey key = DefinitionsKey.of(formatter, workflow);
        return definitionsCache
                .getOrLoad(key, () -> fetchedAndStored(key.connectorUuid(),
                        () -> contentSigningFormattingAttributes.aggregate(formatter, workflow.maxLevel())));
    }

    @EventListener
    public void forgetConnector(ConnectorChangedEvent changed) {
        cacheEvictor
                .evictIf(CacheConfig.FORMATTING_ATTRIBUTE_DEFINITIONS_CACHE,
                        key -> key instanceof DefinitionsKey definitions
                                && changed.connectorUuid().equals(definitions.connectorUuid()));
    }

    /** Signing checks against what the formatter publishes, so a store refusal leaves only Core's copy behind. */
    private List<BaseAttribute> fetchedAndStored(UUID connectorUuid,
            ReadThroughCache.Loader<List<BaseAttribute>, ConnectorException> fetch) throws SigningEngineException {
        List<BaseAttribute> published = fetched(connectorUuid, fetch);
        try {
            attributeEngine
                    .updateDataAttributeDefinitions(connectorUuid, AttributeOperation.WORKFLOW_FORMATTING,
                            storableCopies(published));
        } catch (AttributeException e) {
            logger
                    .warn("Core could not store the attribute definitions published by signature formatting connector {}: {}",
                            connectorUuid, e.getMessage());
        }
        return published;
    }

    /** The HTTP client reports a successful answer without a body as an {@link IllegalStateException}. */
    private static List<BaseAttribute> fetched(UUID connectorUuid,
            ReadThroughCache.Loader<List<BaseAttribute>, ConnectorException> fetch) throws SigningEngineException {
        try {
            return List.copyOf(fetch.load());
        } catch (ConnectorException | ValidationException | IllegalStateException e) {
            throw new SigningEngineException(SigningEngineFailure.CONNECTOR_FAULT,
                    "Signature formatting connector %s could not supply its attribute definitions: %s"
                            .formatted(connectorUuid, e.getMessage()),
                    e, CLIENT_MESSAGE);
        }
    }

    /** The store replaces an encrypted attribute's content with a placeholder, which the cached original must keep. */
    private static List<BaseAttribute> storableCopies(List<BaseAttribute> published) throws AttributeException {
        List<BaseAttribute> copies = new ArrayList<>(published.size());
        for (BaseAttribute attribute : published) {
            copies.add(attribute instanceof DataAttribute data ? storableCopy(data) : attribute);
        }
        return copies;
    }

    private static DataAttribute storableCopy(DataAttribute published) throws AttributeException {
        DataAttribute copy = AttributeVersionHelper.copyDataAttribute(published);
        if (copy == null) {
            throw new AttributeException("Unsupported data attribute version " + published.getVersion(),
                    published.getUuid(), published.getName(), published.getType(), null);
        }
        return copy;
    }

    private record DefinitionsKey(UUID connectorUuid, Snapshot connector, Snapshot workflow) {

        static DefinitionsKey of(ApiClientConnectorInfo formatter, SigningWorkflow workflow) {
            return new DefinitionsKey(UUID.fromString(formatter.getUuid()), new Snapshot(formatter),
                    new Snapshot(workflow));
        }
    }

    /**
     * Matches by identity, tying an entry to one load of the connector and of the profile. A cache fill that read the
     * connector or the profile before an edit stores its result under that old copy's identity. Requests that come
     * after the edit hold the reloaded copy, so they can never get that stale result.
     */
    private record Snapshot(Object value) {

        @Override
        public boolean equals(Object other) {
            return other instanceof Snapshot(Object otherValue) && otherValue == value;
        }

        @Override
        public int hashCode() {
            return System.identityHashCode(value);
        }
    }
}
