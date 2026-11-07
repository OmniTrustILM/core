package com.otilm.core.signing.formatting;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.attribute.AttributeDefinitionsDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.DataAttribute;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.ContentSigningFormattingOperation;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.AttributeVersionHelper;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.config.cache.ReadThroughCache;
import com.otilm.core.events.ConnectorChangedEvent;
import com.otilm.core.signing.contentsigning.formatting.ContentSigningFormattingAttributes;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.cache.CacheManager;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Signature formatters' attribute definitions, cached per formatter until the entry expires or the connector changes. A
 * cache fill also stores what it read, keeping Core's copy as current as the cache.
 */
@Component
public class FormattingAttributeDefinitions {

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
    public List<BaseAttribute> forTimestamping(ApiClientConnectorInfo formatter) throws SigningEngineException {
        UUID connectorUuid = UUID.fromString(formatter.getUuid());
        return definitionsCache
                .getOrLoad(new TimestampingKey(connectorUuid, new Snapshot(formatter)),
                        () -> fetchedAndStored(connectorUuid, () -> liveForTimestamping(formatter)));
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

    /** A content-signing formatter's definitions for the operations a profile with that maximum level runs. */
    public List<BaseAttribute> forContentSigning(ApiClientConnectorInfo formatter, SignatureLevel maxLevel)
            throws SigningEngineException {
        UUID connectorUuid = UUID.fromString(formatter.getUuid());
        ContentSigningKey key = new ContentSigningKey(connectorUuid, new Snapshot(formatter),
                ContentSigningFormattingAttributes.reachableOperations(maxLevel));
        return definitionsCache
                .getOrLoad(key, () -> fetchedAndStored(connectorUuid,
                        () -> contentSigningFormattingAttributes.aggregate(formatter, maxLevel)));
    }

    public void forgetFormatter(UUID formatterUuid) {
        cacheEvictor
                .evictIf(CacheConfig.FORMATTING_ATTRIBUTE_DEFINITIONS_CACHE,
                        key -> key instanceof DefinitionsKey definitions
                                && formatterUuid.equals(definitions.connectorUuid()));
    }

    @EventListener
    public void forgetConnector(ConnectorChangedEvent changed) {
        forgetFormatter(changed.connectorUuid());
    }

    private List<BaseAttribute> fetchedAndStored(UUID connectorUuid,
            ReadThroughCache.Loader<List<BaseAttribute>, ConnectorException> fetch) throws SigningEngineException {
        List<BaseAttribute> published;
        try {
            published = List.copyOf(fetch.load());
            attributeEngine
                    .updateDataAttributeDefinitions(connectorUuid, AttributeOperation.WORKFLOW_FORMATTING,
                            storableCopies(published));
        } catch (ConnectorException | ValidationException | AttributeException e) {
            throw new SigningEngineException(SigningEngineFailure.CONNECTOR_FAULT,
                    "Signature formatting connector %s could not supply usable attribute definitions: %s"
                            .formatted(connectorUuid, e.getMessage()),
                    e, CLIENT_MESSAGE);
        }
        return published;
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

    private sealed interface DefinitionsKey permits TimestampingKey, ContentSigningKey {

        UUID connectorUuid();
    }

    private record TimestampingKey(UUID connectorUuid, Snapshot connector) implements DefinitionsKey {
    }

    private record ContentSigningKey(UUID connectorUuid, Snapshot connector,
            List<ContentSigningFormattingOperation> operations) implements DefinitionsKey {
    }

    /**
     * Matches the connector by identity. An edit reloads the connector, so a load that captured it before the edit
     * fills an entry later requests never read.
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
