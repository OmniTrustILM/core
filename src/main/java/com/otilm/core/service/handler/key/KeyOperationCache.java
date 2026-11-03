package com.otilm.core.service.handler.key;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContent;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.config.cache.ReadThroughCache;
import com.otilm.core.model.crypto.KeyOperationScope;
import java.util.List;
import java.util.UUID;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

/** Caches attributes required for crypto v2 signing operations. */
@Component
public class KeyOperationCache {

    private final AttributeEngine attributeEngine;
    private final CacheEvictor cacheEvictor;
    private final ReadThroughCache tokenScopeAttributesCache;
    private final ReadThroughCache signAttributeDefinitionsCache;

    public KeyOperationCache(AttributeEngine attributeEngine, CacheManager cacheManager, CacheEvictor cacheEvictor) {
        this.attributeEngine = attributeEngine;
        this.cacheEvictor = cacheEvictor;
        this.tokenScopeAttributesCache = ReadThroughCache.from(cacheManager, CacheConfig.TOKEN_SCOPE_ATTRIBUTES_CACHE);
        this.signAttributeDefinitionsCache = ReadThroughCache
                .from(cacheManager, CacheConfig.SIGN_ATTRIBUTE_DEFINITIONS_CACHE);
    }

    /** The rows a token or token profile holds for the connector. Their secrets stay encrypted. */
    public List<ObjectAttributeContent> storedAttributes(Resource objectType, UUID objectUuid, UUID connectorUuid) {
        ObjectAttributeContentInfo scope = attributeScope(objectType, objectUuid, connectorUuid);
        return tokenScopeAttributesCache
                .getOrLoad(scope, () -> attributeEngine.getStoredObjectDataAttributesContent(scope));
    }

    /** The rows of the scope's token and token profile, which an operation reads once and uses throughout. */
    public ScopeRows scopeRows(KeyOperationScope scope, UUID connectorUuid) {
        List<ObjectAttributeContent> tokenRows = storedAttributes(Resource.TOKEN, scope.tokenInstanceReferenceUuid(),
                connectorUuid);
        List<ObjectAttributeContent> tokenProfileRows = storedAttributes(Resource.TOKEN_PROFILE,
                scope.tokenProfileUuid(), connectorUuid);
        return new ScopeRows(scope, connectorUuid, tokenRows, tokenProfileRows);
    }

    /**
     * The key item's sign definitions as the connector answered them for the scope's rows. Each answer is keyed by the
     * cached connector and row lists it was given, so a reload of any of them asks the connector again.
     */
    public List<BaseAttribute> signAttributeDefinitions(UUID keyItemUuid, ApiClientConnectorInfo connector,
            ScopeRows rows, DefinitionsLoader loader) throws ConnectorException {
        SignDefinitionsKey key = new SignDefinitionsKey(keyItemUuid, rows.scope(), rows.connectorUuid(),
                new Snapshot(connector), new Snapshot(rows.tokenRows()), new Snapshot(rows.tokenProfileRows()));
        return signAttributeDefinitionsCache.getOrLoad(key, loader::load);
    }

    public void forgetSignAttributeDefinitions() {
        cacheEvictor.clear(CacheConfig.SIGN_ATTRIBUTE_DEFINITIONS_CACHE);
    }

    public void forgetAttributesOf(Resource objectType, UUID objectUuid, UUID connectorUuid) {
        cacheEvictor
                .evict(CacheConfig.TOKEN_SCOPE_ATTRIBUTES_CACHE, attributeScope(objectType, objectUuid, connectorUuid));
        cacheEvictor.clear(CacheConfig.SIGN_ATTRIBUTE_DEFINITIONS_CACHE);
    }

    /** Forgets what was read for the connector, as an edit to it may change the definitions behind its rows. */
    public void forgetConnector(UUID connectorUuid) {
        cacheEvictor
                .evictIf(CacheConfig.TOKEN_SCOPE_ATTRIBUTES_CACHE, key -> key instanceof ObjectAttributeContentInfo rows
                        && connectorUuid.equals(rows.connectorUuid()));
        cacheEvictor
                .evictIf(CacheConfig.SIGN_ATTRIBUTE_DEFINITIONS_CACHE,
                        key -> key instanceof SignDefinitionsKey definitions
                                && connectorUuid.equals(definitions.connectorUuid()));
    }

    /**
     * It must ask its entry's connector with the attributes resolved from its entry's rows, so each answer matches its
     * key.
     */
    @FunctionalInterface
    public interface DefinitionsLoader {
        List<BaseAttribute> load() throws ConnectorException;
    }

    public record ScopeRows(KeyOperationScope scope, UUID connectorUuid, List<ObjectAttributeContent> tokenRows,
            List<ObjectAttributeContent> tokenProfileRows) {
    }

    private record SignDefinitionsKey(UUID keyItemUuid, KeyOperationScope scope, UUID connectorUuid, Snapshot connector,
            Snapshot tokenRows, Snapshot tokenProfileRows) {
    }

    /** Matches one cached value by identity, which is cheap and changes on every reload of the value. */
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

    private static ObjectAttributeContentInfo attributeScope(Resource objectType, UUID objectUuid, UUID connectorUuid) {
        return ObjectAttributeContentInfo.builder(objectType, objectUuid).connector(connectorUuid).build();
    }
}
