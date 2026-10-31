package com.otilm.core.service.handler.key;

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

    /**
     * The key item's sign definitions as the connector answered them for the scope's current token and token-profile
     * rows. Each answer is keyed by the row lists it was given, so it expires with them.
     */
    public List<BaseAttribute> signAttributeDefinitions(UUID keyItemUuid, KeyOperationScope scope, UUID connectorUuid,
            DefinitionsLoader loader) throws ConnectorException {
        RowsSnapshot tokenRows = new RowsSnapshot(
                storedAttributes(Resource.TOKEN, scope.tokenInstanceReferenceUuid(), connectorUuid));
        RowsSnapshot tokenProfileRows = new RowsSnapshot(
                storedAttributes(Resource.TOKEN_PROFILE, scope.tokenProfileUuid(), connectorUuid));
        SignDefinitionsKey key = new SignDefinitionsKey(keyItemUuid, scope, tokenRows, tokenProfileRows);
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

    public void forgetAllAttributes() {
        cacheEvictor.clear(CacheConfig.TOKEN_SCOPE_ATTRIBUTES_CACHE);
        cacheEvictor.clear(CacheConfig.SIGN_ATTRIBUTE_DEFINITIONS_CACHE);
    }

    /**
     * Resolves the token and token-profile attributes itself, after its entry exists, so an eviction during the load
     * also drops an answer given for attributes that changed.
     */
    @FunctionalInterface
    public interface DefinitionsLoader {
        List<BaseAttribute> load() throws ConnectorException;
    }

    private record SignDefinitionsKey(UUID keyItemUuid, KeyOperationScope scope, RowsSnapshot tokenRows,
            RowsSnapshot tokenProfileRows) {
    }

    /** Matches one cached row list by identity, which is cheap and changes on every reload of the rows. */
    private record RowsSnapshot(List<ObjectAttributeContent> rows) {

        @Override
        public boolean equals(Object other) {
            return other instanceof RowsSnapshot snapshot && snapshot.rows == rows;
        }

        @Override
        public int hashCode() {
            return System.identityHashCode(rows);
        }
    }

    private static ObjectAttributeContentInfo attributeScope(Resource objectType, UUID objectUuid, UUID connectorUuid) {
        return ObjectAttributeContentInfo.builder(objectType, objectUuid).connector(connectorUuid).build();
    }
}
