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

/**
 * Entries hold what a warm v2 signature would otherwise read from the database and the connector's schema. The writes
 * an entry depends on evict it after commit.
 */
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
     * The key item's sign definitions as the connector answered them in {@code scope}. A caller holding a key item read
     * before its move keys its load by the old scope, so callers in the new scope never read that answer.
     */
    public List<BaseAttribute> signAttributeDefinitions(UUID keyItemUuid, KeyOperationScope scope,
            DefinitionsLoader loader) throws ConnectorException {
        return signAttributeDefinitionsCache.getOrLoad(new SignDefinitionsKey(keyItemUuid, scope), loader::load);
    }

    /** Drops every definition, since each key pairs a key item with a scope a key-item write may have changed. */
    public void forgetKeyItemAnswers() {
        cacheEvictor.clear(CacheConfig.SIGN_ATTRIBUTE_DEFINITIONS_CACHE);
    }

    /** Every definition goes as well. Each was answered while the old attributes applied. */
    public void forgetAttributesOf(Resource objectType, UUID objectUuid, UUID connectorUuid) {
        cacheEvictor
                .evict(CacheConfig.TOKEN_SCOPE_ATTRIBUTES_CACHE, attributeScope(objectType, objectUuid, connectorUuid));
        cacheEvictor.clear(CacheConfig.SIGN_ATTRIBUTE_DEFINITIONS_CACHE);
    }

    /** A connector change may change any definition the connector answered, stored rows carrying theirs included. */
    public void forgetConnectorAnswers() {
        cacheEvictor.clear(CacheConfig.TOKEN_SCOPE_ATTRIBUTES_CACHE);
        cacheEvictor.clear(CacheConfig.SIGN_ATTRIBUTE_DEFINITIONS_CACHE);
    }

    /**
     * Resolves the token and token-profile attributes itself, after its entry exists, so an eviction during the load
     * also drops an answer given for attributes that changed. Loaded definitions have already passed the secret echo
     * check.
     */
    @FunctionalInterface
    public interface DefinitionsLoader {
        List<BaseAttribute> load() throws ConnectorException;
    }

    private record SignDefinitionsKey(UUID keyItemUuid, KeyOperationScope scope) {
    }

    private static ObjectAttributeContentInfo attributeScope(Resource objectType, UUID objectUuid, UUID connectorUuid) {
        return ObjectAttributeContentInfo.builder(objectType, objectUuid).connector(connectorUuid).build();
    }
}
