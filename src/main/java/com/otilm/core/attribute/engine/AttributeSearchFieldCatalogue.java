package com.otilm.core.attribute.engine;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.model.SearchFieldObject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

/**
 * The attribute rows of each resource's field catalogue, cached.
 *
 * <p>
 * The rows come from one query per resource that reads every attribute mapping of the resource, so it is run once per
 * TTL rather than for every {@code /search}, saved-view read and attribute sort. A custom definition or relation
 * written here evicts the entry after commit; another replica keeps its entry until the TTL. Data and metadata
 * definitions appear with content that connectors write all the time, so they do not evict: a request that names a
 * field the entry lacks rebuilds it once instead, so a field that just appeared is never refused.
 *
 * <p>
 * Callers get copies. {@code SearchHelper} merges rows that share an identifier in place, and every {@code /search}
 * caller appends its property fields to the list it gets back.
 */
@Component
@RequiredArgsConstructor
public class AttributeSearchFieldCatalogue {

    private static final List<AttributeType> SEARCHABLE_TYPES = List
            .of(AttributeType.CUSTOM, AttributeType.DATA, AttributeType.META);

    private final AttributeDefinitionRepository attributeDefinitionRepository;
    private final CacheManager cacheManager;
    private final CacheEvictor cacheEvictor;

    private record Key(Resource resource, boolean settable) {
    }

    /**
     * The resource's catalogue rows.
     *
     * @param settable only custom fields a value can be written to, the rows the bulk-set form offers
     */
    public List<SearchFieldObject> fields(Resource resource, boolean settable) {
        Key key = new Key(resource, settable);
        return copies(cache().get(key, () -> load(key)));
    }

    /** As {@link #fields}, rebuilt once when any attribute field in {@code named} is missing from the cached rows. */
    public List<SearchFieldObject> fieldsNaming(Resource resource, boolean settable, Collection<NamedField> named) {
        Key key = new Key(resource, settable);
        List<SearchFieldObject> rows = cache().get(key, () -> load(key));
        if (!coversAll(rows, named)) {
            rows = load(key);
            cache().put(key, rows);
        }
        return copies(rows);
    }

    /** Drops every entry after the current transaction commits, on this replica. */
    public void evictAll() {
        cacheEvictor.clear(CacheConfig.ATTRIBUTE_SEARCH_FIELDS_CACHE);
    }

    private List<SearchFieldObject> load(Key key) {
        List<SearchFieldObject> rows = key.settable()
                ? attributeDefinitionRepository
                        .findDistinctAttributeSearchFieldsByResourceAndAttrTypeAndAttrContentType(key.resource(),
                                List.of(AttributeType.CUSTOM),
                                Arrays
                                        .stream(AttributeContentType.values())
                                        .filter(AttributeContentType::isFilterByData)
                                        .toList())
                : attributeDefinitionRepository
                        .findDistinctAttributeSearchFieldsByResourceAndAttrType(key.resource(), SEARCHABLE_TYPES);
        return List.copyOf(rows);
    }

    private static boolean coversAll(List<SearchFieldObject> rows, Collection<NamedField> named) {
        return named.stream().filter(NamedField::isAttribute).allMatch(field -> rows.stream().anyMatch(field::names));
    }

    private static List<SearchFieldObject> copies(List<SearchFieldObject> rows) {
        return rows.stream().map(SearchFieldObject::copy).collect(Collectors.toCollection(ArrayList::new));
    }

    private Cache cache() {
        return Objects.requireNonNull(cacheManager.getCache(CacheConfig.ATTRIBUTE_SEARCH_FIELDS_CACHE));
    }
}
