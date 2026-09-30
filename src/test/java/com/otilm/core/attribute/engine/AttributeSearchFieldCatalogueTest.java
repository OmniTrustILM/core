package com.otilm.core.attribute.engine;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.dao.DataAccessResourceFailureException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AttributeSearchFieldCatalogueTest {

    private final AttributeDefinitionRepository repository = mock(AttributeDefinitionRepository.class);

    private final AttributeSearchFieldCatalogue catalogue = catalogueOver(repository);

    @Test
    void aFailingCatalogueQueryThrowsItsOwnException() {
        DataAccessResourceFailureException failure = new DataAccessResourceFailureException("database unavailable");
        when(repository.findDistinctAttributeSearchFieldsByResourceAndAttrType(any(), any())).thenThrow(failure);
        List<NamedField> named = List.of(NamedField.of(FilterFieldSource.CUSTOM, "missing|TEXT"));

        assertThatThrownBy(() -> catalogue.fields(Resource.CERTIFICATE, false)).isSameAs(failure);
        assertThatThrownBy(() -> catalogue.fieldsNaming(Resource.CERTIFICATE, false, named)).isSameAs(failure);
    }

    private static AttributeSearchFieldCatalogue catalogueOver(AttributeDefinitionRepository repository) {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager(CacheConfig.ATTRIBUTE_SEARCH_FIELDS_CACHE);
        CacheEvictor cacheEvictor = new CacheEvictor();
        cacheEvictor.setCacheManager(cacheManager);
        return new AttributeSearchFieldCatalogue(repository, cacheManager, cacheEvictor);
    }
}
