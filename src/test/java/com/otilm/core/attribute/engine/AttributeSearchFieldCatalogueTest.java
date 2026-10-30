package com.otilm.core.attribute.engine;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.config.cache.CacheEvictor;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.model.SearchFieldObject;
import com.otilm.core.util.cache.CacheManagerFixtures;
import com.otilm.core.util.cache.HeldLoad;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.cache.CacheManager;
import org.springframework.dao.DataAccessResourceFailureException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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

    @Test
    void anEvictAllDuringTheRefreshDropsTheRefreshedRows() {
        // given
        HeldLoad held = new HeldLoad();
        Supplier<List<SearchFieldObject>> refresh = held.holding(List::of);
        when(repository.findDistinctAttributeSearchFieldsByResourceAndAttrType(any(), any()))
                .thenReturn(List.of())
                .thenAnswer(invocation -> refresh.get())
                .thenReturn(List.of());
        List<NamedField> named = List.of(NamedField.of(FilterFieldSource.CUSTOM, "missing|TEXT"));
        catalogue.fields(Resource.CERTIFICATE, false);
        CompletableFuture<List<SearchFieldObject>> during = held
                .start(() -> catalogue.fieldsNaming(Resource.CERTIFICATE, false, named));

        // when
        catalogue.evictAll();
        held.release(during);
        catalogue.fields(Resource.CERTIFICATE, false);

        // then
        verify(repository, times(3)).findDistinctAttributeSearchFieldsByResourceAndAttrType(any(), any());
    }

    private static AttributeSearchFieldCatalogue catalogueOver(AttributeDefinitionRepository repository) {
        CacheManager cacheManager = CacheManagerFixtures.configured();
        CacheEvictor cacheEvictor = new CacheEvictor();
        cacheEvictor.setCacheManager(cacheManager);
        return new AttributeSearchFieldCatalogue(repository, cacheManager, cacheEvictor);
    }
}
