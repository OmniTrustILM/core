package com.otilm.core.integration.attribute;

import com.github.benmanes.caffeine.cache.Cache;
import com.otilm.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.otilm.api.model.client.attribute.custom.CustomAttributeDefinitionDetailDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.attribute.engine.AttributeSearchFieldCatalogue;
import com.otilm.core.attribute.engine.NamedField;
import com.otilm.core.config.cache.CacheConfig;
import com.otilm.core.model.SearchFieldObject;
import com.otilm.core.service.AttributeExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SqlCapture;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;

import static org.assertj.core.api.Assertions.assertThat;

class AttributeSearchFieldCatalogueITest extends BaseSpringBootTest {

    @Autowired
    private AttributeSearchFieldCatalogue catalogue;

    @Autowired
    private AttributeExternalService attributeService;

    @Autowired
    private CacheManager cacheManager;

    @Test
    void aSecondReadRunsNoCatalogueQuery() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);

        List<String> statements = SqlCapture.during(() -> catalogue.fields(Resource.CERTIFICATE, false)).statements();

        assertThat(statements).noneMatch(sql -> sql.contains("attribute_definition"));
    }

    @Test
    void aReaderChangingItsCopyDoesNotChangeTheNextRead() throws Exception {
        createCustomAttribute("environment");
        List<SearchFieldObject> first = catalogue.fields(Resource.CERTIFICATE, false);
        environmentRow(first).setVisible(false);
        first.clear();

        List<SearchFieldObject> second = catalogue.fields(Resource.CERTIFICATE, false);

        assertThat(environmentRow(second).isVisible()).isTrue();
    }

    private static SearchFieldObject environmentRow(List<SearchFieldObject> rows) {
        return rows
                .stream()
                .filter(row -> row.getAttributeName().equals("environment"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no environment row in " + rows));
    }

    @Test
    void aCustomAttributeCreatedHereShowsOnTheNextRead() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);

        createCustomAttribute("created-later");

        assertThat(catalogue.fields(Resource.CERTIFICATE, false))
                .anyMatch(row -> row.getAttributeName().equals("created-later"));
    }

    /** A replica that did not make the change keeps its entry, until a request names the new field. */
    @Test
    void aFieldCreatedElsewhereIsReadOnceARequestNamesIt() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);
        onAnotherReplica(() -> createCustomAttribute("created-elsewhere"));
        NamedField named = NamedField
                .of(FilterFieldSource.CUSTOM, "created-elsewhere|" + AttributeContentType.TEXT.name());

        assertThat(catalogue.fields(Resource.CERTIFICATE, false)).noneMatch(named::names);
        assertThat(catalogue.fieldsNaming(Resource.CERTIFICATE, false, List.of(named))).anyMatch(named::names);
        assertThat(catalogue.fields(Resource.CERTIFICATE, false)).anyMatch(named::names);
    }

    @Test
    void aPropertyFieldNamedByARequestNeverForcesARebuild() throws Exception {
        catalogue.fields(Resource.CERTIFICATE, false);

        List<String> statements = SqlCapture
                .during(() -> catalogue
                        .fieldsNaming(Resource.CERTIFICATE, false,
                                List.of(NamedField.of(FilterFieldSource.PROPERTY, "COMMON_NAME"))))
                .statements();

        assertThat(statements).isEmpty();
    }

    private CustomAttributeDefinitionDetailDto createCustomAttribute(String name) throws Exception {
        CustomAttributeCreateRequestDto request = new CustomAttributeCreateRequestDto();
        request.setName(name);
        request.setLabel(name);
        request.setResources(List.of(Resource.CERTIFICATE));
        request.setContentType(AttributeContentType.TEXT);
        return attributeService.createCustomAttribute(request);
    }

    /** Makes a change as another replica would: afterwards this one holds exactly the entries it held before. */
    private void onAnotherReplica(Callable<?> change) throws Exception {
        Map<Object, Object> entriesBeforeTheChange = Map.copyOf(nativeCache().asMap());
        change.call();
        nativeCache().invalidateAll();
        nativeCache().putAll(entriesBeforeTheChange);
    }

    @SuppressWarnings("unchecked")
    private Cache<Object, Object> nativeCache() {
        return (Cache<Object, Object>) Objects
                .requireNonNull(cacheManager.getCache(CacheConfig.ATTRIBUTE_SEARCH_FIELDS_CACHE))
                .getNativeCache();
    }
}
