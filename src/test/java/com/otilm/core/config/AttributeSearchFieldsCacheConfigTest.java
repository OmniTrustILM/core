package com.otilm.core.config;

import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.FileSystemResource;

import static org.assertj.core.api.Assertions.assertThat;

class AttributeSearchFieldsCacheConfigTest {

    private static final Path SHIPPED_CONFIG = Path.of("src/main/resources/application.yml");

    @Test
    void theCatalogueCacheShipsWithAFiveMinuteTtlAnOverrideAndABoundedSize() {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new FileSystemResource(SHIPPED_CONFIG));
        Properties shipped = yaml.getObject();

        assertThat(shipped).isNotNull();
        assertThat(shipped.getProperty("caching.attribute-search-fields.ttl-minutes"))
                .isEqualTo("${ATTRIBUTE_SEARCH_FIELDS_CACHE_TTL_MINUTES:5}");
        assertThat(shipped.getProperty("caching.attribute-search-fields.max-size"))
                .isEqualTo("${ATTRIBUTE_SEARCH_FIELDS_CACHE_MAX_SIZE:200}");
    }
}
