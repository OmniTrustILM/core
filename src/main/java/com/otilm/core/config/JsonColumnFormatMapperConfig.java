package com.otilm.core.config;

import com.otilm.core.serialization.ObjectMapperFactory;
import org.hibernate.cfg.MappingSettings;
import org.hibernate.type.format.jackson.JacksonJsonFormatMapper;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * States the {@code FormatMapper} for every {@code @JdbcTypeCode(SqlTypes.JSON)} column, so tests and production
 * serialize them identically. {@link ObjectMapperFactory#jsonColumn()} is Hibernate's own recipe with one change, dates
 * as text.
 * <p>
 * A column that also carries {@code ObjectToJsonConverter} is outside this: the converter makes the relational type
 * {@code String}, which reaches the driver verbatim, so those columns keep the wire mapper's shape.
 */
@Configuration
public class JsonColumnFormatMapperConfig {

    @Bean
    JacksonJsonFormatMapper jsonColumnFormatMapper() {
        return new JacksonJsonFormatMapper(ObjectMapperFactory.jsonColumn());
    }

    @Bean
    HibernatePropertiesCustomizer jsonColumnFormatMapperCustomizer(JacksonJsonFormatMapper jsonColumnFormatMapper) {
        return properties -> properties.put(MappingSettings.JSON_FORMAT_MAPPER, jsonColumnFormatMapper);
    }
}
