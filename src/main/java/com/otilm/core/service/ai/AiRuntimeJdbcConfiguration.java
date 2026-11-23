package com.otilm.core.service.ai;

import javax.sql.DataSource;
import org.hibernate.cfg.JdbcSettings;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
public class AiRuntimeJdbcConfiguration {
    @Bean(destroyMethod = "stop")
    AiRuntimeJdbcConnectionProvider aiRuntimeJdbcConnectionProvider(DataSource source) {
        return new AiRuntimeJdbcConnectionProvider(source);
    }

    @Bean
    HibernatePropertiesCustomizer aiRuntimeJdbcProviderCustomizer(AiRuntimeJdbcConnectionProvider provider) {
        return properties -> properties.put(JdbcSettings.CONNECTION_PROVIDER, provider);
    }
}
