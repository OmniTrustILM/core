package com.otilm.core.config;

import org.hibernate.cfg.JdbcSettings;
import org.hibernate.resource.jdbc.spi.PhysicalConnectionHandlingMode;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Returns a session's connection to the pool when each transaction ends and after each query outside one. Spring's
 * default holds it until the EntityManager closes: a read in a {@code NOT_SUPPORTED} scope then keeps its connection
 * while each transaction the scope starts takes another, and enough concurrent requests leave every pooled connection
 * waiting for a second one. Set in code, not in {@code application.yml}, so that tests run with it too.
 * <p>
 * Spring applies a transaction's isolation level and read-only flag to the connection only under its default. Here it
 * refuses an {@code isolation} on {@code @Transactional}, and {@code readOnly} only stops flushes. A transaction that
 * needs another isolation level sets it with its first statement, as
 * {@code SigningRecordRepository.readUnderOneSnapshot} does.
 */
@Configuration(proxyBeanMethods = false)
public class DatabaseConnectionHandlingConfig {

    @Bean
    HibernatePropertiesCustomizer connectionHandlingCustomizer() {
        return properties -> properties
                .put(JdbcSettings.CONNECTION_HANDLING,
                        PhysicalConnectionHandlingMode.DELAYED_ACQUISITION_AND_RELEASE_AFTER_TRANSACTION);
    }
}
