package com.otilm.core.config;

import org.hibernate.cfg.JdbcSettings;
import org.hibernate.resource.jdbc.spi.PhysicalConnectionHandlingMode;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Returns a session's connection to the pool when each transaction ends and after each query outside one. A lazy load
 * outside a transaction is not a query: its connection stays with the session until the next query or until the
 * EntityManager closes. Under Spring's default, which holds the connection until the EntityManager closes, a
 * {@code NOT_SUPPORTED} read keeps its connection while the scope's transactions take another, and concurrent requests
 * deadlock the pool. Set in code so tests use it.
 * <p>
 * Cost: Spring refuses {@code isolation} on {@code @Transactional}, and {@code readOnly} no longer makes the JDBC
 * connection read-only; it still suppresses automatic flushes and, on a transaction's own EntityManager, loads entities
 * read-only. Set another isolation level with the transaction's first statement, as
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
