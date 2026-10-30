package com.otilm.core.config;

import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.FileSystemResource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Asserts that the shipped datasource keeps PostgreSQL's failing-row DETAIL out of driver exception messages.
 *
 * <p>
 * A constraint violation is answered with {@code DETAIL: Failing row contains (...)}, listing every column of the
 * offending row, and pgjdbc copies that into the exception message unless {@code logServerErrorDetail} is off.
 * Hibernate's {@code SqlExceptionHelper} logs the driver's message at ERROR the moment the statement fails, which is
 * upstream of every catch in the application -- so this is the only place the disclosure can be prevented rather than
 * mopped up. {@code crypto_asset.identity_key} is 64 hex characters, exactly pgjdbc's per-value truncation point, so it
 * is the value that prints whole.
 *
 * <p>
 * Pinned rather than left to review because turning it back on is one word, produces no test failure anywhere else, and
 * its consequence is invisible until an incident. What it does <em>not</em> cover is a deploy-time {@code JDBC_URL}
 * carrying {@code logServerErrorDetail=true} as a query parameter, which the driver would honour over this: that
 * belongs to whoever owns the deployment charts.
 */
class DatasourceErrorDetailConfigTest {

    private static final Path SHIPPED_CONFIG = Path.of("src/main/resources/application.yml");

    private static final String PROPERTY = "spring.datasource.hikari.data-source-properties.logServerErrorDetail";

    @Test
    void theShippedDatasourceDoesNotPutTheFailingRowIntoExceptionMessages() {
        assertThat(shippedConfiguration().getProperty(PROPERTY))
                .describedAs("%s keeps the failing row out of the ERROR line Hibernate logs before any catch runs",
                        PROPERTY)
                .isEqualTo("false");
    }

    private static Properties shippedConfiguration() {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new FileSystemResource(SHIPPED_CONFIG));
        Properties flattened = yaml.getObject();
        assertThat(flattened).describedAs("%s must be readable", SHIPPED_CONFIG).isNotNull();
        return flattened;
    }
}
