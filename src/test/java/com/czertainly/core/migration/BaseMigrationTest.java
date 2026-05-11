package com.czertainly.core.migration;

import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

// Migration DDL commits FK renames Hibernate can't undo; resetSchema() + @DirtiesContext gives each class a clean slate without touching the shared daemon container.
// Route migration tests to their own isolated TC daemon container.
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public abstract class BaseMigrationTest extends BaseSpringBootTest {

    @DynamicPropertySource
    static void migrationDatasource(DynamicPropertyRegistry registry) {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new ClassPathResource("application.yml"));
        try {
            yaml.afterPropertiesSet();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load application.yml for migration datasource configuration", e);
        }
        Properties props = yaml.getObject();
        if (props == null) {
            throw new IllegalStateException("application.yml loaded no properties");
        }
        String baseUrl = props.getProperty("spring.datasource.url");
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("spring.datasource.url is not set in application.yml");
        }
        // Keep most PostgreSQL URL parameters (version, query flags) in sync with application.yml.
        String migrationUrl = baseUrl.replaceFirst("//[^/]+/", "//migration-tests/");
        registry.add("spring.datasource.url", () -> migrationUrl);
    }

    @Autowired
    private DataSource dataSource;

    @Value("${spring.jpa.properties.hibernate.default_schema:core}")
    private String dbSchema;

    @AfterAll
    void resetSchema() throws SQLException {
        if (!dbSchema.matches("^[a-zA-Z0-9_]+$")) {
            throw new IllegalArgumentException("Invalid schema name: " + dbSchema);
        }
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("DROP SCHEMA IF EXISTS " + dbSchema + " CASCADE");
            stmt.execute("CREATE SCHEMA " + dbSchema);
        }
    }
}
