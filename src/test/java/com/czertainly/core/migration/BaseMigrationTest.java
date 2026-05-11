package com.czertainly.core.migration;

import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

// Migration DDL commits FK renames Hibernate can't undo; resetSchema() + @DirtiesContext gives each class a clean slate without touching the shared daemon container.
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@TestPropertySource(properties =
        "spring.datasource.url=jdbc:tc:postgresql:17-alpine://migration-tests/czertainly-test" +
        "?currentSchema=core&TC_TMPFS=/testtmpfs:rw&TC_DAEMON=true"
)
public abstract class BaseMigrationTest extends BaseSpringBootTest {

    @Autowired
    private DataSource dataSource;

    @AfterAll
    void resetSchema() throws SQLException {
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("DROP SCHEMA core CASCADE");
            stmt.execute("CREATE SCHEMA core");
        }
    }
}
