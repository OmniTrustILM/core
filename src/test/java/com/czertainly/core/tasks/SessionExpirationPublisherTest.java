package com.czertainly.core.tasks;

import com.czertainly.core.messaging.scheduler.SessionExpirationPublisher;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import javax.sql.DataSource;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.session.Session;


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SessionExpirationPublisherTest extends BaseSpringBootTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private FindByIndexNameSessionRepository sessionRepository;

    @Autowired
    private SessionExpirationPublisher sessionExpirationPublisher;

    @BeforeEach
    void setUp() {
        // Ensure the session tables are created before each test
        setupSessionTables();
    }

    @Test
    void testSessionExpiration() {

        Assertions.assertDoesNotThrow(() -> sessionExpirationPublisher.processExpiredSessions());

        Session s = sessionRepository.createSession();
        s.setMaxInactiveInterval(Duration.ZERO);
        s.setLastAccessedTime(Instant.now().minus(Duration.of(10, ChronoUnit.MINUTES)));
        sessionRepository.save(s);

        sessionExpirationPublisher.processExpiredSessions();

        Assertions.assertNull(sessionRepository.findById(s.getId()));


        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        s = sessionRepository.createSession();
        s.setMaxInactiveInterval(Duration.ZERO);
        s.setLastAccessedTime(Instant.now().minus(Duration.of(10, ChronoUnit.MINUTES)));
        s.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        sessionRepository.save(s);

        sessionExpirationPublisher.processExpiredSessions();
        Assertions.assertNull(sessionRepository.findById(s.getId()));
    }

    @Test
    void testProcessExpiredSessions_handlesDatabaseException() throws Exception {
        JdbcIndexedSessionRepository mocked = Mockito.mock(JdbcIndexedSessionRepository.class);
        DataSource dataSource = Mockito.mock(DataSource.class);
        GenericConversionService conversionService = Mockito.mock(GenericConversionService.class);
        SessionExpirationPublisher publisher = new SessionExpirationPublisher(mocked, dataSource, conversionService);
        ReflectionTestUtils.setField(publisher, "dbSchema", "core");
        publisher.init();
        Assertions.assertDoesNotThrow(publisher::processExpiredSessions);

        Session s = sessionRepository.createSession();
        s.setMaxInactiveInterval(Duration.ZERO);
        s.setLastAccessedTime(Instant.now().minus(Duration.of(10, ChronoUnit.MINUTES)));
        s.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.createEmptyContext());
        sessionRepository.save(s);

        Mockito.when(dataSource.getConnection()).thenReturn(jdbcTemplate.getDataSource().getConnection());
        Mockito.when(conversionService.convert(Mockito.any(), Mockito.eq(Object.class))).thenThrow(new RuntimeException("Conversion error"));
        publisher = new SessionExpirationPublisher(mocked, dataSource, conversionService);
        ReflectionTestUtils.setField(publisher, "dbSchema", "core");
        publisher.init();
        Assertions.assertDoesNotThrow(publisher::processExpiredSessions);
    }


    @Test
    void testInit_throwsExceptionForInvalidTableName() {
        JdbcIndexedSessionRepository mocked = Mockito.mock(JdbcIndexedSessionRepository.class);
        DataSource dataSource = Mockito.mock(DataSource.class);
        GenericConversionService conversionService = Mockito.mock(GenericConversionService.class);
        SessionExpirationPublisher publisher = new SessionExpirationPublisher(mocked, dataSource, conversionService);
        ReflectionTestUtils.setField(publisher, "dbSchema", "invalid table; drop table users;");
        Assertions.assertThrows(IllegalArgumentException.class, publisher::init);
    }

    private void setupSessionTables() {
        // Create spring_session table
        jdbcTemplate.execute("""
                    CREATE TABLE IF NOT EXISTS spring_session (
                        PRIMARY_ID CHAR(36) NOT NULL,
                        SESSION_ID CHAR(36) NOT NULL,
                        CREATION_TIME BIGINT NOT NULL,
                        LAST_ACCESS_TIME BIGINT NOT NULL,
                        MAX_INACTIVE_INTERVAL INT NOT NULL,
                        EXPIRY_TIME BIGINT NOT NULL,
                        PRINCIPAL_NAME VARCHAR(100),
                        CONSTRAINT spring_session_pkey PRIMARY KEY(PRIMARY_ID)
                    );
                """);

        // Create spring_session_attributes table (your JSON setup)
        jdbcTemplate.execute("""
                    CREATE TABLE IF NOT EXISTS spring_session_attributes (
                        SESSION_PRIMARY_ID CHAR(36) NOT NULL,
                        ATTRIBUTE_NAME VARCHAR(200) NOT NULL,
                        ATTRIBUTE_BYTES JSONB,
                        CONSTRAINT spring_session_attributes_pkey PRIMARY KEY(SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
                        CONSTRAINT fk_session FOREIGN KEY(SESSION_PRIMARY_ID) REFERENCES spring_session(PRIMARY_ID) ON DELETE CASCADE
                    );
                """);
    }

    @AfterAll
    void dropSessionTables() {
        jdbcTemplate.execute("DROP TABLE IF EXISTS spring_session_attributes");
        jdbcTemplate.execute("DROP TABLE IF EXISTS spring_session");
    }

}
