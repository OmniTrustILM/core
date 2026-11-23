package com.otilm.core.service.impl;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.core.security.authz.SecuredUUID;
import jakarta.persistence.PersistenceException;
import java.util.UUID;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThat;

class EstProfileServiceImplTest {

    private static final String STATEMENT_FAILED = "could not execute statement";
    private static final String SYSTEM_DEFAULT_INDEX = "uk_est_profile_single_system_default";

    // ── IsSystemDefaultClash ──────────────────────────────────────────────────

    @Nested
    class IsSystemDefaultClash {

        @Test
        void returnsTrue_whenCauseIsViolationOfTheSystemDefaultConstraint() {
            // given
            var directClash = new DataIntegrityViolationException(STATEMENT_FAILED,
                    new ConstraintViolationException("dup", null, SYSTEM_DEFAULT_INDEX));

            // when
            boolean systemDefaultClash = EstProfileServiceImpl.isSystemDefaultClash(directClash);

            // then
            assertThat(systemDefaultClash).isTrue();
        }

        @Test
        void returnsTrue_whenViolationSitsDeeperInTheCauseChain() {
            // given
            var wrappedClash = new DataIntegrityViolationException(STATEMENT_FAILED,
                    new PersistenceException(new ConstraintViolationException("dup", null, SYSTEM_DEFAULT_INDEX)));

            // when
            boolean systemDefaultClash = EstProfileServiceImpl.isSystemDefaultClash(wrappedClash);

            // then
            assertThat(systemDefaultClash).isTrue();
        }

        @Test
        void returnsFalse_whenViolatedConstraintIsAnotherOne() {
            // given
            var nameClash = new DataIntegrityViolationException(STATEMENT_FAILED,
                    new ConstraintViolationException("dup", null, "est_profile_name_key"));

            // when
            boolean systemDefaultClash = EstProfileServiceImpl.isSystemDefaultClash(nameClash);

            // then
            assertThat(systemDefaultClash).isFalse();
        }

        @Test
        void returnsFalse_whenThereIsNoConstraintViolation() {
            // given
            var withoutConstraint = new DataIntegrityViolationException(STATEMENT_FAILED);

            // when
            boolean systemDefaultClash = EstProfileServiceImpl.isSystemDefaultClash(withoutConstraint);

            // then
            assertThat(systemDefaultClash).isFalse();
        }
    }

    // ── LogBulkFailure ────────────────────────────────────────────────────────

    @Nested
    class LogBulkFailure {

        private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
        private final Logger logger = (Logger) LoggerFactory.getLogger(EstProfileServiceImpl.class);

        @BeforeEach
        void captureServiceLog() {
            appender.start();
            logger.addAppender(appender);
        }

        @AfterEach
        void releaseServiceLog() {
            logger.detachAppender(appender);
            appender.stop();
        }

        /** Only a refusal the platform shaped is expected in a bulk request; anything else keeps its trace. */
        @Test
        void logsErrorWithTrace_whenFailureIsUnexpected() {
            // given
            var operation = "enable";
            var uuid = SecuredUUID.fromUUID(UUID.randomUUID());
            var unexpectedFailure = new IllegalStateException("connection lost");

            // when
            EstProfileServiceImpl.logBulkFailure(operation, uuid, unexpectedFailure);

            // then
            assertThat(appender.list).singleElement().satisfies(event -> {
                assertThat(event.getLevel()).isEqualTo(Level.ERROR);
                assertThat(event.getFormattedMessage()).isEqualTo("Failed to " + operation + " EST Profile " + uuid);
                assertThat(event.getThrowableProxy().getMessage()).isEqualTo(unexpectedFailure.getMessage());
            });
        }
    }
}
