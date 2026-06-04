package com.czertainly.core.messaging.jms.configuration;

import com.czertainly.core.util.BaseSpringBootTest;
import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.Session;
import jakarta.jms.TextMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.support.converter.MessageConverter;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * <p>This test verifies that the MessageConverter bean configured in {@link JmsConfig}
 * correctly handles Java 8 date/time types (OffsetDateTime, LocalDateTime, etc.).</p>
 */
class JmsMessageConverterTest extends BaseSpringBootTest {

    @Autowired
    private MessageConverter messageConverter;

    private Session mockSession;

    @BeforeEach
    void setUp() throws JMSException {
        mockSession = mock(Session.class);
        TextMessage mockTextMessage = mock(TextMessage.class);
        when(mockSession.createTextMessage(anyString())).thenReturn(mockTextMessage);
    }

    @Test
    void shouldSerializeOffsetDateTimeUsingAppMessageConverter() throws JMSException {
        // Given: Message with OffsetDateTime (simulates AuditLogMessage with LogRecord.timestamp)
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        TestMessageWithOffsetDateTime message = new TestMessageWithOffsetDateTime(
                "test-id",
                now,
                "Test audit log message"
        );

        Message result = messageConverter.toMessage(message, mockSession);

        // Then: Should successfully serialize without throwing InvalidDefinitionException
        assertNotNull(result);
        assertInstanceOf(TextMessage.class, result);
    }

    /**
     * Test DTO simulating AuditLogMessage structure with OffsetDateTime
     */
    static class TestMessageWithOffsetDateTime {
        public String id;
        public OffsetDateTime timestamp;
        public String description;

        public TestMessageWithOffsetDateTime(String id, OffsetDateTime timestamp, String description) {
            this.id = id;
            this.timestamp = timestamp;
            this.description = description;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            TestMessageWithOffsetDateTime that = (TestMessageWithOffsetDateTime) o;
            return Objects.equals(id, that.id) &&
                   Objects.equals(timestamp, that.timestamp) &&
                   Objects.equals(description, that.description);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, timestamp, description);
        }
    }
}