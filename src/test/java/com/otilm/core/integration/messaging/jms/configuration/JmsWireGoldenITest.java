package com.otilm.core.integration.messaging.jms.configuration;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.messaging.model.ValidationMessage;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.serialization.golden.WireGolden;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.jms.JMSException;
import jakarta.jms.Session;
import jakarta.jms.TextMessage;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.jms.support.converter.MappingJackson2MessageConverter;
import org.springframework.jms.support.converter.MessageConverter;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JmsWireGoldenITest extends BaseSpringBootTest {

    private static final UUID FIRST = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID SECOND = UUID.fromString("00000000-0000-0000-0000-000000000002");

    @Autowired
    private Jackson2ObjectMapperBuilder objectMapperBuilder;

    @Autowired
    private MessageConverter messageConverter;

    @Test
    void jmsMapperIsConfiguredAsOnThe35Line() {
        // The converter keeps its mapper private; JmsConfig builds it with the factory fingerprinted below.
        assertInstanceOf(MappingJackson2MessageConverter.class, messageConverter);
        WireGolden
                .assertFingerprintMatches("jms-message-mapper.txt",
                        ObjectMapperFactory.jmsMessage(objectMapperBuilder));
    }

    @Test
    void validationMessageIsWrittenAsOnThe35Line() throws Exception {
        ValidationMessage message = new ValidationMessage(Resource.CERTIFICATE, List.of(FIRST), SECOND, "discovery",
                FIRST, "location");
        WireGolden.assertMatches("jms-validation-message.json", written(message));
    }

    @Test
    void eventMessageIsWrittenAsOnThe35Line() throws Exception {
        EventMessage message = new EventMessage(ResourceEvent.CERTIFICATE_STATUS_CHANGED, Resource.CERTIFICATE, FIRST,
                Map.of("at", OffsetDateTime.parse("2026-01-02T03:04:05Z")));
        WireGolden.assertMatches("jms-event-message.json", written(message));
    }

    private String written(Object message) throws JMSException {
        Session session = mock(Session.class);
        TextMessage textMessage = mock(TextMessage.class);
        when(session.createTextMessage(anyString())).thenReturn(textMessage);
        messageConverter.toMessage(message, session);
        ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
        verify(session).createTextMessage(text.capture());
        return text.getValue();
    }
}
