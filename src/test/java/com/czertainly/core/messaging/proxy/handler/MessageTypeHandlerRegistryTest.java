package com.czertainly.core.messaging.proxy.handler;

import com.czertainly.api.clients.mq.model.ConnectorResponse;
import com.czertainly.api.clients.mq.model.ProxyMessage;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link MessageTypeHandlerRegistry}.
 * Tests handler registration, exact match, and RabbitMQ topic exchange pattern matching.
 *
 * <p>Pattern matching follows RabbitMQ topic exchange semantics:</p>
 * <ul>
 *   <li>Segments separated by '.' (dot)</li>
 *   <li>'*' matches exactly one segment</li>
 *   <li>'#' matches zero or more segments</li>
 * </ul>
 */
class MessageTypeHandlerRegistryTest {

    // ==================== Initialization Tests ====================

    @Test
    void init_registersAllHandlers() {
        List<MessageTypeResponseHandler> handlers = List.of(
                createHandler("type.a"),
                createHandler("type.b"),
                createHandler("type.c")
        );

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(handlers);
        registry.init();

        assertThat(registry.getHandlerCount()).isEqualTo(3);
    }

    @Test
    void init_withNullHandlerList_initializesEmptyRegistry() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(null);
        registry.init();

        assertThat(registry.getHandlerCount()).isZero();
    }

    @Test
    void init_withEmptyHandlerList_initializesEmptyRegistry() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(List.of());
        registry.init();

        assertThat(registry.getHandlerCount()).isZero();
    }

    @Test
    void init_withBlankMessageType_skipsHandler() {
        List<MessageTypeResponseHandler> handlers = List.of(
                createHandler("valid.type"),
                createHandler(""),
                createHandler("another.type")
        );

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(handlers);
        registry.init();

        assertThat(registry.getHandlerCount()).isEqualTo(2);
    }

    @Test
    void init_withNullMessageType_skipsHandler() {
        List<MessageTypeResponseHandler> handlers = new ArrayList<>();
        handlers.add(createHandler("valid.type"));
        handlers.add(createHandler(null));
        handlers.add(createHandler("another.type"));

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(handlers);
        registry.init();

        assertThat(registry.getHandlerCount()).isEqualTo(2);
    }

    @Test
    void init_withDuplicateMessageType_keepsFirstHandler() {
        MessageTypeResponseHandler firstHandler = createHandler("duplicate.type");
        MessageTypeResponseHandler secondHandler = createHandler("duplicate.type");

        List<MessageTypeResponseHandler> handlers = List.of(firstHandler, secondHandler);

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(handlers);
        registry.init();

        // Only one should be registered
        assertThat(registry.getHandlerCount()).isEqualTo(1);

        // Verify first handler is kept
        ProxyMessage message = createMessage("duplicate.type");
        registry.dispatch(message);
        verify(firstHandler).handleResponse(message);
        verify(secondHandler, never()).handleResponse(any());
    }

    // ==================== hasHandler - Exact Match Tests ====================

    @Test
    void hasHandler_withExactMatch_returnsTrue() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("certificate.issued"))
        );
        registry.init();

        assertThat(registry.hasHandler("certificate.issued")).isTrue();
    }

    @Test
    void hasHandler_withNoMatch_returnsFalse() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("certificate.issued"))
        );
        registry.init();

        assertThat(registry.hasHandler("certificate.revoked")).isFalse();
        assertThat(registry.hasHandler("unknown.type")).isFalse();
    }

    @Test
    void hasHandler_withNullMessageType_returnsFalse() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("certificate.issued"))
        );
        registry.init();

        assertThat(registry.hasHandler(null)).isFalse();
    }

    // ==================== hasHandler - Single-Segment Wildcard (*) Tests ====================

    @Test
    void hasHandler_singleWildcard_matchesExactlyOneSegment() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("GET.v1.certificates.*"))
        );
        registry.init();

        // Should match: exactly one segment after certificates
        assertThat(registry.hasHandler("GET.v1.certificates.123")).isTrue();
        assertThat(registry.hasHandler("GET.v1.certificates.abc")).isTrue();

        // Should NOT match: no segment after certificates
        assertThat(registry.hasHandler("GET.v1.certificates")).isFalse();

        // Should NOT match: more than one segment after certificates
        assertThat(registry.hasHandler("GET.v1.certificates.123.details")).isFalse();
    }

    @Test
    void hasHandler_singleWildcard_atStart() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("*.v1.certificates"))
        );
        registry.init();

        assertThat(registry.hasHandler("GET.v1.certificates")).isTrue();
        assertThat(registry.hasHandler("POST.v1.certificates")).isTrue();

        // Wrong number of segments
        assertThat(registry.hasHandler("v1.certificates")).isFalse();
        assertThat(registry.hasHandler("GET.POST.v1.certificates")).isFalse();
    }

    @Test
    void hasHandler_singleWildcard_inMiddle() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("GET.*.certificates"))
        );
        registry.init();

        assertThat(registry.hasHandler("GET.v1.certificates")).isTrue();
        assertThat(registry.hasHandler("GET.v2.certificates")).isTrue();

        // Wrong number of middle segments
        assertThat(registry.hasHandler("GET.certificates")).isFalse();
        assertThat(registry.hasHandler("GET.v1.v2.certificates")).isFalse();
    }

    @Test
    void hasHandler_multipleStarWildcards() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("*.v1.*.issue"))
        );
        registry.init();

        assertThat(registry.hasHandler("POST.v1.certificates.issue")).isTrue();
        assertThat(registry.hasHandler("GET.v1.authorities.issue")).isTrue();

        // Wrong number of segments
        assertThat(registry.hasHandler("POST.v1.certificates")).isFalse();
        assertThat(registry.hasHandler("POST.v1.certificates.123.issue")).isFalse();
    }

    // ==================== hasHandler - Multi-Segment Wildcard (#) Tests ====================

    @Test
    void hasHandler_hashWildcard_matchesZeroOrMoreSegments() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("GET.v1.#"))
        );
        registry.init();

        // Zero segments after v1
        assertThat(registry.hasHandler("GET.v1")).isTrue();

        // One segment
        assertThat(registry.hasHandler("GET.v1.certificates")).isTrue();

        // Multiple segments
        assertThat(registry.hasHandler("GET.v1.certificates.123.details")).isTrue();
    }

    @Test
    void hasHandler_hashAtEnd_matchesEverythingAfter() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("audit.events.#"))
        );
        registry.init();

        assertThat(registry.hasHandler("audit.events")).isTrue();
        assertThat(registry.hasHandler("audit.events.users")).isTrue();
        assertThat(registry.hasHandler("audit.events.users.signup")).isTrue();
        assertThat(registry.hasHandler("audit.events.orders.placed.confirmed")).isTrue();

        // Different prefix should not match
        assertThat(registry.hasHandler("audit.logs.events")).isFalse();
    }

    @Test
    void hasHandler_hashOnly_matchesEverything() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("#"))
        );
        registry.init();

        // Fanout behavior - matches everything
        assertThat(registry.hasHandler("GET.v1.certificates")).isTrue();
        assertThat(registry.hasHandler("POST.anything.at.all")).isTrue();
        assertThat(registry.hasHandler("single")).isTrue();
        assertThat(registry.hasHandler("a.b.c.d.e.f.g")).isTrue();
    }

    @Test
    void hasHandler_hashInMiddle_matchesVariableSegments() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("events.#.completed"))
        );
        registry.init();

        // Zero middle segments
        assertThat(registry.hasHandler("events.completed")).isTrue();

        // One middle segment
        assertThat(registry.hasHandler("events.order.completed")).isTrue();

        // Multiple middle segments
        assertThat(registry.hasHandler("events.order.payment.completed")).isTrue();

        // Wrong ending
        assertThat(registry.hasHandler("events.order.failed")).isFalse();
    }

    @Test
    void hasHandler_hashAtStart() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("#.completed"))
        );
        registry.init();

        assertThat(registry.hasHandler("completed")).isTrue();
        assertThat(registry.hasHandler("task.completed")).isTrue();
        assertThat(registry.hasHandler("workflow.task.completed")).isTrue();

        assertThat(registry.hasHandler("completed.extra")).isFalse();
    }

    // ==================== hasHandler - Combined Wildcard Tests ====================

    @Test
    void hasHandler_starAndHashCombined() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("*.events.#"))
        );
        registry.init();

        assertThat(registry.hasHandler("audit.events")).isTrue();
        assertThat(registry.hasHandler("system.events.user.login")).isTrue();
        assertThat(registry.hasHandler("app.events.order.created.processed")).isTrue();

        // Wrong - first segment must be exactly one
        assertThat(registry.hasHandler("events")).isFalse();
        assertThat(registry.hasHandler("audit.log.events")).isFalse();
    }

    @Test
    void hasHandler_hashThenStar() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("#.resource.*"))
        );
        registry.init();

        // # matches zero, then resource, then exactly one
        assertThat(registry.hasHandler("resource.123")).isTrue();

        // # matches one, then resource, then exactly one
        assertThat(registry.hasHandler("api.resource.456")).isTrue();

        // # matches multiple, then resource, then exactly one
        assertThat(registry.hasHandler("v1.api.resource.789")).isTrue();

        // Missing the final segment for *
        assertThat(registry.hasHandler("api.resource")).isFalse();

        // Too many segments after resource
        assertThat(registry.hasHandler("api.resource.123.456")).isFalse();
    }

    // ==================== dispatch - Exact Match Tests ====================

    @Test
    void dispatch_withExactMatch_invokesHandler() {
        MessageTypeResponseHandler handler = createHandler("certificate.issued");
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(List.of(handler));
        registry.init();

        ProxyMessage message = createMessage("certificate.issued");
        boolean result = registry.dispatch(message);

        assertThat(result).isTrue();
        verify(handler).handleResponse(message);
    }

    @Test
    void dispatch_withExactMatch_returnsTrue() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("certificate.issued"))
        );
        registry.init();

        assertThat(registry.dispatch(createMessage("certificate.issued"))).isTrue();
    }

    // ==================== dispatch - Wildcard Match Tests ====================

    @Test
    void dispatch_withSingleWildcardMatch_invokesHandler() {
        MessageTypeResponseHandler handler = createHandler("POST.v1.certificates.*");
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(List.of(handler));
        registry.init();

        ProxyMessage message = createMessage("POST.v1.certificates.issue");
        boolean result = registry.dispatch(message);

        assertThat(result).isTrue();
        verify(handler).handleResponse(message);
    }

    @Test
    void dispatch_withHashWildcardMatch_invokesHandler() {
        MessageTypeResponseHandler handler = createHandler("audit.#");
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(List.of(handler));
        registry.init();

        ProxyMessage message = createMessage("audit.events.user.login");
        boolean result = registry.dispatch(message);

        assertThat(result).isTrue();
        verify(handler).handleResponse(message);
    }

    // ==================== dispatch - Specificity/Precedence Tests ====================

    @Test
    void dispatch_exactMatchTakesPrecedence_overWildcard() {
        MessageTypeResponseHandler wildcardHandler = createHandler("GET.v1.certificates.*");
        MessageTypeResponseHandler exactHandler = createHandler("GET.v1.certificates.special");

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(wildcardHandler, exactHandler)
        );
        registry.init();

        ProxyMessage message = createMessage("GET.v1.certificates.special");
        registry.dispatch(message);

        // Exact match should take precedence
        verify(exactHandler).handleResponse(message);
        verify(wildcardHandler, never()).handleResponse(any());
    }

    @Test
    void dispatch_moreSpecificPatternWins() {
        MessageTypeResponseHandler generalHandler = createHandler("GET.#");
        MessageTypeResponseHandler specificHandler = createHandler("GET.v1.certificates.*");

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(generalHandler, specificHandler)
        );
        registry.init();

        ProxyMessage message = createMessage("GET.v1.certificates.123");
        registry.dispatch(message);

        // More specific pattern (with literal segments) wins
        verify(specificHandler).handleResponse(message);
        verify(generalHandler, never()).handleResponse(any());
    }

    @Test
    void dispatch_literalBeatsWildcard() {
        MessageTypeResponseHandler wildcardHandler = createHandler("GET.v1.certificates.*");
        MessageTypeResponseHandler literalHandler = createHandler("GET.v1.certificates.special");

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(wildcardHandler, literalHandler)
        );
        registry.init();

        // Message matching both patterns
        ProxyMessage message = createMessage("GET.v1.certificates.special");
        registry.dispatch(message);

        // Literal match wins
        verify(literalHandler).handleResponse(message);
        verify(wildcardHandler, never()).handleResponse(any());
    }

    @Test
    void dispatch_starBeatsHash() {
        MessageTypeResponseHandler hashHandler = createHandler("GET.v1.#");
        MessageTypeResponseHandler starHandler = createHandler("GET.v1.*");

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(hashHandler, starHandler)
        );
        registry.init();

        // Message with single segment after v1
        ProxyMessage message = createMessage("GET.v1.certificates");
        registry.dispatch(message);

        // * is more specific than # (matches exactly one vs zero-or-more)
        verify(starHandler).handleResponse(message);
        verify(hashHandler, never()).handleResponse(any());
    }

    @Test
    void dispatch_longerPatternWins() {
        MessageTypeResponseHandler shortHandler = createHandler("GET.*");
        MessageTypeResponseHandler longHandler = createHandler("GET.v1.certificates.*");

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(shortHandler, longHandler)
        );
        registry.init();

        ProxyMessage message = createMessage("GET.v1.certificates.issue");
        registry.dispatch(message);

        // Longer pattern with more literal segments should win
        verify(longHandler).handleResponse(message);
        verify(shortHandler, never()).handleResponse(any());
    }

    @Test
    void dispatch_multipleWildcards_mostSpecificWins() {
        MessageTypeResponseHandler level1 = createHandler("GET.#");
        MessageTypeResponseHandler level2 = createHandler("GET.v1.#");
        MessageTypeResponseHandler level3 = createHandler("GET.v1.certificates.#");

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(level1, level2, level3)
        );
        registry.init();

        // Test different paths - most specific (highest specificity score) should win
        ProxyMessage message1 = createMessage("GET.v1.certificates.123");
        registry.dispatch(message1);
        verify(level3).handleResponse(message1);

        ProxyMessage message2 = createMessage("GET.v1.keys.456");
        registry.dispatch(message2);
        verify(level2).handleResponse(message2);

        ProxyMessage message3 = createMessage("GET.other.path");
        registry.dispatch(message3);
        verify(level1).handleResponse(message3);
    }

    // ==================== dispatch - No Match Tests ====================

    @Test
    void dispatch_withNoMatch_returnsFalse() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("certificate.issued"))
        );
        registry.init();

        assertThat(registry.dispatch(createMessage("unknown.type"))).isFalse();
    }

    @Test
    void dispatch_withNullResponse_returnsFalse() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("certificate.issued"))
        );
        registry.init();

        assertThat(registry.dispatch(null)).isFalse();
    }

    @Test
    void dispatch_withNullMessageType_returnsFalse() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("certificate.issued"))
        );
        registry.init();

        assertThat(registry.dispatch(createMessage(null))).isFalse();
    }

    // ==================== Handler Error Tests ====================

    @Test
    void dispatch_onHandlerException_returnsFalse() {
        MessageTypeResponseHandler failingHandler = mock(MessageTypeResponseHandler.class);
        when(failingHandler.getMessageType()).thenReturn("failing.type");
        doThrow(new RuntimeException("Handler failed")).when(failingHandler).handleResponse(any());

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(List.of(failingHandler));
        registry.init();

        ProxyMessage message = createMessage("failing.type");
        boolean result = registry.dispatch(message);

        assertThat(result).isFalse();
        verify(failingHandler).handleResponse(message);
    }

    // ==================== Edge Cases ====================

    @Test
    void matches_consecutiveWildcards_workCorrectly() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("*.*.end"))
        );
        registry.init();

        assertThat(registry.hasHandler("a.b.end")).isTrue();
        assertThat(registry.hasHandler("x.y.end")).isTrue();

        // Wrong number of segments before 'end'
        assertThat(registry.hasHandler("a.end")).isFalse();
        assertThat(registry.hasHandler("a.b.c.end")).isFalse();
    }

    @Test
    void matches_emptySegments_handledCorrectly() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("a..b"))
        );
        registry.init();

        // Pattern with empty segment
        assertThat(registry.hasHandler("a..b")).isTrue();
        assertThat(registry.hasHandler("a.x.b")).isFalse();
    }

    @Test
    void matches_singleSegmentPattern() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("*"))
        );
        registry.init();

        assertThat(registry.hasHandler("anything")).isTrue();
        assertThat(registry.hasHandler("multi.segment")).isFalse();
    }

    @Test
    void matches_multipleHashPatterns() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(createHandler("#.middle.#"))
        );
        registry.init();

        assertThat(registry.hasHandler("middle")).isTrue();
        assertThat(registry.hasHandler("before.middle")).isTrue();
        assertThat(registry.hasHandler("middle.after")).isTrue();
        assertThat(registry.hasHandler("before.middle.after")).isTrue();
        assertThat(registry.hasHandler("a.b.middle.c.d")).isTrue();

        assertThat(registry.hasHandler("nomiddlehere")).isFalse();
    }

    // ==================== getHandlerCount Tests ====================

    @Test
    void getHandlerCount_returnsCorrectCount() {
        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(
                List.of(
                        createHandler("type.a"),
                        createHandler("type.b"),
                        createHandler("type.c")
                )
        );
        registry.init();

        assertThat(registry.getHandlerCount()).isEqualTo(3);
    }

    @Test
    void getHandlerCount_afterInit_withNullTypes_excludesInvalid() {
        List<MessageTypeResponseHandler> handlers = new ArrayList<>();
        handlers.add(createHandler("valid.type"));
        handlers.add(createHandler(null));
        handlers.add(createHandler(""));

        MessageTypeHandlerRegistry registry = new MessageTypeHandlerRegistry(handlers);
        registry.init();

        assertThat(registry.getHandlerCount()).isEqualTo(1);
    }

    // ==================== Helper Methods ====================

    private MessageTypeResponseHandler createHandler(String messageType) {
        MessageTypeResponseHandler handler = mock(MessageTypeResponseHandler.class);
        when(handler.getMessageType()).thenReturn(messageType);
        return handler;
    }

    private ProxyMessage createMessage(String messageType) {
        return ProxyMessage.builder()
                .correlationId("test-corr")
                .proxyId("test-proxy")
                .messageType(messageType)
                .timestamp(Instant.now())
                .connectorResponse(ConnectorResponse.builder()
                        .statusCode(200)
                        .build())
                .build();
    }
}
