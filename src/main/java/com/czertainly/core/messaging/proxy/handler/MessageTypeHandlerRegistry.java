package com.czertainly.core.messaging.proxy.handler;

import com.czertainly.api.clients.mq.model.ProxyMessage;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry for messageType-based message handlers.
 * Dispatches proxy messages to appropriate handlers based on messageType.
 *
 * <p>This enables fire-and-forget style messaging where any instance can process
 * a message based on its messageType, rather than requiring correlation-based
 * routing back to the originating instance.</p>
 *
 * <p>Pattern matching follows RabbitMQ topic exchange semantics:</p>
 * <ul>
 *   <li>Segments are separated by '.' (dot)</li>
 *   <li>Exact match: "health.check" matches exactly "health.check"</li>
 *   <li>Single-segment wildcard: '*' matches exactly one segment
 *       (e.g., "GET.v1.certificates.*" matches "GET.v1.certificates.123" but not "GET.v1.certificates" or "GET.v1.certificates.123.details")</li>
 *   <li>Multi-segment wildcard: '#' matches zero or more segments
 *       (e.g., "audit.events.#" matches "audit.events", "audit.events.users", "audit.events.users.signup")</li>
 *   <li>Pattern "#" alone matches everything (fanout behavior)</li>
 * </ul>
 *
 * <p>When multiple patterns match, the most specific one wins (literal segments > '*' > '#').</p>
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "proxy.enabled", havingValue = "true")
@ConditionalOnBean(MessageTypeResponseHandler.class)
public class MessageTypeHandlerRegistry {

    private final Map<String, MessageTypeResponseHandler> handlers = new ConcurrentHashMap<>();
    private final List<MessageTypeResponseHandler> registeredHandlers;

    public MessageTypeHandlerRegistry(List<MessageTypeResponseHandler> registeredHandlers) {
        this.registeredHandlers = registeredHandlers != null ? registeredHandlers : List.of();
    }

    @PostConstruct
    public void init() {
        for (MessageTypeResponseHandler handler : registeredHandlers) {
            String messageType = handler.getMessageType();
            if (messageType != null && !messageType.isBlank()) {
                MessageTypeResponseHandler existing = handlers.get(messageType);
                if (existing != null) {
                    log.warn("Duplicate messageType '{}' detected: handler {} would overwrite existing handler {}. Keeping first registered handler.",
                            messageType, handler.getClass().getSimpleName(), existing.getClass().getSimpleName());
                    continue;
                }
                handlers.put(messageType, handler);
                log.info("Registered messageType handler: {} -> {}", messageType, handler.getClass().getSimpleName());
            } else {
                log.warn("Skipping handler with null/blank messageType: {}", handler.getClass().getSimpleName());
            }
        }
        log.info("MessageTypeHandlerRegistry initialized with {} handlers: {}", handlers.size(), handlers.keySet());
    }

    /**
     * Check if a handler exists for the given messageType.
     *
     * @param messageType The message type to check
     * @return true if a handler is registered (exact or pattern match)
     */
    public boolean hasHandler(String messageType) {
        if (messageType == null) {
            return false;
        }
        return handlers.containsKey(messageType) || findPatternMatch(messageType) != null;
    }

    /**
     * Dispatch a message to the appropriate handler based on messageType.
     *
     * @param message The proxy message to dispatch
     * @return true if a handler was found and invoked, false otherwise
     */
    public boolean dispatch(ProxyMessage message) {
        if (message == null) {
            log.debug("Cannot dispatch null message");
            return false;
        }
        String messageType = message.getMessageType();
        if (messageType == null) {
            log.debug("Cannot dispatch message without messageType");
            return false;
        }

        // Try exact match first
        MessageTypeResponseHandler handler = handlers.get(messageType);

        // Try pattern match if no exact match
        if (handler == null) {
            handler = findPatternMatch(messageType);
        }

        if (handler != null) {
            try {
                log.debug("Dispatching to handler {} for messageType={}", handler.getClass().getSimpleName(), messageType);
                handler.handleResponse(message);
                return true;
            } catch (Exception e) {
                log.error("Error handling message messageType={}: {}", messageType, e.getMessage(), e);
                return false;
            }
        }

        log.debug("No handler found for messageType={}", messageType);
        return false;
    }

    /**
     * Find a handler matching a pattern using RabbitMQ topic exchange semantics.
     * Uses most-specific-wins strategy based on pattern specificity score.
     * When scores are equal, uses lexicographic comparison for deterministic selection.
     *
     * @param messageType The messageType to match
     * @return The most specific matching handler, or null if none match
     */
    private MessageTypeResponseHandler findPatternMatch(String messageType) {
        MessageTypeResponseHandler bestMatch = null;
        int bestScore = -1;
        String bestPattern = null;

        for (Map.Entry<String, MessageTypeResponseHandler> entry : handlers.entrySet()) {
            String pattern = entry.getKey();
            if (matches(pattern, messageType)) {
                int score = calculateSpecificity(pattern);
                // Use lexicographic comparison as tie-breaker for deterministic selection
                if (score > bestScore || (score == bestScore && bestPattern != null && pattern.compareTo(bestPattern) < 0)) {
                    bestScore = score;
                    bestMatch = entry.getValue();
                    bestPattern = pattern;
                }
            }
        }
        return bestMatch;
    }

    /**
     * Check if a pattern matches a messageType using RabbitMQ topic exchange semantics.
     * Segments are separated by '.'; '*' matches exactly one segment; '#' matches zero or more.
     *
     * @param pattern The pattern (may contain '*' and '#' wildcards)
     * @param messageType The messageType to match
     * @return true if the messageType matches the pattern
     */
    private boolean matches(String pattern, String messageType) {
        if (pattern == null || messageType == null) {
            return false;
        }
        if (pattern.equals(messageType)) {
            return true;
        }
        if (!pattern.contains("*") && !pattern.contains("#")) {
            return false;
        }

        String[] patternSegs = pattern.split("\\.", -1);
        String[] messageSegs = messageType.split("\\.", -1);
        return matchSegments(patternSegs, 0, messageSegs, 0);
    }

    /**
     * Recursively match pattern segments against message segments.
     *
     * @param pattern Pattern segments array
     * @param pi Current pattern index
     * @param message Message segments array
     * @param mi Current message index
     * @return true if remaining segments match
     */
    private boolean matchSegments(String[] pattern, int pi, String[] message, int mi) {
        // Base case: both exhausted - success
        if (pi == pattern.length && mi == message.length) {
            return true;
        }

        // Pattern exhausted but message has more segments - fail
        if (pi == pattern.length) {
            return false;
        }

        String seg = pattern[pi];

        // Handle '#' - matches zero or more segments
        if ("#".equals(seg)) {
            // If # is last segment, it matches everything remaining
            if (pi == pattern.length - 1) {
                return true;
            }
            // Try matching # with 0, 1, 2, ... segments
            for (int skip = 0; skip <= message.length - mi; skip++) {
                if (matchSegments(pattern, pi + 1, message, mi + skip)) {
                    return true;
                }
            }
            return false;
        }

        // Message exhausted but pattern has more non-# segments - check if remaining are all #
        if (mi == message.length) {
            for (int i = pi; i < pattern.length; i++) {
                if (!"#".equals(pattern[i])) {
                    return false;
                }
            }
            return true;
        }

        // Handle '*' - matches exactly one segment
        if ("*".equals(seg)) {
            return matchSegments(pattern, pi + 1, message, mi + 1);
        }

        // Literal match
        if (seg.equals(message[mi])) {
            return matchSegments(pattern, pi + 1, message, mi + 1);
        }

        return false;
    }

    /**
     * Calculate specificity score for a pattern.
     * Higher score = more specific pattern.
     * Scoring: literal segment = 100, '*' = 10, '#' = 1.
     *
     * @param pattern The pattern to score
     * @return Specificity score (higher = more specific)
     */
    private int calculateSpecificity(String pattern) {
        if (pattern == null || pattern.isEmpty()) {
            return 0;
        }

        int score = 0;
        for (String seg : pattern.split("\\.", -1)) {
            if ("#".equals(seg)) {
                score += 1;
            } else if ("*".equals(seg)) {
                score += 10;
            } else {
                score += 100;
            }
        }
        return score;
    }

    /**
     * Get the number of registered handlers.
     * Useful for monitoring.
     */
    public int getHandlerCount() {
        return handlers.size();
    }
}
