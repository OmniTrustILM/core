package com.czertainly.core.messaging.proxy.handler;

import com.czertainly.api.clients.mq.model.ProxyMessage;

/**
 * Handler interface for processing proxy messages by messageType.
 *
 * <p>Implement this interface to handle fire-and-forget style messages where any
 * instance can process the message. The handler is registered with a specific
 * messageType pattern, and when a message arrives with a matching messageType,
 * it will be dispatched to this handler instead of using correlation-based routing.</p>
 *
 * <p>Use cases:</p>
 * <ul>
 *   <li>Health check messages from proxies</li>
 *   <li>Certificate issuance results that need to be stored in the database</li>
 *   <li>Discovery results that should be processed by any available instance</li>
 *   <li>Long-running operations where the response can be handled asynchronously</li>
 * </ul>
 *
 * <p>Pattern matching follows RabbitMQ topic exchange semantics. Segments are separated by '.' (dot):</p>
 * <ul>
 *   <li>Exact match: "health.check" matches only "health.check"</li>
 *   <li>Single-segment wildcard '*': "GET.v1.certificates.*" matches "GET.v1.certificates.123"
 *       but NOT "GET.v1.certificates" or "GET.v1.certificates.123.details"</li>
 *   <li>Multi-segment wildcard '#': "audit.events.#" matches "audit.events", "audit.events.users.signup"</li>
 *   <li>Pattern "#" alone matches everything (fanout behavior)</li>
 * </ul>
 */
public interface MessageTypeResponseHandler {

    /**
     * Get the message type pattern this handler processes.
     * Can be an exact match or a pattern with '*' and '#' wildcards.
     *
     * @return Message type pattern (e.g., "health.check", "GET.v1.certificates.*", "audit.events.#")
     */
    String getMessageType();

    /**
     * Process the proxy message.
     *
     * @param message The proxy message to handle
     */
    void handleResponse(ProxyMessage message);
}
