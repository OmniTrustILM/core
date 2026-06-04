package com.czertainly.core.messaging.jms.listeners;

import com.czertainly.api.exception.MessageHandlingException;

/**
 * The {@link MessageProcessor} interface represents a contract for processing messages of a specific type.
 * Classes implementing this interface are responsible for handling messages of the given type
 * and processing them according to specific business logic.
 *
 * @param <T> the type of message to be processed

 * Implementing classes may throw {@link MessageHandlingException} to indicate
 * any issues or errors encountered during the message processing.
 */
public interface MessageProcessor<T> {

    void processMessage(T message) throws MessageHandlingException;
}
