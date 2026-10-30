package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.exception.EventException;
import com.otilm.core.events.IEventHandler;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.util.AuthHelper;
import java.util.Map;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@AllArgsConstructor
public class EventListener implements MessageProcessor<EventMessage> {

    private static final Logger logger = LoggerFactory.getLogger(EventListener.class);

    private AuthHelper authHelper;

    private Map<String, IEventHandler> eventHandlers;

    @Override
    public void processMessage(EventMessage eventMessage) {
        if (eventMessage.getUserUuid() != null) {
            authenticateAsActingUser(eventMessage);
        }

        IEventHandler eventHandler = eventHandlers.get(eventMessage.getEvent().getCode());
        if (eventHandler == null) {
            // An event can be published by a Core version deployed ahead of the one carrying its handler; skipping
            // beats poisoning the queue with a message no retry can ever process.
            logger
                    .warn("No handler is registered for event '{}'. The event is skipped. Message: {}",
                            eventMessage.getEvent().getLabel(), eventMessage);
            return;
        }
        try {
            eventHandler.handleEvent(eventMessage);
        } catch (EventException e) {
            logger
                    .error("Error in handling event {}: {}. Message: {}", eventMessage.getEvent().getLabel(),
                            e.getMessage(), eventMessage);
        }
    }

    /**
     * Attribution is best-effort: losing it beats losing the event, so a failure must not escape into the JMS retry
     * template. Failure has two shapes — an unreachable auth service throws, while a user that no longer resolves comes
     * back as {@link AuthenticationInfo#getAnonymousAuthenticationInfo()}, a principal auditing would stamp as
     * "anonymousUser" and authorization would accept. Both are reduced to no identity at all.
     */
    private void authenticateAsActingUser(EventMessage eventMessage) {
        try {
            authHelper.authenticateAsUser(eventMessage.getUserUuid());
            if (!resolvesToRealUser(SecurityContextHolder.getContext().getAuthentication())) {
                logger
                        .warn("User {} carried by event '{}' no longer resolves to a platform user. The event will be "
                                + "handled without an identity and its audited records attributed to the system user.",
                                eventMessage.getUserUuid(), eventMessage.getEvent().getLabel());
                discardIdentity();
            }
        } catch (Exception e) {
            logger
                    .warn("Could not authenticate as user {} carried by event '{}'. The event will be handled without "
                            + "an identity and its audited records attributed to the system user. Message: {}",
                            eventMessage.getUserUuid(), eventMessage.getEvent().getLabel(), e.getMessage(), e);
            discardIdentity();
        }
    }

    private boolean resolvesToRealUser(Authentication authentication) {
        return authentication != null && authentication.getPrincipal() instanceof PlatformUserDetails userDetails
                && userDetails.getUserUuid() != null;
    }

    /** Clears the actor MDC too — {@code authenticateAsUser} writes it before calling the auth service. */
    private void discardIdentity() {
        SecurityContextHolder.clearContext();
        LoggingHelper.clearActorInfo();
    }

}
