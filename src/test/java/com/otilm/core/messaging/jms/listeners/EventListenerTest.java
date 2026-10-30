package com.otilm.core.messaging.jms.listeners;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.events.IEventHandler;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.util.AuthHelper;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class EventListenerTest {

    @Mock
    private AuthHelper authHelper;

    @Mock
    private IEventHandler eventHandler;

    private Authentication authenticationSeenByHandler;
    private boolean actorInfoSeenByHandler;

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        LoggingHelper.clearActorInfo();
    }

    @Test
    void authenticatesAsTheUserCarriedByTheMessage() throws Exception {
        UUID userUuid = UUID.randomUUID();

        listener().processMessage(uploadMessageFrom(userUuid));

        verify(authHelper).authenticateAsUser(userUuid);
        verify(eventHandler).handleEvent(any());
    }

    /** Losing attribution is acceptable; losing the event is not, so the failure must not reach the retry template. */
    @Test
    void stillHandlesTheEventWhenTheCarriedUserCannotBeAuthenticated() throws Exception {
        UUID userUuid = UUID.randomUUID();
        doThrow(new PlatformAuthenticationException("user is gone")).when(authHelper).authenticateAsUser(userUuid);

        EventListener listener = listener();

        assertThatNoException().isThrownBy(() -> listener.processMessage(uploadMessageFrom(userUuid)));
        verify(eventHandler).handleEvent(any());
    }

    /**
     * {@code authenticateAsUser} writes the actor MDC before calling the auth service, so a failure would otherwise
     * leave audit logs naming a user the platform could not authenticate while the DB columns say "system".
     */
    @Test
    void leavesNoActorAttributionBehindWhenAuthenticationFails() throws Exception {
        UUID userUuid = UUID.randomUUID();
        doAnswer(invocation -> {
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, userUuid.toString(), null);
            throw new PlatformAuthenticationException("user is gone");
        }).when(authHelper).authenticateAsUser(userUuid);
        recordWhatTheHandlerSees();

        listener().processMessage(uploadMessageFrom(userUuid));

        assertThat(actorInfoSeenByHandler).as("no actor attribution may survive a failed authentication").isFalse();
    }

    /**
     * For a deleted user the auth service answers "not authenticated" rather than failing, so
     * {@code authenticateAsUser} returns normally having installed an anonymous principal — which auditing would stamp
     * as "anonymousUser" and OPA would treat as genuine. The event must run with no identity instead.
     */
    @Test
    void discardsTheAnonymousPrincipalInstalledForAUserThatNoLongerResolves() throws Exception {
        UUID userUuid = UUID.randomUUID();
        doAnswer(invocation -> {
            AuthenticationInfo anonymous = AuthenticationInfo.getAnonymousAuthenticationInfo();
            SecurityContextHolder
                    .getContext()
                    .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(anonymous)));
            return null;
        }).when(authHelper).authenticateAsUser(userUuid);
        recordWhatTheHandlerSees();

        listener().processMessage(uploadMessageFrom(userUuid));

        verify(eventHandler).handleEvent(any());
        assertThat(authenticationSeenByHandler)
                .as("an unresolvable user must leave no principal, so audited rows fall back to the system user")
                .isNull();
    }

    @Test
    void eventWithoutARegisteredHandlerIsSkipped() {
        EventListener listener = new EventListener(authHelper, Map.of());

        assertThatNoException()
                .isThrownBy(() -> listener
                        .processMessage(new EventMessage(ResourceEvent.CERTIFICATE_UPLOADED, Resource.CERTIFICATE, null,
                                null, null, "payload", null, null)));
    }

    private void recordWhatTheHandlerSees() throws Exception {
        doAnswer(invocation -> {
            authenticationSeenByHandler = SecurityContextHolder.getContext().getAuthentication();
            actorInfoSeenByHandler = LoggingHelper.hasActorInfo();
            return null;
        }).when(eventHandler).handleEvent(any());
    }

    private EventListener listener() {
        return new EventListener(authHelper, Map.of(ResourceEvent.CERTIFICATE_UPLOADED.getCode(), eventHandler));
    }

    private EventMessage uploadMessageFrom(UUID userUuid) {
        return new EventMessage(ResourceEvent.CERTIFICATE_UPLOADED, Resource.CERTIFICATE, null, null, null, "payload",
                userUuid, null);
    }
}
