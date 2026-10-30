package com.otilm.core.events;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.other.ResourceEvent;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.workflows.Trigger;
import com.otilm.core.dao.entity.workflows.TriggerAssociation;
import com.otilm.core.dao.entity.workflows.TriggerHistory;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import com.otilm.core.evaluator.TriggerEvaluator;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authn.PlatformAuthenticationException;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.util.AuthHelper;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Trigger processing runs as the association's creator, so the automation carries its owner's permissions. That
 * impersonation must end with the loop: the audited writes afterwards (Certificate, CertificateEventHistory) belong to
 * the acting user, and JPA auditing reads whoever is left in the context.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EventHandlerTriggerIdentityTest {

    private static final String UPLOADER = "uploader";
    private static final String TRIGGER_CREATOR = "trigger-creator";

    private String usernameInsideLoop;
    private String actorNameInsideLoop;

    @Mock
    private AuthHelper authHelper;

    @Mock
    private TriggerEvaluator<Certificate> triggerEvaluator;

    @Mock
    private SecurityFilterRepository<Certificate, UUID> repository;

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        LoggingHelper.clearActorInfo();
    }

    @Test
    void actingUserIsRestoredAfterTriggersAreEvaluated() {
        UUID uploaderUuid = UUID.randomUUID();
        UUID triggerCreatorUuid = UUID.randomUUID();
        authenticateAs(uploaderUuid, UPLOADER);
        impersonateOnAuthenticateAsUser(triggerCreatorUuid);

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(uploaderUuid);
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(triggerCreatorUuid));

        handler.evaluateTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null);

        assertThat(currentUsername())
                .as("identity after the trigger loop must be the acting user, not the trigger's creator")
                .isEqualTo(UPLOADER);
    }

    @Test
    void actingUserIsRestoredAfterIgnoreTriggersAreEvaluated() throws Exception {
        UUID uploaderUuid = UUID.randomUUID();
        UUID triggerCreatorUuid = UUID.randomUUID();
        authenticateAs(uploaderUuid, UPLOADER);
        impersonateOnAuthenticateAsUser(triggerCreatorUuid);
        when(triggerEvaluator.evaluateTrigger(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(mock(TriggerHistory.class));

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(uploaderUuid);
        context.getPlatformTriggers().getIgnoreTriggers().add(associationCreatedBy(triggerCreatorUuid));

        handler.evaluateIgnoreTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null);

        assertThat(currentUsername())
                .as("identity after the ignore-trigger loop must be the acting user")
                .isEqualTo(UPLOADER);
    }

    /** Without this, an implementation that cleared the context and never impersonated would pass every other test. */
    @Test
    void triggersAreEvaluatedAsTheAssociationCreator() throws Exception {
        UUID uploaderUuid = UUID.randomUUID();
        UUID triggerCreatorUuid = UUID.randomUUID();
        authenticateAs(uploaderUuid, UPLOADER);
        impersonateOnAuthenticateAsUser(triggerCreatorUuid);
        recordIdentityInsideLoop();

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(uploaderUuid);
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(triggerCreatorUuid));

        handler.evaluateTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null);

        assertThat(usernameInsideLoop)
                .as("the trigger itself must be evaluated as its creator, not as the acting user")
                .isEqualTo(TRIGGER_CREATOR);
    }

    /** {@code authenticateAsUser} writes the actor uuid with a null name, so a stale name would mix with it. */
    @Test
    void actingUsersActorAttributionDoesNotBleedIntoTheTriggerLoop() throws Exception {
        UUID uploaderUuid = UUID.randomUUID();
        UUID triggerCreatorUuid = UUID.randomUUID();
        authenticateAs(uploaderUuid, UPLOADER);
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, uploaderUuid.toString(), UPLOADER);
        impersonateOnAuthenticateAsUser(triggerCreatorUuid);
        recordActorNameInsideLoop();

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(uploaderUuid);
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(triggerCreatorUuid));

        handler.evaluateTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null);

        assertThat(actorNameInsideLoop)
                .as("the acting user's actor name must not remain while the trigger creator's uuid is installed")
                .isNotEqualTo(UPLOADER);
        assertThat(LoggingHelper.getActorInfo().name())
                .as("the acting user's actor must be restored after the loop")
                .isEqualTo(UPLOADER);
    }

    /**
     * The memo can name a different user than the thread actually holds, so it must not decide whether impersonation is
     * needed — only the installed principal can.
     */
    @Test
    void impersonatesWhenTheMemoDisagreesWithTheInstalledPrincipal() {
        UUID triggerCreatorUuid = UUID.randomUUID();
        authenticateAs(UUID.randomUUID(), UPLOADER);
        impersonateOnAuthenticateAsUser(triggerCreatorUuid);

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(triggerCreatorUuid);
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(triggerCreatorUuid));

        handler.evaluateTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null);

        verify(authHelper).authenticateAsUser(triggerCreatorUuid);
    }

    /**
     * {@code currentUserUuid} is seeded from the message, so it can name a user the thread never held — the listener
     * degrades to no identity when the carried user fails to authenticate.
     */
    @Test
    void impersonatesEvenWhenTheContextMemoAlreadyNamesTheTriggerCreator() {
        UUID triggerCreatorUuid = UUID.randomUUID();
        SecurityContextHolder.clearContext();
        impersonateOnAuthenticateAsUser(triggerCreatorUuid);

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(triggerCreatorUuid);
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(triggerCreatorUuid));

        handler.evaluateTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null);

        verify(authHelper).authenticateAsUser(triggerCreatorUuid);
    }

    @Test
    void unauthenticatedCallerStaysUnauthenticatedAfterTriggersAreEvaluated() {
        UUID triggerCreatorUuid = UUID.randomUUID();
        impersonateOnAuthenticateAsUser(triggerCreatorUuid);

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(null);
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(triggerCreatorUuid));

        handler.evaluateTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null);

        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .as("an event with no acting user must not inherit the trigger creator's identity")
                .isNull();
    }

    /**
     * A deleted or disabled owner does not make {@code authenticateAsUser} throw — the auth service answers "not
     * authenticated" and the client installs an anonymous principal. Evaluating the trigger's actions under that
     * principal is the wrong-permissions outcome the impersonation exists to prevent.
     */
    @Test
    void failsRatherThanEvaluatingATriggerWhoseOwnerNoLongerResolves() throws Exception {
        UUID deletedOwnerUuid = UUID.randomUUID();
        authenticateAs(UUID.randomUUID(), UPLOADER);
        doAnswer(invocation -> {
            AuthenticationInfo anonymous = AuthenticationInfo.getAnonymousAuthenticationInfo();
            SecurityContextHolder
                    .getContext()
                    .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(anonymous)));
            return null;
        }).when(authHelper).authenticateAsUser(deletedOwnerUuid);

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(null);
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(deletedOwnerUuid));

        assertThatThrownBy(
                () -> handler.evaluateTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null))
                .as("the event must fail rather than evaluate the trigger under an anonymous principal")
                .isInstanceOf(PlatformAuthenticationException.class);

        verify(triggerEvaluator, never()).evaluateTrigger(any(), any(), any(), any(), any(), any(), any());
    }

    /**
     * Two associations owned by different users: the second must not inherit the first owner's actor attribution.
     */
    @Test
    void actorAttributionDoesNotCarryBetweenAssociationOwners() throws Exception {
        UUID firstOwner = UUID.randomUUID();
        UUID secondOwner = UUID.randomUUID();
        authenticateAs(UUID.randomUUID(), UPLOADER);
        impersonateOnAuthenticateAsUser(firstOwner);
        impersonateOnAuthenticateAsUser(secondOwner);
        List<String> actorUuidsSeen = new ArrayList<>();
        doAnswer(invocation -> {
            actorUuidsSeen
                    .add(LoggingHelper.hasActorInfo() && LoggingHelper.getActorInfo().uuid() != null
                            ? LoggingHelper.getActorInfo().uuid().toString()
                            : null);
            return null;
        }).when(triggerEvaluator).evaluateTrigger(any(), any(), any(), any(), any(), any(), any());

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(null);
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(firstOwner));
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(secondOwner));

        handler.evaluateTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null);

        assertThat(actorUuidsSeen).containsExactly(firstOwner.toString(), secondOwner.toString());
    }

    /** An association owned by the acting user needs no switch, but its trigger must still be audited as them. */
    @Test
    void actorAttributionIsRestatedWhenTheOwnerIsAlreadyInstalled() throws Exception {
        UUID uploaderUuid = UUID.randomUUID();
        authenticateAs(uploaderUuid, UPLOADER);
        List<String> actorUuidsSeen = recordActorUuidsInsideLoop();

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(uploaderUuid);
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(uploaderUuid));

        handler.evaluateTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null);

        assertThat(actorUuidsSeen).containsExactly(uploaderUuid.toString());
    }

    /** An ownerless association clears the principal, so it must clear the previous owner's attribution too. */
    @Test
    void actorAttributionIsClearedWhenAnOwnerlessAssociationFollowsAnOwnedOne() throws Exception {
        UUID ownerUuid = UUID.randomUUID();
        authenticateAs(UUID.randomUUID(), UPLOADER);
        impersonateOnAuthenticateAsUser(ownerUuid);
        List<String> actorUuidsSeen = recordActorUuidsInsideLoop();

        TestEventHandler handler = handler();
        EventContext<Certificate> context = contextFor(null);
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(ownerUuid));
        context.getPlatformTriggers().getTriggers().add(associationCreatedBy(null));

        handler.evaluateTriggers(context, context.getPlatformTriggers(), new Certificate(), null, null);

        assertThat(actorUuidsSeen).containsExactly(ownerUuid.toString(), null);
    }

    private List<String> recordActorUuidsInsideLoop() throws Exception {
        List<String> seen = new ArrayList<>();
        doAnswer(invocation -> {
            seen
                    .add(LoggingHelper.hasActorInfo() && LoggingHelper.getActorInfo().uuid() != null
                            ? LoggingHelper.getActorInfo().uuid().toString()
                            : null);
            return null;
        }).when(triggerEvaluator).evaluateTrigger(any(), any(), any(), any(), any(), any(), any());
        return seen;
    }

    private void recordIdentityInsideLoop() throws Exception {
        doAnswer(invocation -> {
            usernameInsideLoop = currentUsername();
            return null;
        }).when(triggerEvaluator).evaluateTrigger(any(), any(), any(), any(), any(), any(), any());
    }

    private void recordActorNameInsideLoop() throws Exception {
        doAnswer(invocation -> {
            actorNameInsideLoop = LoggingHelper.hasActorInfo() ? LoggingHelper.getActorInfo().name() : null;
            return null;
        }).when(triggerEvaluator).evaluateTrigger(any(), any(), any(), any(), any(), any(), any());
    }

    private TestEventHandler handler() {
        TestEventHandler handler = new TestEventHandler(repository, triggerEvaluator);
        handler.setAuthHelper(authHelper);
        return handler;
    }

    private EventContext<Certificate> contextFor(UUID actingUserUuid) {
        EventMessage message = new EventMessage(ResourceEvent.CERTIFICATE_UPLOADED, Resource.CERTIFICATE, null, null,
                null, null, actingUserUuid, null);
        return new EventContext<>(message, triggerEvaluator, new Certificate(), null);
    }

    private TriggerAssociation associationCreatedBy(UUID triggeredBy) {
        Trigger trigger = mock(Trigger.class);
        when(trigger.getName()).thenReturn("SomeTrigger");

        TriggerAssociation association = mock(TriggerAssociation.class);
        when(association.getTriggeredBy()).thenReturn(triggeredBy);
        when(association.getTrigger()).thenReturn(trigger);
        return association;
    }

    /** Mirrors production {@code AuthHelper.authenticateAsUser}: installs the principal AND writes the actor MDC. */
    private void impersonateOnAuthenticateAsUser(UUID userUuid) {
        doAnswer(invocation -> {
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, userUuid.toString(), null);
            authenticateAs(userUuid, TRIGGER_CREATOR);
            return null;
        }).when(authHelper).authenticateAsUser(userUuid);
    }

    private void authenticateAs(UUID userUuid, String username) {
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, userUuid.toString(), username,
                List.of());
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
    }

    private String currentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication == null ? null : ((User) authentication.getPrincipal()).getUsername();
    }

    private static class TestEventHandler extends EventHandler<Certificate> {

        TestEventHandler(SecurityFilterRepository<Certificate, UUID> repository,
                TriggerEvaluator<Certificate> triggerEvaluator) {
            super(repository, triggerEvaluator);
        }

        @Override
        protected Object getEventData(Certificate object, Object eventMessageData) {
            return null;
        }

        @Override
        public void handleEvent(EventMessage eventMessage) {
            // not exercised by these tests
        }
    }
}
