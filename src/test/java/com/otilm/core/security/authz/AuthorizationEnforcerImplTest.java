package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationEnforcerImplTest {

    @Mock
    ExternalAuthorizationCore core;

    @Mock
    PlatformAuthenticationClient authenticationClient;

    AuthorizationEnforcerImpl enforcer;

    @BeforeEach
    void setUp() {
        enforcer = new AuthorizationEnforcerImpl(core, authenticationClient);
        SecurityContextHolder.getContext().setAuthentication(platformAuth());
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        LoggingHelper.clearActorInfo();
    }

    @Test
    void returnsNormallyWhenCoreGrants() {
        // given
        when(core.decide(any(), any())).thenReturn(new AuthorizationDecision(true));

        // when + then
        assertThatCode(() -> enforcer
                .enforce(Resource.TOKEN_PROFILE, ResourceAction.DETAIL, SecuredUUID.fromUUID(UUID.randomUUID())))
                .doesNotThrowAnyException();
    }

    @Test
    void throwsAccessDeniedWhenCoreDenies() {
        // given
        when(core.decide(any(), any())).thenReturn(new AuthorizationDecision(false));
        SecuredUUID uuid = SecuredUUID.fromUUID(UUID.randomUUID());

        // when + then
        assertThatThrownBy(() -> enforcer.enforce(Resource.TOKEN, ResourceAction.MEMBERS, uuid))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void buildsDirectCheckRequestWithResourceActionAndUuids() {
        // given
        when(core.decide(any(), any())).thenReturn(new AuthorizationDecision(true));
        SecuredUUID uuid = SecuredUUID.fromUUID(UUID.randomUUID());

        // when
        enforcer.enforce(Resource.CERTIFICATE, ResourceAction.DETAIL, uuid);

        // then
        verify(core)
                .decide(any(),
                        argThat(req -> req.properties().get("name").equals(Resource.CERTIFICATE.getCode())
                                && req.properties().get("action").equals(ResourceAction.DETAIL.getCode())
                                && req.properties().get("parentName").equals(Resource.NONE.getCode())
                                && req.properties().get("parentAction").equals(ResourceAction.NONE.getCode())
                                && req.objectUuids().equals(List.of(uuid)) && req.parentUuids().isEmpty()
                                && !req.hasSecurityFilter() && req.parentUuidGetterClass().isEmpty()));
    }

    @Test
    void listOverloadPassesAllUuids() {
        // given
        when(core.decide(any(), any())).thenReturn(new AuthorizationDecision(true));
        SecuredUUID a = SecuredUUID.fromUUID(UUID.randomUUID());
        SecuredUUID b = SecuredUUID.fromUUID(UUID.randomUUID());

        // when
        enforcer.enforce(Resource.SIGNING_PROFILE, ResourceAction.DETAIL, List.of(a, b));

        // then
        verify(core).decide(any(), argThat(req -> req.objectUuids().equals(List.of(a, b))));
    }

    @Test
    void passesCurrentAuthenticationFromSecurityContextToCore() {
        // given
        PlatformAuthenticationToken auth = platformAuth();
        SecurityContextHolder.getContext().setAuthentication(auth);
        when(core.decide(any(), any())).thenReturn(new AuthorizationDecision(true));

        // when
        enforcer.enforce(Resource.VAULT, ResourceAction.DETAIL, SecuredUUID.fromUUID(UUID.randomUUID()));

        // then
        verify(core).decide(eq(auth), any());
    }

    @Test
    void forwardsNullAuthenticationWhenSecurityContextIsEmpty() {
        // given: no authenticated principal (fail-closed relies on the core rejecting null, so the enforcer must
        // hand the null through rather than fabricate an authentication or throw before delegating)
        SecurityContextHolder.clearContext();
        when(core.decide(isNull(), any())).thenReturn(new AuthorizationDecision(false));
        SecuredUUID uuid = SecuredUUID.fromUUID(UUID.randomUUID());

        // when + then: the core's null-authentication denial surfaces as AccessDeniedException
        assertThatThrownBy(() -> enforcer.enforce(Resource.CERTIFICATE, ResourceAction.DETAIL, uuid))
                .isInstanceOf(AccessDeniedException.class);
        verify(core).decide(isNull(), any());
    }

    @Test
    void authorizesAnotherUserAgainstAPrincipalResolvedForThem() {
        UUID otherUser = UUID.randomUUID();
        when(authenticationClient.authenticateByUserUuid(otherUser)).thenReturn(resolvableUser());
        when(core.decide(any(), any())).thenReturn(new AuthorizationDecision(true));

        boolean authorized = enforcer
                .isAuthorizedAs(otherUser, Resource.RA_PROFILE, ResourceAction.DETAIL,
                        SecuredUUID.fromUUID(UUID.randomUUID()));

        assertThat(authorized).isTrue();
        verify(core)
                .decide(argThat(auth -> auth instanceof PlatformAuthenticationToken token
                        && "other-user".equals(token.getPrincipal().getUsername())),
                        argThat(req -> req.properties().get("action").equals(ResourceAction.DETAIL.getCode())));
    }

    @Test
    void deniesAUserTheAuthServiceNoLongerResolves() {
        UUID deletedUser = UUID.randomUUID();
        when(authenticationClient.authenticateByUserUuid(deletedUser))
                .thenReturn(AuthenticationInfo.getAnonymousAuthenticationInfo());

        boolean authorized = enforcer
                .isAuthorizedAs(deletedUser, Resource.RA_PROFILE, ResourceAction.DETAIL,
                        SecuredUUID.fromUUID(UUID.randomUUID()));

        assertThat(authorized).isFalse();
        verifyNoInteractions(core);
    }

    @Test
    void deniesWhenTheUserCannotBeResolvedAtAll() {
        UUID unreachable = UUID.randomUUID();
        when(authenticationClient.authenticateByUserUuid(unreachable))
                .thenThrow(new IllegalStateException("auth service is down"));

        assertThat(enforcer
                .isAuthorizedAs(unreachable, Resource.RA_PROFILE, ResourceAction.DETAIL,
                        SecuredUUID.fromUUID(UUID.randomUUID())))
                .isFalse();
        verifyNoInteractions(core);
    }

    @Test
    void leavesTheCallersActorAttributionUntouched() {
        UUID otherUser = UUID.randomUUID();
        // Resolving somebody replays their actor MDC, which must not become the caller's audited identity
        when(authenticationClient.authenticateByUserUuid(otherUser)).thenAnswer(invocation -> {
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, otherUser.toString(), "other-user");
            return resolvableUser();
        });
        when(core.decide(any(), any())).thenReturn(new AuthorizationDecision(true));
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, UUID.randomUUID().toString(), "caller");

        enforcer
                .isAuthorizedAs(otherUser, Resource.RA_PROFILE, ResourceAction.DETAIL,
                        SecuredUUID.fromUUID(UUID.randomUUID()));

        assertThat(LoggingHelper.getActorInfo().name()).isEqualTo("caller");
    }

    private AuthenticationInfo resolvableUser() {
        return new AuthenticationInfo(AuthMethod.USER_PROXY, UUID.randomUUID().toString(), "other-user", List.of(),
                "{\"user\":{\"username\":\"other-user\"}}");
    }

    private PlatformAuthenticationToken platformAuth() {
        return new PlatformAuthenticationToken(
                new PlatformUserDetails(new AuthenticationInfo(AuthMethod.USER_PROXY, null, "TestUser", List.of())));
    }
}
