package com.otilm.core.util;

import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.records.ActorRecord;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.PlatformAnonymousToken;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

/**
 * Contract of the scoped {@code runAsSystem} elevation: the action runs under a system principal, and the caller's
 * prior context is restored afterwards — on success, on exception, and (critically) leaving NO system principal on a
 * principal-less thread (the async status-poll listener runs pooled with no {@code SecurityContext}). The remote
 * elevation is stubbed so these assertions test only the save/restore discipline, not the auth-service call.
 */
class AuthHelperTest {

    private final AuthHelper authHelper = spy(new AuthHelper());

    @BeforeEach
    void stubElevation() {
        // runAsSystem installs a fresh context before elevating; the stub sets a system principal + actor on it.
        doAnswer(inv -> {
            SecurityContextHolder.getContext().setAuthentication(mock(Authentication.class));
            LoggingHelper.putActorInfoWhenNull(ActorType.CORE, null, inv.getArgument(0));
            return null;
        }).when(authHelper).authenticateAsSystemUser(anyString());
    }

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
        LoggingHelper.clearActorInfo();
    }

    @Test
    void runAsSystem_elevatesDuringActionThenRestoresOriginal() throws Exception {
        Authentication original = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(original);
        Authentication[] during = new Authentication[1];

        String result = authHelper.runAsSystem(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME, () -> {
            during[0] = SecurityContextHolder.getContext().getAuthentication();
            return "ok";
        });

        assertEquals("ok", result);
        assertNotNull(during[0], "a system principal must be installed for the action");
        assertNotSame(original, during[0], "the action must run elevated, not as the caller");
        assertSame(original, SecurityContextHolder.getContext().getAuthentication(),
                "the caller's principal must be restored after");
    }

    @Test
    void runAsSystem_restoresOriginalWhenActionThrows() {
        Authentication original = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(original);

        assertThrows(IllegalStateException.class,
                () -> authHelper.runAsSystem(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME, () -> {
                    throw new IllegalStateException("boom");
                }));

        assertSame(original, SecurityContextHolder.getContext().getAuthentication(),
                "the caller's principal must be restored even when the action throws");
    }

    @Test
    void runAsSystem_restoresCallerActorWhenCallerHadOne() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(mock(Authentication.class));
        String callerUuid = "11111111-1111-1111-1111-111111111111";
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, callerUuid, "operator-jane");

        ActorRecord[] during = new ActorRecord[1];
        authHelper.runAsSystem(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME, () -> {
            during[0] = LoggingHelper.getActorInfo();
            return null;
        });

        assertEquals(ActorType.CORE, during[0].type(),
                "authorization must run under the system actor during the action");
        assertNull(during[0].uuid(), "no caller uuid may linger in the actor MDC during the elevated window");
        ActorRecord after = LoggingHelper.getActorInfo();
        assertEquals(ActorType.USER, after.type(),
                "caller's actor type must be restored, not left as the system identity");
        assertEquals("operator-jane", after.name(), "caller's actor name must be restored");
        assertEquals(callerUuid, after.uuid().toString(), "caller's actor uuid must be restored, not left stale");
    }

    /**
     * An anonymous caller's principal IS a {@link PlatformUserDetails}, with a null userUuid, so
     * {@code getUserIdentification()} succeeds rather than throwing and the uuid must be treated as absent.
     */
    @Test
    void getActingUserUuidOrNull_returnsNullForAnonymousPrincipal() {
        AuthenticationInfo anonymous = AuthenticationInfo.getAnonymousAuthenticationInfo();
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAnonymousToken(UUID.randomUUID().toString(),
                        new PlatformUserDetails(anonymous), anonymous.getAuthorities()));

        assertNull(AuthHelper.getActingUserUuidOrNull());
    }

    @Test
    void getActingUserUuidOrNull_returnsNullWhenNobodyIsAuthenticated() {
        SecurityContextHolder.clearContext();

        assertNull(AuthHelper.getActingUserUuidOrNull());
    }

    @Test
    void getActingUserUuidOrNull_returnsTheAuthenticatedUsersUuid() {
        UUID userUuid = UUID.randomUUID();
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(
                        new AuthenticationInfo(AuthMethod.USER_PROXY, userUuid.toString(), "operator", List.of()))));

        assertEquals(userUuid, AuthHelper.getActingUserUuidOrNull());
    }

    @Test
    void getActingUserOrNull_returnsTheAuthenticatedUsersUuidAndUsername() {
        UUID userUuid = UUID.randomUUID();
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(
                        new AuthenticationInfo(AuthMethod.USER_PROXY, userUuid.toString(), "operator", List.of()))));

        NameAndUuidDto actingUser = AuthHelper.getActingUserOrNull();

        assertNotNull(actingUser);
        assertEquals(userUuid.toString(), actingUser.getUuid());
        assertEquals("operator", actingUser.getName());
    }

    /** "anonymousUser" is a placeholder, not an identity, so it must not be persisted as one. */
    @Test
    void getActingUserOrNull_returnsNullForAnonymousPrincipal() {
        AuthenticationInfo anonymous = AuthenticationInfo.getAnonymousAuthenticationInfo();
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAnonymousToken(UUID.randomUUID().toString(),
                        new PlatformUserDetails(anonymous), anonymous.getAuthorities()));

        assertNull(AuthHelper.getActingUserOrNull());
    }

    @Test
    void getActingUserOrNull_returnsNullWhenNobodyIsAuthenticated() {
        SecurityContextHolder.clearContext();

        assertNull(AuthHelper.getActingUserOrNull());
    }

    @Test
    void runAsSystem_leavesNoPrincipalWhenCallerHadNone() throws Exception {
        SecurityContextHolder.clearContext(); // principal-less caller (async status-poll pooled thread)

        authHelper.runAsSystem(AuthHelper.ATTRIBUTE_CONTENT_RESOLVER_USERNAME, () -> {
            assertNotNull(SecurityContextHolder.getContext().getAuthentication(),
                    "the action must still run elevated when the caller has no principal");
            return null;
        });

        assertNull(SecurityContextHolder.getContext().getAuthentication(),
                "no system principal may leak onto a principal-less (pooled) thread");
        assertFalse(LoggingHelper.hasActorInfo(), "no system actor may leak into MDC");
    }
}
