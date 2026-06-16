package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.util.AuthHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;

@ExtendWith(MockitoExtension.class)
class TspSecurityContextWriterTest {

    @Mock
    private AuthHelper authHelper;

    private TspSecurityContextWriter writer;

    @BeforeEach
    void createWriterAndClearContext() {
        writer = new TspSecurityContextWriter(authHelper);
        SecurityContextHolder.clearContext();
        LoggingHelper.clearActorInfo();
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        LoggingHelper.clearActorInfo();
    }

    // ── SetFromAuthInfo ───────────────────────────────────────────────────────

    @Nested
    class SetFromAuthInfo {

        @Test
        void returnsFalseAndLeavesContextEmpty_whenInfoNull() {
            // when / then
            assertThat(writer.setFromAuthInfo(null)).isFalse();
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        void returnsFalseAndLeavesContextEmpty_whenInfoAnonymous() {
            // when / then
            assertThat(writer.setFromAuthInfo(AuthenticationInfo.getAnonymousAuthenticationInfo())).isFalse();
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        void populatesContext_whenInfoValid() {
            // given
            UUID principalUuid = UUID.randomUUID();
            AuthenticationInfo info = new AuthenticationInfo(AuthMethod.CERTIFICATE, principalUuid.toString(), "alice",
                    List.of(new SimpleGrantedAuthority("ROLE_USER")));

            // when / then
            assertThat(writer.setFromAuthInfo(info)).isTrue();
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
            // the TSP audit actor is attributed to the authenticated principal, not a system user
            assertThat(LoggingHelper.hasActorInfo()).isTrue();
            assertThat(LoggingHelper.getActorType()).isEqualTo(ActorType.USER);
            assertThat(LoggingHelper.getActorInfo().uuid()).isEqualTo(principalUuid);
            assertThat(LoggingHelper.getActorInfo().name()).isEqualTo("alice");
        }
    }

    // ── AuthenticateAsUser ────────────────────────────────────────────────────

    @Nested
    class AuthenticateAsUser {

        @Test
        void returnsFalseAndClearsContext_whenProxyFails() {
            // given — authenticateAsUser populates actor MDC before the failing proxy call
            UUID userUuid = UUID.randomUUID();
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, userUuid.toString(), "mapped-user");
            doThrow(new RuntimeException("auth service down")).when(authHelper).authenticateAsUser(userUuid);

            // when / then
            assertThat(writer.authenticateAsUser(userUuid)).isFalse();
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            // actor attribution must be dropped so the failure is not misattributed to the mapped user
            assertThat(LoggingHelper.hasActorInfo()).isFalse();
        }

        @Test
        void returnsTrue_whenProxySucceeds() {
            // given
            UUID userUuid = UUID.randomUUID();

            // when / then
            assertThat(writer.authenticateAsUser(userUuid)).isTrue();
        }
    }
}
