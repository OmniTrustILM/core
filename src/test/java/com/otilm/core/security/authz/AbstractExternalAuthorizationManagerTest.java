package com.otilm.core.security.authz;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import lombok.Setter;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class AbstractExternalAuthorizationManagerTest {

    TestImplementationOfManager manager = new TestImplementationOfManager();

    Authentication authentication = createPlatformAuthentication();

    @Test
    void abstainsIfAuthenticationIsNotOfTypePlatformAuthenticationToken() {
        // given
        Authentication auth = new UsernamePasswordAuthenticationToken(null, null);

        // when
        AuthorizationDecision result = manager.check(() -> auth, new Object());

        // then
        assertFalse(result.isGranted());
    }

    @Test
    void abstainsIfCantDecideForGivenObject() {
        // given
        manager.setCanDecideForGivenObject(false);

        // when
        AuthorizationDecision result = manager.check(() -> authentication, new Object());

        // then
        assertFalse(result.isGranted());
    }

    @Test
    void returnsDecisionFromSubclass() {
        // given
        manager.setCheckResult(new AuthorizationDecision(false));

        // when
        AuthorizationDecision result = manager.check(() -> authentication, new Object());

        // then
        assertFalse(result.isGranted());
    }

    @Test
    void returnsDecisionFromSubclassWhenAnonymousAuthIsUsed() {
        // given
        manager.setAnonymousCheckResult(new AuthorizationDecision(false));

        // when
        AuthorizationDecision result = manager.check(this::getAnonymousToken, new Object());

        // then
        assertFalse(result.isGranted());
    }

    Authentication createPlatformAuthentication() {
        return new PlatformAuthenticationToken(
                new PlatformUserDetails(
                        new AuthenticationInfo(AuthMethod.USER_PROXY, null, "FrantisekJednicka", List.of())
                )
        );
    }

    AnonymousAuthenticationToken getAnonymousToken() {
        return new AnonymousAuthenticationToken(
                UUID.randomUUID().toString(),
                new Object(),
                List.of(new SimpleGrantedAuthority("ANONYMOUS"))
        );
    }

    @Setter
    static class TestImplementationOfManager extends AbstractExternalAuthorizationManager<Object> {

        private AuthorizationDecision checkResult = new AuthorizationDecision(true);
        private AuthorizationDecision anonymousCheckResult = new AuthorizationDecision(true);
        private boolean canDecideForGivenObject = true;

        @Override
        protected AuthorizationDecision checkInternal(PlatformAuthenticationToken authentication, Object object) {
            return checkResult;
        }

        @Override
        protected AuthorizationDecision checkInternal(AnonymousAuthenticationToken authenticationToken, Object object) {
            return anonymousCheckResult;
        }

        @Override
        protected boolean canDecide(Authentication auth, Object object) {
            return canDecideForGivenObject;
        }

    }
}
