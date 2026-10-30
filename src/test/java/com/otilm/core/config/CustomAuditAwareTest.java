package com.otilm.core.config;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.security.authn.PlatformAnonymousToken;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Characterization tests for the resolver behind every {@code @CreatedBy} / {@code @LastModifiedBy} column — it is what
 * decides the author of a certificate and of its event-history rows.
 */
class CustomAuditAwareTest {

    private final CustomAuditAware auditAware = new CustomAuditAware();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void authenticatedUserIsTheAuditor() {
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(new AuthenticationInfo(
                        AuthMethod.USER_PROXY, UUID.randomUUID().toString(), "uploader", List.of()))));

        assertThat(auditAware.getCurrentAuditor()).contains("uploader");
    }

    @Test
    void unauthenticatedThreadIsAttributedToTheSystemUser() {
        assertThat(auditAware.getCurrentAuditor()).contains("system");
    }

    /**
     * The shape the platform's anonymous filter produces — a {@link PlatformUserDetails} with a null userUuid, taking
     * the {@code instanceof User} branch. Also what is installed for a user that no longer resolves.
     */
    @Test
    void platformAnonymousPrincipalIsAttributedToAnonymousUser() {
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAnonymousToken(UUID.randomUUID().toString(),
                        new PlatformUserDetails(AuthenticationInfo.getAnonymousAuthenticationInfo()),
                        AuthenticationInfo.getAnonymousAuthenticationInfo().getAuthorities()));

        assertThat(auditAware.getCurrentAuditor()).contains("anonymousUser");
    }

    /** The string-principal branch supports connector self-registration. */
    @Test
    void stringAnonymousPrincipalIsAttributedToAnonymousUser() {
        SecurityContextHolder
                .getContext()
                .setAuthentication(new AnonymousAuthenticationToken("key", "anonymousUser",
                        List.of(new SimpleGrantedAuthority("ANONYMOUS"))));

        assertThat(auditAware.getCurrentAuditor()).contains("anonymousUser");
    }
}
