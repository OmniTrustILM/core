package com.czertainly.core.service;

import com.czertainly.api.model.core.logging.enums.AuthMethod;
import com.czertainly.core.security.authn.client.AuthenticationCache;
import com.czertainly.core.security.authn.client.AuthenticationInfo;
import com.czertainly.core.security.authn.client.RoleManagementApiClient;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.util.SessionTableHelper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import static org.mockito.Mockito.*;

/**
 * Integration tests verifying that service mutations correctly invalidate the authentication cache.
 * Each test populates the real Caffeine cache, triggers a service operation, then asserts that
 * the affected entries are evicted and the loader is re-invoked on the next authentication request.
 */
class AuthenticationCacheIntegrationTest extends BaseSpringBootTest {

    @Autowired
    private AuthenticationCache authenticationCache;

    @Autowired
    private UserManagementService userManagementService;

    @Autowired
    private RoleManagementService roleManagementService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    private UserManagementApiClient userManagementApiClient;

    @MockitoBean
    private RoleManagementApiClient roleManagementApiClient;

    @BeforeEach
    void setup() {
        authenticationCache.evictAll();
        SessionTableHelper.createSessionTables(jdbcTemplate);
    }

    // -------------------------------------------------------------------------
    // Per-user eviction — deleteUser as a representative mutation
    // -------------------------------------------------------------------------

    @Nested
    class PerUserEviction {

        @Test
        void evictsUserUuidEntry() {
            // given - UUID cache is warm for a user
            String userUuid = UUID.randomUUID().toString();
            Supplier<AuthenticationInfo> loader = loaderReturning(authenticatedInfo(userUuid, "user"));
            authenticationCache.getOrAuthenticateByUserUuid(UUID.fromString(userUuid), loader);

            // when
            userManagementService.deleteUser(userUuid);

            // then - the next lookup for this user misses the cache and calls the loader again
            authenticationCache.getOrAuthenticateByUserUuid(UUID.fromString(userUuid), loader);
            verify(loader, times(2)).get();
        }

        @Test
        void evictsAllTokensForUser() {
            // given - two tokens issued to the same user are both cached
            String userUuid = UUID.randomUUID().toString();
            Supplier<AuthenticationInfo> loaderA = loaderReturning(authenticatedInfo(userUuid, "user"));
            Supplier<AuthenticationInfo> loaderB = loaderReturning(authenticatedInfo(userUuid, "user"));
            authenticationCache.getOrAuthenticateByToken("jti-A", loaderA);
            authenticationCache.getOrAuthenticateByToken("jti-B", loaderB);

            // when
            userManagementService.deleteUser(userUuid);

            // then - both token entries are evicted via the JTI index
            authenticationCache.getOrAuthenticateByToken("jti-A", loaderA);
            authenticationCache.getOrAuthenticateByToken("jti-B", loaderB);
            verify(loaderA, times(2)).get();
            verify(loaderB, times(2)).get();
        }

        @Test
        void evictsCertificateEntryForUser() {
            // given - certificate cache is warm; the user-certificate index tracks the mapping
            String userUuid = UUID.randomUUID().toString();
            String fingerprint = "fp-" + userUuid;
            Supplier<AuthenticationInfo> loader = loaderReturning(authenticatedInfo(userUuid, "certUser"));
            authenticationCache.getOrAuthenticateByCertificate(fingerprint, loader);

            // when
            userManagementService.deleteUser(userUuid);

            // then - the certificate entry is evicted via the user-certificate index
            authenticationCache.getOrAuthenticateByCertificate(fingerprint, loader);
            verify(loader, times(2)).get();
        }

        @Test
        void doesNotEvictOtherUsersEntries() {
            // given - two users are independently cached
            String evictedUserUuid = UUID.randomUUID().toString();
            String survivingUserUuid = UUID.randomUUID().toString();
            Supplier<AuthenticationInfo> evictedLoader = loaderReturning(authenticatedInfo(evictedUserUuid, "evicted"));
            Supplier<AuthenticationInfo> survivingLoader = loaderReturning(authenticatedInfo(survivingUserUuid, "surviving"));
            authenticationCache.getOrAuthenticateByUserUuid(UUID.fromString(evictedUserUuid), evictedLoader);
            authenticationCache.getOrAuthenticateByUserUuid(UUID.fromString(survivingUserUuid), survivingLoader);

            // when - only one user is deleted
            userManagementService.deleteUser(evictedUserUuid);

            // then - the surviving user's entry is still cached; its loader is not called again
            authenticationCache.getOrAuthenticateByUserUuid(UUID.fromString(survivingUserUuid), survivingLoader);
            verify(survivingLoader, times(1)).get();
        }
    }

    // -------------------------------------------------------------------------
    // Global eviction — deleteRole as a representative mutation
    // -------------------------------------------------------------------------

    @Nested
    class GlobalEviction {

        @Test
        void evictsAllUsersFromAllCaches() {
            // given - cache is warm with entries across all three auth methods
            UUID userUuidA = UUID.randomUUID();
            String userUuidB = UUID.randomUUID().toString();
            String userUuidC = UUID.randomUUID().toString();
            Supplier<AuthenticationInfo> uuidLoader = loaderReturning(authenticatedInfo(userUuidA.toString(), "uuidUser"));
            Supplier<AuthenticationInfo> certLoader = loaderReturning(authenticatedInfo(userUuidB, "certUser"));
            Supplier<AuthenticationInfo> tokenLoader = loaderReturning(authenticatedInfo(userUuidC, "tokenUser"));
            authenticationCache.getOrAuthenticateByUserUuid(userUuidA, uuidLoader);
            authenticationCache.getOrAuthenticateByCertificate("fp-B", certLoader);
            authenticationCache.getOrAuthenticateByToken("jti-C", tokenLoader);

            // when - a role is deleted, which may affect the permissions of any user that held it
            roleManagementService.deleteRole(UUID.randomUUID().toString());

            // then - all entries are gone; every loader is invoked again
            authenticationCache.getOrAuthenticateByUserUuid(userUuidA, uuidLoader);
            authenticationCache.getOrAuthenticateByCertificate("fp-B", certLoader);
            authenticationCache.getOrAuthenticateByToken("jti-C", tokenLoader);
            verify(uuidLoader, times(2)).get();
            verify(certLoader, times(2)).get();
            verify(tokenLoader, times(2)).get();
        }
    }

    // -------------------------------------------------------------------------
    // Certificate fingerprint eviction — selective eviction by fingerprint
    // -------------------------------------------------------------------------

    @Nested
    class CertificateFingerprintEviction {

        @Test
        void evictsOnlyTheTargetedFingerprint() {
            // given - two certificates belonging to different users are both cached
            String userUuidA = UUID.randomUUID().toString();
            String userUuidB = UUID.randomUUID().toString();
            Supplier<AuthenticationInfo> loaderA = loaderReturning(authenticatedInfo(userUuidA, "userA"));
            Supplier<AuthenticationInfo> loaderB = loaderReturning(authenticatedInfo(userUuidB, "userB"));
            authenticationCache.getOrAuthenticateByCertificate("fp-revoked", loaderA);
            authenticationCache.getOrAuthenticateByCertificate("fp-valid", loaderB);

            // when - only the revoked certificate's fingerprint is invalidated
            authenticationCache.evictByCertificateFingerprint("fp-revoked");

            // then - the revoked entry is gone; the other certificate's entry survives
            authenticationCache.getOrAuthenticateByCertificate("fp-revoked", loaderA);
            authenticationCache.getOrAuthenticateByCertificate("fp-valid", loaderB);
            verify(loaderA, times(2)).get();
            verify(loaderB, times(1)).get();
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static AuthenticationInfo authenticatedInfo(String userUuid, String username) {
        return new AuthenticationInfo(AuthMethod.CERTIFICATE, userUuid, username,
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @SuppressWarnings("unchecked")
    private static Supplier<AuthenticationInfo> loaderReturning(AuthenticationInfo info) {
        Supplier<AuthenticationInfo> loader = mock(Supplier.class);
        when(loader.get()).thenReturn(info);
        return loader;
    }

}
