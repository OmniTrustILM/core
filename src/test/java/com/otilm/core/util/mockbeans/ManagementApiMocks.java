package com.otilm.core.util.mockbeans;

import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import static org.mockito.Mockito.mock;

/**
 * Mocks the platform authentication API clients (HTTP boundary to the auth service).
 * <p>
 * {@code AuthenticationCache} must NOT move here. {@code AuthenticationCacheITest} imports this module and autowires
 * the real cache as its subject, so a {@code @Primary} mock would replace what that test verifies; the tests that need
 * it mocked declare a per-class {@code @MockitoBean}.
 */
@TestConfiguration
public class ManagementApiMocks {

    @Bean
    @Primary
    UserManagementApiClient mockUserManagementApiClient() {
        return mock(UserManagementApiClient.class);
    }

    @Bean
    @Primary
    RoleManagementApiClient mockRoleManagementApiClient() {
        return mock(RoleManagementApiClient.class);
    }

    @Bean
    @Primary
    PlatformAuthenticationClient mockPlatformAuthenticationClient() {
        return mock(PlatformAuthenticationClient.class);
    }
}
