package com.otilm.core.util.ai;

import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import static org.mockito.Mockito.mock;

/** Unrelated Auth management boundaries; authentication and authorization remain real. */
@TestConfiguration
public class AuthoritativePolicyProofConfiguration {
    @Bean
    @Primary
    com.otilm.core.client.ConnectorApiFactory proofConnectorCalls() {
        return mock(com.otilm.core.client.ConnectorApiFactory.class);
    }

    @Bean
    @Primary
    UserManagementApiClient proofUserManagement() {
        return mock(UserManagementApiClient.class);
    }

    @Bean
    @Primary
    RoleManagementApiClient proofRoleManagement() {
        return mock(RoleManagementApiClient.class);
    }
}
