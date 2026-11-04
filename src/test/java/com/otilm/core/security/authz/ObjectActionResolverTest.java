package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.secret.SecretDetailDto;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ObjectActionResolverTest {

    private static final UUID SECRET_UUID = UUID.randomUUID();

    @Mock
    AuthorizationEnforcer authorizationEnforcer;

    @Mock
    ContextRefreshListener contextRefreshListener;

    ObjectActionResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new ObjectActionResolver(authorizationEnforcer, contextRefreshListener);
        when(contextRefreshListener.getResources())
                .thenReturn(List
                        .of(syncResource(com.otilm.core.model.auth.Resource.SECRET, "detail", "update", "delete",
                                "getSecretContent", "ANY"),
                                syncResource(com.otilm.core.model.auth.Resource.CERTIFICATE, "revoke")));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void reportsOnlyTheDeclaredActionsTheAuthorizationCheckGrantsOnTheObject() {
        signIn(false);
        when(authorizationEnforcer.isAuthorized(eq(Resource.SECRET), any(), argThat(this::isTheSecret)))
                .thenAnswer(invocation -> invocation.getArgument(1) != ResourceAction.DELETE);

        SecretDetailDto secret = resolver.withAllowedActions(Resource.SECRET, SECRET_UUID, new SecretDetailDto());

        assertThat(secret.getAllowedActions())
                .containsExactly(ResourceAction.DETAIL, ResourceAction.GET_SECRET_CONTENT, ResourceAction.UPDATE);
        verify(authorizationEnforcer)
                .isAuthorized(eq(Resource.SECRET), eq(ResourceAction.DELETE), argThat(this::isTheSecret));
    }

    @Test
    void reportsEveryDeclaredActionWithoutAskingWhenTheUserHoldsAllResources() {
        signIn(true);

        SecretDetailDto secret = resolver
                .withAllowedActions(Resource.SECRET, SECRET_UUID.toString(), new SecretDetailDto());

        assertThat(secret.getAllowedActions())
                .containsExactly(ResourceAction.DELETE, ResourceAction.DETAIL, ResourceAction.GET_SECRET_CONTENT,
                        ResourceAction.UPDATE);
        verifyNoInteractions(authorizationEnforcer);
    }

    @Test
    void reportsNoActionWhenTheAuthorizationCheckDeniesAll() {
        signIn(false);
        when(authorizationEnforcer.isAuthorized(any(), any(), any())).thenReturn(false);

        assertThat(resolver.withAllowedActions(Resource.SECRET, SECRET_UUID, new SecretDetailDto()).getAllowedActions())
                .isEmpty();
    }

    private boolean isTheSecret(SecuredUUID objectUuid) {
        return objectUuid != null && SECRET_UUID.equals(objectUuid.getValue());
    }

    private static ResourceSyncRequestDto syncResource(com.otilm.core.model.auth.Resource resource, String... actions) {
        ResourceSyncRequestDto syncResource = new ResourceSyncRequestDto();
        syncResource.setName(resource);
        syncResource.setActions(List.of(actions));
        return syncResource;
    }

    private static void signIn(boolean allowAllResources) {
        String profile = """
                {
                    "user": {"uuid": "%s", "username": "tester", "enabled": true, "systemUser": false},
                    "roles": [],
                    "permissions": {"allowAllResources": %s, "resources": []}
                }
                """.formatted(UUID.randomUUID(), allowAllResources);
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, UUID.randomUUID().toString(), "tester",
                List.of(), profile);
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
    }
}
