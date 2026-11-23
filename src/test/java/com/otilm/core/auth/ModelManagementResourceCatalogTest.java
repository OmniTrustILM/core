package com.otilm.core.auth;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
import com.otilm.core.security.ai.AiModelUseAuthorization;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import static org.assertj.core.api.Assertions.assertThat;

/** Actual Core startup catalogue scan; no Auth grant or maintained server acceptance is inferred. */
@ExtendWith(MockitoExtension.class)
class ModelManagementResourceCatalogTest {
    @Mock
    private PlatformAuthenticationClient authenticationClient;

    @Mock
    private AuthorizationEnforcer authorizationEnforcer;

    @Test
    void registersUseAndConnectWithoutGrantingReadOnlyRole_whenBothAuthorizationsArePresent() {
        try (var context = new GenericApplicationContext()) {
            // given
            context.registerBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
            context
                    .registerBean("modelUse", AiModelUseAuthorization.class,
                            () -> new AiModelUseAuthorization(authenticationClient, authorizationEnforcer));
            context
                    .registerBean("modelManagement", AiModelManagementAuthorization.class,
                            () -> new AiModelManagementAuthorization(authenticationClient, authorizationEnforcer));
            context.refresh();
            var listener = new ContextRefreshListener();

            // when
            listener.handleContextRefresh(new ContextRefreshedEvent(context));

            // then
            assertThat(listener.getResources())
                    .filteredOn(r -> r.getName().getCode().equals(Resource.AI_MODEL.getCode()))
                    .singleElement()
                    .satisfies(r -> assertThat(r.getActions())
                            .containsExactlyInAnyOrder(ResourceAction.USE.getCode(), ResourceAction.CONNECT.getCode()));
            assertThat(ReadOnlyRolePermissions.deriveFrom(listener.getResources()).getResources()).isEmpty();
        }
    }
}
