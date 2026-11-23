package com.otilm.core.auth;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
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

@ExtendWith(MockitoExtension.class)
class ModelResourceCatalogTest {
    @Mock
    private PlatformAuthenticationClient authenticationClient;

    @Mock
    private AuthorizationEnforcer authorizationEnforcer;

    @Test
    void registersModelUseOnly_whenOnlyUseAuthorizationIsPresent() {
        try (var context = new GenericApplicationContext()) {
            // given
            context.registerBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
            context
                    .registerBean("modelOperation", AiModelUseAuthorization.class,
                            () -> new AiModelUseAuthorization(authenticationClient, authorizationEnforcer));
            context.refresh();
            var listener = new ContextRefreshListener();

            // when
            listener.handleContextRefresh(new ContextRefreshedEvent(context));

            // then
            assertThat(listener.getResources())
                    .filteredOn(resource -> resource.getName().getCode().equals(Resource.AI_MODEL.getCode()))
                    .singleElement()
                    .satisfies(resource -> {
                        assertThat(resource.getName().getCode()).isEqualTo(Resource.AI_MODEL.getCode());
                        assertThat(resource.getActions()).containsExactly(ResourceAction.USE.getCode());
                    });
            assertThat(ReadOnlyRolePermissions.deriveFrom(listener.getResources()).getResources()).isEmpty();
        }
    }
}
