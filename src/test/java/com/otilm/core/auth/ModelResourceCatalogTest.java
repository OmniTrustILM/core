package com.otilm.core.auth;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.ai.AiModelUseAuthorization;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import org.junit.jupiter.api.Test;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;

class ModelResourceCatalogTest {
    @Test
    void registersModelUseWithoutRequiringDetailOrGrantingAuditorUse() {
        try (var context = new GenericApplicationContext()) {
            context.registerBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
            context
                    .registerBean("modelOperation", AiModelUseAuthorization.class,
                            () -> new AiModelUseAuthorization(mock(PlatformAuthenticationClient.class),
                                    mock(AuthorizationEnforcer.class)));
            context.refresh();
            var listener = new ContextRefreshListener();

            assertThatCode(() -> listener.handleContextRefresh(new ContextRefreshedEvent(context)))
                    .doesNotThrowAnyException();

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
