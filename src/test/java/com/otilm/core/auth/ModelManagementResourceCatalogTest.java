package com.otilm.core.auth;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
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

/** Actual Core startup catalogue scan; no Auth grant or maintained server acceptance is inferred. */
class ModelManagementResourceCatalogTest {
    @Test
    void separateConnectAndUseCatalogueDoesNotGrantEitherToReadOnlyRole() {
        try (var context = new GenericApplicationContext()) {
            context.registerBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
            context
                    .registerBean("modelUse", AiModelUseAuthorization.class,
                            () -> new AiModelUseAuthorization(mock(PlatformAuthenticationClient.class),
                                    mock(AuthorizationEnforcer.class)));
            context
                    .registerBean("modelManagement", AiModelManagementAuthorization.class,
                            () -> new AiModelManagementAuthorization(mock(PlatformAuthenticationClient.class),
                                    mock(AuthorizationEnforcer.class)));
            context.refresh();
            var listener = new ContextRefreshListener();
            var event = new ContextRefreshedEvent(context);
            assertThatCode(() -> listener.handleContextRefresh(event)).doesNotThrowAnyException();
            assertThat(listener.getResources())
                    .filteredOn(r -> r.getName().getCode().equals(Resource.AI_MODEL.getCode()))
                    .singleElement()
                    .satisfies(r -> assertThat(r.getActions())
                            .containsExactlyInAnyOrder(ResourceAction.USE.getCode(), ResourceAction.CONNECT.getCode()));
            assertThat(ReadOnlyRolePermissions.deriveFrom(listener.getResources()).getResources()).isEmpty();
        }
    }
}
