package com.otilm.core.integration.security.authz;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.service.LocationExternalService;
import com.otilm.core.service.SigningRecordExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Regression suite for the static {@link com.otilm.core.security.authz.ExternalAuthorization} annotation exercised
 * through the real Spring AOP stack, pinning the resource, action, object UUIDs and parent-before-child ordering of
 * what reaches OPA.
 *
 * <p>
 * Both target resources are declared without owner or group associations, so a denied OPA decision is not rescued by
 * the fallback in {@code ExternalAuthorizationCore.checkGroupOwnerAssociations}.
 */
class ExternalAuthorizationStaticITest extends BaseSpringBootTest {

    @Autowired
    private SigningRecordExternalService signingRecordService;

    @Autowired
    private LocationExternalService locationService;

    @Test
    void permitsWhenOpaAuthorizesAnnotatedResourceAndAction() {
        assertThat(signingRecordService.getSearchableFieldInformation())
                .as("an authorized call runs to completion through the advisor")
                .isNotNull();
        assertThat(captureOpaRequests()).isNotEmpty();
    }

    @Test
    void deniesWhenOpaRejectsAnnotatedResourceAndAction() {
        denyResourceAccess(Resource.SIGNING_RECORD, ResourceAction.LIST);

        assertThatThrownBy(() -> signingRecordService.getSearchableFieldInformation())
                .isInstanceOf(AuthorizationDeniedException.class);

        assertThat(captureOpaRequests()).anySatisfy(request -> {
            assertThat(request.getProperties()).containsEntry("name", Resource.SIGNING_RECORD.getCode());
            assertThat(request.getProperties()).containsEntry("action", ResourceAction.LIST.getCode());
        });
    }

    @Test
    void deniesWhenAuthenticationIsNotAPlatformToken() {
        SecurityContextHolder
                .getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken("someone", "secret", List.of()));

        assertThatThrownBy(() -> signingRecordService.getSearchableFieldInformation())
                .isInstanceOf(AuthorizationDeniedException.class);
        verify(opaClient, never()).checkResourceAccess(any(), any(), any(), any());
    }

    @Test
    void deniesWhenThereIsNoAuthentication() {
        SecurityContextHolder.clearContext();

        assertThatThrownBy(() -> signingRecordService.getSearchableFieldInformation())
                .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        verify(opaClient, never()).checkResourceAccess(any(), any(), any(), any());
    }

    @Test
    void sendsAnnotatedResourceAndActionToOpa() {
        signingRecordService.getSearchableFieldInformation();

        assertThat(captureOpaRequests())
                .as("the resource and action named on the annotation are what OPA is asked about")
                .anySatisfy(request -> {
                    assertThat(request.getProperties()).containsEntry("name", Resource.SIGNING_RECORD.getCode());
                    assertThat(request.getProperties()).containsEntry("action", ResourceAction.LIST.getCode());
                });
    }

    @Test
    void checksParentBeforeChild() {
        SecuredParentUUID entity = SecuredParentUUID.fromUUID(UUID.randomUUID());
        SecuredUUID location = SecuredUUID.fromUUID(UUID.randomUUID());

        assertThatThrownBy(() -> locationService.getLocation(entity, location))
                .as("authorization passes, so the method body runs and fails to find the location")
                .isInstanceOf(NotFoundException.class);

        List<OpaRequestedResource> requests = captureOpaRequests();
        assertThat(requests).hasSize(2);
        assertThat(requests.get(0).getProperties())
                .containsEntry("name", Resource.ENTITY.getCode())
                .containsEntry("action", ResourceAction.DETAIL.getCode());
        assertThat(requests.get(1).getProperties())
                .containsEntry("name", Resource.LOCATION.getCode())
                .containsEntry("action", ResourceAction.DETAIL.getCode());
    }

    @Test
    void sendsEachCheckItsOwnObjectUuid() {
        UUID entityUuid = UUID.randomUUID();
        UUID locationUuid = UUID.randomUUID();
        SecuredParentUUID entity = SecuredParentUUID.fromUUID(entityUuid);
        SecuredUUID location = SecuredUUID.fromUUID(locationUuid);

        assertThatThrownBy(() -> locationService.getLocation(entity, location)).isInstanceOf(NotFoundException.class);

        List<OpaRequestedResource> requests = captureOpaRequests();
        assertThat(requests).hasSize(2);
        assertThat(requests.get(0).getObjectUUIDs()).containsExactly(entityUuid.toString());
        assertThat(requests.get(1).getObjectUUIDs()).containsExactly(locationUuid.toString());
    }

    @Test
    void omitsInternalRoutingHintsFromTheOpaRequest() {
        SecuredParentUUID entity = SecuredParentUUID.fromUUID(UUID.randomUUID());
        SecuredUUID location = SecuredUUID.fromUUID(UUID.randomUUID());

        assertThatThrownBy(() -> locationService.getLocation(entity, location)).isInstanceOf(NotFoundException.class);

        assertThat(captureOpaRequests())
                .isNotEmpty()
                .allSatisfy(request -> assertThat(request.getProperties())
                        .doesNotContainKeys("parentName", "parentAction"));
    }

    @Test
    void skipsChildCheckWhenParentIsDenied() {
        denyResourceAccess(Resource.ENTITY, ResourceAction.DETAIL);
        SecuredParentUUID entity = SecuredParentUUID.fromUUID(UUID.randomUUID());
        SecuredUUID location = SecuredUUID.fromUUID(UUID.randomUUID());

        assertThatThrownBy(() -> locationService.getLocation(entity, location))
                .isInstanceOf(AuthorizationDeniedException.class);

        assertThat(captureOpaRequests())
                .as("only the parent resource is submitted to OPA")
                .allSatisfy(request -> assertThat(request.getProperties())
                        .containsEntry("name", Resource.ENTITY.getCode()));
    }
}
