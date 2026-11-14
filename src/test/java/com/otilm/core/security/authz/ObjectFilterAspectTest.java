package com.otilm.core.security.authz;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.config.OpaSecuredAnnotationMetadataExtractor;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.ai.AiReadInvocation;
import com.otilm.core.security.ai.CertificateReadScope;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.aspectj.lang.ProceedingJoinPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ObjectFilterAspectTest {
    private final UUID actor = UUID.randomUUID();
    private final UUID profile = UUID.randomUUID();
    private final OpaClient opa = mock(OpaClient.class);
    private final PlatformAuthenticationClient auth = mock(PlatformAuthenticationClient.class);
    private final ObjectFilterAspect aspect = new ObjectFilterAspect(opa, new OpaSecuredAnnotationMetadataExtractor());
    private final AiReadInvocation invocation = new AiReadInvocation(auth);

    @BeforeEach
    void setup() {
        var info = new AuthenticationInfo(AuthMethod.USER_PROXY, actor.toString(), "synthetic", List.of(), "{}");
        when(auth.authenticateByUserUuidAuthoritatively(any(), any())).thenReturn(info);
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
        var result = new OpaObjectAccessResult();
        result.setAllowedObjects(List.of(profile.toString()));
        result.setForbiddenObjects(List.of());
        when(opa.checkObjectAccess(any(), any(), any(), any())).thenReturn(result);
    }

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void scopedPopulationSkipsAssociationVoteAndReplacesEveryOldFilter() throws Exception {
        var filter = SecurityFilter.create();
        filter.setGroupMembersFilter(SecurityResourceFilter.create());
        filter.setParentRefProperty("wrong");
        invocation.call(actor, new CertificateReadScope(profile, Set.of()), Duration.ofSeconds(3), () -> {
            populate(filter);
            assertThat(filter.getGroupMembersFilter()).isNull();
            assertThat(filter.getParentRefProperty()).isNull();
            assertThat(filter.getResourceFilter().getResource()).isEqualTo(Resource.CERTIFICATE);
            assertThat(filter.getParentResourceFilter().getResource()).isEqualTo(Resource.RA_PROFILE);
            return true;
        });
        verify(opa, times(2)).checkObjectAccess(any(), any(), any(), any());
    }

    @Test
    void scopedResourceFailureClearsOldAndPartialFilters() throws Exception {
        var result = new OpaObjectAccessResult();
        result.setAllowedObjects(List.of(profile.toString()));
        result.setForbiddenObjects(List.of());
        when(opa.checkObjectAccess(any(), any(), any(), any()))
                .thenReturn(result)
                .thenThrow(new AccessDeniedException("synthetic"));
        var filter = SecurityFilter.create();
        filter.setResourceFilter(SecurityResourceFilter.create());
        filter.setParentResourceFilter(SecurityResourceFilter.create());
        invocation.call(actor, new CertificateReadScope(profile, Set.of()), Duration.ofSeconds(3), () -> {
            assertThatThrownBy(() -> populate(filter)).isInstanceOf(AccessDeniedException.class);
            assertThat(filter.getResourceFilter()).isNull();
            assertThat(filter.getParentResourceFilter()).isNull();
            return true;
        });
    }

    @Test
    void scopedMissingParentMetadataStopsBeforeAnyVote() throws Exception {
        invocation.call(actor, new CertificateReadScope(profile, Set.of()), Duration.ofSeconds(3), () -> {
            var filter = SecurityFilter.create();
            assertThatThrownBy(
                    () -> aspect.populateSecurityFilter(Resource.CERTIFICATE, ResourceAction.LIST, null, null, filter))
                    .isInstanceOf(AccessDeniedException.class);
            return true;
        });
        verifyNoInteractions(opa);
    }

    @Test
    void ordinaryPopulationStillLoadsGroupMembership() {
        var filter = SecurityFilter.create();
        populate(filter);
        assertThat(filter.getGroupMembersFilter()).isNotNull();
        verify(opa, times(3)).checkObjectAccess(any(), any(), any(), any());
    }

    @Test
    void scopedMissingFilterArgumentStopsBeforeProceeding() throws Throwable {
        var point = mock(ProceedingJoinPoint.class);
        when(point.getArgs()).thenReturn(new Object[]{});
        invocation.call(actor, new CertificateReadScope(profile, Set.of()), Duration.ofSeconds(3), () -> {
            assertThatThrownBy(() -> aspect.obtainObjectAccessData(point)).isInstanceOf(AccessDeniedException.class);
            return true;
        });
        verify(point, never()).proceed();
    }

    @Test
    void ordinaryMissingFilterArgumentStillProceeds() throws Throwable {
        var point = mock(ProceedingJoinPoint.class);
        when(point.getArgs()).thenReturn(new Object[]{});
        when(point.proceed()).thenReturn("ordinary");
        assertThat(aspect.obtainObjectAccessData(point)).isEqualTo("ordinary");
    }

    @ParameterizedTest
    @ValueSource(strings = {"resource", "action", "parent", "parentAction"})
    void scopedWrongMetadataStopsBeforeAnyVote(String wrong) throws Exception {
        invocation.call(actor, new CertificateReadScope(profile, Set.of()), Duration.ofSeconds(3), () -> {
            Resource resource = wrong.equals("resource") ? Resource.RA_PROFILE : Resource.CERTIFICATE;
            ResourceAction action = wrong.equals("action") ? ResourceAction.DETAIL : ResourceAction.LIST;
            Resource parent = wrong.equals("parent") ? Resource.CERTIFICATE : Resource.RA_PROFILE;
            ResourceAction parentAction = wrong.equals("parentAction") ? ResourceAction.LIST : ResourceAction.MEMBERS;
            var filter = SecurityFilter.create();
            assertThatThrownBy(() -> aspect.populateSecurityFilter(resource, action, parent, parentAction, filter))
                    .isInstanceOf(AccessDeniedException.class);
            return true;
        });
        verifyNoInteractions(opa);
    }

    private void populate(SecurityFilter filter) {
        aspect
                .populateSecurityFilter(Resource.CERTIFICATE, ResourceAction.LIST, Resource.RA_PROFILE,
                        ResourceAction.MEMBERS, filter);
    }
}
