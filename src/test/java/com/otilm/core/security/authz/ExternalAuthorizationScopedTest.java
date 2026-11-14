package com.otilm.core.security.authz;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.client.certificate.CertificateSearchRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.config.OpaSecuredAnnotationMetadataExtractor;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.ai.AiReadInvocation;
import com.otilm.core.security.ai.CertificateReadScope;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.AuditLogInternalService;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.impl.CertificateServiceImpl;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ExternalAuthorizationScopedTest {
    private static final UUID ACTOR = UUID.fromString("a1000000-0000-0000-0000-000000000001");
    private static final UUID PROFILE = UUID.fromString("b1000000-0000-0000-0000-000000000001");
    private static final UUID CERTIFICATE = UUID.fromString("c1000000-0000-0000-0000-000000000001");
    private MockWebServer auth;
    private AiReadInvocation invocation;
    private OpaClient opa;
    private OwnerAssociationRepository owners;
    private GroupAssociationRepository groups;
    private ExternalAuthorizationCore core;

    @BeforeEach
    void setup() throws Exception {
        auth = new MockWebServer();
        auth.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse()
                        .setHeader("Content-Type", "application/json")
                        .setBody("{\"authenticated\":true,\"data\":{\"user\":{\"uuid\":\"" + ACTOR
                                + "\",\"username\":\"synthetic-admin\",\"enabled\":true},\"roles\":[{\"name\":\"ROLE_ADMINISTRATOR\"}],\"permissions\":{\"allowAllResources\":true,\"resources\":[]}}}");
            }
        });
        auth.start();
        invocation = new AiReadInvocation(new PlatformAuthenticationClient(mock(AuditLogInternalService.class),
                new ObjectMapper(), mock(AuthenticationCache.class), auth.url("/").toString()));
        opa = mock(OpaClient.class);
        owners = mock(OwnerAssociationRepository.class);
        groups = mock(GroupAssociationRepository.class);
        core = new ExternalAuthorizationCore(opa, new ObjectMapper(), groups, owners);
    }

    @AfterEach
    void cleanup() throws Exception {
        auth.shutdown();
        SecurityContextHolder.clearContext();
        MDC.clear();
    }

    @ParameterizedTest
    @MethodSource("forbiddenActions")
    void readCeilingRejectsAdministratorBeforeOpa(ResourceAction action) throws Exception {
        when(opa.checkResourceAccess(any(), any(), any(), any()))
                .thenReturn(new OpaResourceAccessResult(true, List.of("Admin")));
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            var result = core
                    .decide(SecurityContextHolder.getContext().getAuthentication(), AuthorizationRequest
                            .forDirectCheck(Resource.CERTIFICATE, action, List.of(SecuredUUID.fromUUID(CERTIFICATE))));
            assertThat(result.isGranted()).isFalse();
            return null;
        });
        verifyNoInteractions(opa, owners, groups);
    }

    static Stream<ResourceAction> forbiddenActions() {
        return Arrays
                .stream(ResourceAction.values())
                .filter(action -> action != ResourceAction.LIST && action != ResourceAction.DETAIL);
    }

    @Test
    void otherResourcesAndForeignTrustedUuidsRejectBeforeOpa() throws Exception {
        when(opa.checkResourceAccess(any(), any(), any(), any()))
                .thenReturn(new OpaResourceAccessResult(true, List.of("Admin")));
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            for (AuthorizationRequest request : List
                    .of(AuthorizationRequest.forDirectCheck(Resource.TOKEN, ResourceAction.DETAIL, List.of()),
                            AuthorizationRequest
                                    .forDirectCheck(Resource.CERTIFICATE, ResourceAction.DETAIL,
                                            List.of(SecuredUUID.fromUUID(PROFILE))),
                            AuthorizationRequest
                                    .forDirectCheck(Resource.RA_PROFILE, ResourceAction.MEMBERS,
                                            List.of(SecuredUUID.fromUUID(CERTIFICATE))))) {
                assertThat(core.decide(SecurityContextHolder.getContext().getAuthentication(), request).isGranted())
                        .isFalse();
            }
            return null;
        });
        verifyNoInteractions(opa, owners, groups);
    }

    @Test
    void deniedOrUnavailableVoteNeverInspectsAssociations() throws Exception {
        when(opa.checkResourceAccess(any(), any(), any(), any())).thenReturn(OpaResourceAccessResult.unauthorized());
        when(owners.countOwnedObjects(any(), any(), any())).thenReturn(1L);
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            var request = AuthorizationRequest
                    .forDirectCheck(Resource.CERTIFICATE, ResourceAction.DETAIL,
                            List.of(SecuredUUID.fromUUID(CERTIFICATE)));
            assertThat(core.decide(SecurityContextHolder.getContext().getAuthentication(), request).isGranted())
                    .isFalse();
            when(opa.checkResourceAccess(any(), any(), any(), any()))
                    .thenThrow(new IllegalStateException("synthetic private authority detail"));
            assertThat(core.decide(SecurityContextHolder.getContext().getAuthentication(), request).isGranted())
                    .isFalse();
            return null;
        });
        verifyNoInteractions(owners, groups);
    }

    @ParameterizedTest
    @MethodSource("forbiddenMethods")
    void exactMethodCeilingPrecedesMetadataAndArgumentResolution(Method method) throws Exception {
        var metadata = mock(OpaSecuredAnnotationMetadataExtractor.class);
        var manager = new ExternalMethodAuthorizationManager(metadata, core);
        MethodInvocation call = mock(MethodInvocation.class);
        when(call.getMethod()).thenReturn(method);
        Object target = mock(CertificateServiceImpl.class);
        when(call.getThis()).thenReturn(target);
        when(call.getArguments()).thenReturn(new Object[]{});
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            assertThat(
                    manager.authorize(() -> SecurityContextHolder.getContext().getAuthentication(), call).isGranted())
                    .isFalse();
            return null;
        });
        verifyNoInteractions(metadata, opa, owners, groups);
    }

    static Stream<Method> forbiddenMethods() {
        return Arrays
                .stream(CertificateServiceImpl.class.getMethods())
                .filter(method -> Set
                        .of("getCertificateValidationResult", "downloadCertificate", "downloadCertificateChain",
                                "updateCertificateObjects", "deleteCertificate")
                        .contains(method.getName()));
    }

    @Test
    void exactListSignatureWorksForInterfaceAndImplementationProxyForms() throws Exception {
        when(opa.checkResourceAccess(any(), any(), any(), any()))
                .thenReturn(new OpaResourceAccessResult(true, List.of("Explicit")));
        var manager = new ExternalMethodAuthorizationManager(new OpaSecuredAnnotationMetadataExtractor(), core);
        Object target = mock(CertificateServiceImpl.class);
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            for (Class<?> form : List.of(CertificateExternalService.class, CertificateServiceImpl.class)) {
                MethodInvocation call = mock(MethodInvocation.class);
                when(call.getThis()).thenReturn(target);
                when(call.getMethod())
                        .thenReturn(form
                                .getMethod("listCertificates", SecurityFilter.class,
                                        CertificateSearchRequestDto.class));
                when(call.getArguments())
                        .thenReturn(new Object[]{SecurityFilter.create(), new CertificateSearchRequestDto()});
                assertThat(manager
                        .authorize(() -> SecurityContextHolder.getContext().getAuthentication(), call)
                        .isGranted()).isTrue();
            }
            return null;
        });
        verifyNoInteractions(owners, groups);
    }

    @Test
    void claimedContextLabelCannotGrantAnotherMethodOrResource() throws Exception {
        when(opa.checkResourceAccess(any(), any(), any(), any()))
                .thenReturn(new OpaResourceAccessResult(true, List.of("Admin")));
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            var request = new AuthorizationRequest(Map
                    .of("name", Resource.CERTIFICATE.getCode(), "action", ResourceAction.REVOKE.getCode(), "parentName",
                            Resource.NONE.getCode(), "parentAction", ResourceAction.NONE.getCode()),
                    List.of(), List.of(), true, Optional.empty(), "listCertificates");
            assertThat(core.decide(SecurityContextHolder.getContext().getAuthentication(), request).isGranted())
                    .isFalse();
            return null;
        });
        verifyNoInteractions(opa, owners, groups);
    }

    @Test
    void certificateMethodOnAnUnrelatedTargetCannotGrantMethodAccess() throws Exception {
        var metadata = mock(OpaSecuredAnnotationMetadataExtractor.class);
        var manager = new ExternalMethodAuthorizationManager(metadata, core);
        MethodInvocation call = mock(MethodInvocation.class);
        when(call.getThis()).thenReturn(new Object());
        when(call.getMethod())
                .thenReturn(CertificateExternalService.class
                        .getMethod("listCertificates", SecurityFilter.class, CertificateSearchRequestDto.class));
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            assertThat(
                    manager.authorize(() -> SecurityContextHolder.getContext().getAuthentication(), call).isGranted())
                    .isFalse();
            return null;
        });
        verifyNoInteractions(metadata, opa, owners, groups);
    }

    @Test
    void parentScopeAndResourceShapeAreCheckedBeforeAnyVote() throws Exception {
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            for (AuthorizationRequest request : List
                    .of(AuthorizationRequest.forDirectCheck(Resource.CERTIFICATE, ResourceAction.DETAIL, List.of()),
                            AuthorizationRequest
                                    .forDirectCheck(Resource.CERTIFICATE, ResourceAction.DETAIL,
                                            List.of(SecuredUUID.fromUUID(null))),
                            new AuthorizationRequest(Map
                                    .of("name", Resource.CERTIFICATE.getCode(), "action", ResourceAction.LIST.getCode(),
                                            "parentName", Resource.TOKEN.getCode(), "parentAction",
                                            ResourceAction.MEMBERS.getCode()),
                                    List.of(), List.of(), true, Optional.empty(), "synthetic"))) {
                assertThat(core.decide(SecurityContextHolder.getContext().getAuthentication(), request).isGranted())
                        .isFalse();
            }
            return null;
        });
        verifyNoInteractions(opa, owners, groups);
    }

    @Test
    void requiredParentVoteIsPinnedAndPrecedesCertificateVote() throws Exception {
        when(opa.checkResourceAccess(any(), any(), any(), any()))
                .thenReturn(new OpaResourceAccessResult(true, List.of("Explicit")));
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            var request = new AuthorizationRequest(Map
                    .of("name", Resource.CERTIFICATE.getCode(), "action", ResourceAction.DETAIL.getCode(), "parentName",
                            Resource.RA_PROFILE.getCode(), "parentAction", ResourceAction.MEMBERS.getCode()),
                    List.of(SecuredUUID.fromUUID(CERTIFICATE)), List.of(), false, Optional.empty(), "synthetic");
            assertThat(core.decide(SecurityContextHolder.getContext().getAuthentication(), request).isGranted())
                    .isTrue();
            return null;
        });
        var resources = org.mockito.ArgumentCaptor
                .forClass(com.otilm.core.security.authz.opa.dto.OpaRequestedResource.class);
        verify(opa, times(2)).checkResourceAccess(any(), resources.capture(), any(), any());
        assertThat(resources.getAllValues().get(0).getProperties())
                .containsEntry("name", Resource.RA_PROFILE.getCode());
        assertThat(resources.getAllValues().get(0).getObjectUUIDs()).containsExactly(PROFILE.toString());
        assertThat(resources.getAllValues().get(1).getProperties())
                .containsEntry("name", Resource.CERTIFICATE.getCode());
        assertThat(resources.getAllValues().get(1).getObjectUUIDs()).containsExactly(CERTIFICATE.toString());
        verifyNoInteractions(owners, groups);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void nullOrDisappearingMethodTargetIsControlledDenial(boolean disappears) throws Exception {
        var metadata = mock(OpaSecuredAnnotationMetadataExtractor.class);
        var manager = new ExternalMethodAuthorizationManager(metadata, core);
        MethodInvocation call = mock(MethodInvocation.class);
        Object target = mock(CertificateServiceImpl.class);
        when(call.getMethod())
                .thenReturn(CertificateExternalService.class
                        .getMethod("listCertificates", SecurityFilter.class, CertificateSearchRequestDto.class));
        if (disappears) {
            when(call.getThis()).thenReturn(target, null);
        }
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            var actor = SecurityContextHolder.getContext().getAuthentication();
            java.util.function.Supplier<org.springframework.security.core.Authentication> authentication = () -> actor;
            var decision = assertDoesNotThrow(() -> manager.authorize(authentication, call));
            assertThat(decision.isGranted()).isFalse();
            return null;
        });
        verifyNoInteractions(metadata, opa, owners, groups);
    }

    @Test
    void nullPlatformPrincipalNeverReachesOpaOrAssociations() throws Exception {
        invocation.call(ACTOR, scope(), Duration.ofSeconds(2), () -> {
            var current = (com.otilm.core.security.authn.PlatformAuthenticationToken) SecurityContextHolder
                    .getContext()
                    .getAuthentication();
            var malformed = new com.otilm.core.security.authn.PlatformAuthenticationToken(current.getPrincipal()) {
                @Override
                public com.otilm.core.security.authn.PlatformUserDetails getPrincipal() {
                    return null;
                }
            };
            var request = AuthorizationRequest
                    .forDirectCheck(Resource.CERTIFICATE, ResourceAction.DETAIL,
                            List.of(SecuredUUID.fromUUID(CERTIFICATE)));
            assertThat(core.decide(malformed, request).isGranted()).isFalse();
            return null;
        });
        verifyNoInteractions(opa, owners, groups);
    }

    private static CertificateReadScope scope() {
        return new CertificateReadScope(PROFILE, Set.of(CERTIFICATE));
    }
}
