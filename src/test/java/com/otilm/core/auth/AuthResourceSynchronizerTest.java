package com.otilm.core.auth;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.model.core.auth.ResourcePermissionsDto;
import com.otilm.api.model.core.auth.RoleDetailDto;
import com.otilm.api.model.core.auth.RoleDto;
import com.otilm.api.model.core.auth.RolePermissionsRequestDto;
import com.otilm.api.model.core.auth.RoleRequestDto;
import com.otilm.api.model.core.auth.RoleWithPaginationDto;
import com.otilm.api.model.core.auth.SubjectPermissionsDto;
import com.otilm.core.model.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.security.authn.client.ResourceApiClient;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.exception.AuthenticationServiceException;
import com.otilm.core.util.AuthHelper;
import java.net.ConnectException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Covers the startup step that brings the auditor role in line with the resource catalogue the same boot has just
 * synced, creating it when it is missing. The mapping itself is pinned by {@link ReadOnlyRolePermissionsTest}; what
 * matters here is which role is acted on, that it is written only when it is out of step, and that nothing here can
 * stop the platform from starting.
 */
class AuthResourceSynchronizerTest {

    private static final String AUDITOR_ROLE_UUID = UUID.randomUUID().toString();

    private ContextRefreshListener contextRefreshListener;
    private ResourceApiClient resourceApiClient;
    private RoleManagementApiClient roleManagementApiClient;
    private AuthResourceSynchronizer synchronizer;

    @BeforeEach
    void setUp() {
        contextRefreshListener = mock(ContextRefreshListener.class);
        resourceApiClient = mock(ResourceApiClient.class);
        roleManagementApiClient = mock(RoleManagementApiClient.class);

        synchronizer = new AuthResourceSynchronizer();
        synchronizer.setEndpointsListener(contextRefreshListener);
        synchronizer.setEndPointApiClient(resourceApiClient);
        synchronizer.setRoleManagementApiClient(roleManagementApiClient);

        when(contextRefreshListener.getResources())
                .thenReturn(List
                        .of(resource(Resource.CERTIFICATE, ResourceAction.LIST, ResourceAction.DETAIL,
                                ResourceAction.REVOKE), resource(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT)));
    }

    /** The logger is a process-wide singleton, so a capturing appender left on it would follow the next test. */
    @AfterEach
    void releaseTheSynchronizerLogger() {
        Logger logger = (Logger) LoggerFactory.getLogger(AuthResourceSynchronizer.class);
        logger.detachAndStopAllAppenders();
        logger.setLevel(null);
    }

    @Test
    void rebuildsTheAuditorPermissionsFromTheCatalogueItJustSynced() {
        auditorRoleExists(true);
        when(roleManagementApiClient.getPermissions(AUDITOR_ROLE_UUID)).thenReturn(storedPermissions());

        synchronizer.register();

        ArgumentCaptor<RolePermissionsRequestDto> saved = ArgumentCaptor.forClass(RolePermissionsRequestDto.class);
        verify(roleManagementApiClient).savePermissions(eq(AUDITOR_ROLE_UUID), saved.capture());
        assertThat(saved.getValue().getAllowAllResources()).isFalse();
        assertThat(saved.getValue().getResources()).singleElement().satisfies(certificates -> {
            assertThat(certificates.getName()).isEqualTo(Resource.CERTIFICATE.getCode());
            assertThat(certificates.getActions())
                    .containsExactly(ResourceAction.DETAIL.getCode(), ResourceAction.LIST.getCode());
        });
    }

    /**
     * Nothing else creates the role now that no migration does, so a deployment that has never had it must end this
     * startup holding it - as a system role, with exactly the derived read set and no paired system user.
     */
    @Test
    void createsTheAuditorRoleWhenItIsAbsent() {
        noRoleNamedAuditorExists();
        when(roleManagementApiClient.createRole(any())).thenReturn(createdRole());

        synchronizer.register();

        ArgumentCaptor<RoleRequestDto> created = ArgumentCaptor.forClass(RoleRequestDto.class);
        verify(roleManagementApiClient).createRole(created.capture());
        assertThat(created.getValue().getName()).isEqualTo(AuthHelper.AUDITOR_ROLE_NAME);
        assertThat(created.getValue().getSystemRole()).isTrue();
        assertThat(created.getValue().getDescription()).isNotBlank();
        assertThat(created.getValue().getPermissions()).satisfies(permissions -> {
            assertThat(permissions.getAllowAllResources()).isFalse();
            assertThat(permissions.getResources()).singleElement().satisfies(certificates -> {
                assertThat(certificates.getName()).isEqualTo(Resource.CERTIFICATE.getCode());
                assertThat(certificates.getActions())
                        .containsExactly(ResourceAction.DETAIL.getCode(), ResourceAction.LIST.getCode());
            });
        });
    }

    @Test
    void logsThatItCreatedTheRoleRatherThanRebuiltIt() {
        noRoleNamedAuditorExists();
        when(roleManagementApiClient.createRole(any())).thenReturn(createdRole());

        ListAppender<ILoggingEvent> logged = captureLogsOfSynchronizer();
        synchronizer.register();

        assertThat(messagesLoggedAt(logged, Level.INFO))
                .anySatisfy(message -> assertThat(message).contains(AuthHelper.AUDITOR_ROLE_NAME).contains("created"))
                .noneSatisfy(message -> assertThat(message).contains("rebuilt"));
    }

    /**
     * A role of that name the deployment defined itself is not this one: rewriting it would strip or widen grants
     * someone there relies on, and creating a second one of the same name is what the auth service forbids anyway.
     */
    @Test
    void leavesARoleNamedAuditorAloneWhenItIsNotASystemRole() {
        auditorRoleExists(false);

        ListAppender<ILoggingEvent> logged = captureLogsOfSynchronizer();
        synchronizer.register();

        verify(roleManagementApiClient, never()).savePermissions(any(), any());
        verify(roleManagementApiClient, never()).createRole(any());
        assertThat(messagesLoggedAt(logged, Level.WARN))
                .anySatisfy(message -> assertThat(message)
                        .contains(AuthHelper.AUDITOR_ROLE_NAME)
                        .contains("not a system role"));
    }

    /**
     * Replicas start together and each finds the role missing, so several will try to create it. Role names are unique
     * in the auth service, so the losers are refused - and must go on reconciling the role that now exists instead of
     * leaving it unmanaged for this boot.
     */
    @Test
    void reconcilesTheRoleAnotherInstanceCreatedFirst() {
        RoleDto auditor = role(AuthHelper.AUDITOR_ROLE_NAME, true);
        auditor.setUuid(AUDITOR_ROLE_UUID);
        when(roleManagementApiClient.getRoles())
                .thenReturn(roles(role("superadmin", true)), roles(role("superadmin", true), auditor));
        when(roleManagementApiClient.createRole(any()))
                .thenThrow(new AuthenticationServiceException("Role with name auditor already exists"));

        ListAppender<ILoggingEvent> logged = captureLogsOfSynchronizer();
        synchronizer.register();

        verify(roleManagementApiClient).savePermissions(eq(AUDITOR_ROLE_UUID), any());
        assertThat(messagesLoggedAt(logged, Level.ERROR)).isEmpty();
    }

    /** A creation that failed for a reason other than losing that race is a failure, and has to be reported as one. */
    @Test
    void completesStartupWhenTheRoleCannotBeCreated() {
        noRoleNamedAuditorExists();
        when(roleManagementApiClient.createRole(any()))
                .thenThrow(new AuthenticationServiceException("Unknown resource 'certificates'"));

        ListAppender<ILoggingEvent> logged = captureLogsOfSynchronizer();
        assertThatCode(() -> synchronizer.register()).doesNotThrowAnyException();

        verify(roleManagementApiClient, never()).savePermissions(any(), any());
        assertThat(messagesLoggedAt(logged, Level.ERROR))
                .anySatisfy(message -> assertThat(message)
                        .contains(AuthHelper.AUDITOR_ROLE_NAME)
                        .contains("Unable to reconcile"));
    }

    @Test
    void leavesTheRoleAloneWhenItAlreadyHoldsTheDerivedGrants() {
        auditorRoleExists(true);
        when(roleManagementApiClient.getPermissions(AUDITOR_ROLE_UUID))
                .thenReturn(storedPermissions(storedResource(Resource.CERTIFICATE, ResourceAction.LIST.getCode(),
                        ResourceAction.DETAIL.getCode())));

        ListAppender<ILoggingEvent> logged = captureLogsOfSynchronizer();
        synchronizer.register();

        verify(roleManagementApiClient, never()).savePermissions(any(), any());
        assertThat(messagesLoggedAt(logged, Level.DEBUG))
                .anySatisfy(message -> assertThat(message)
                        .contains(AuthHelper.AUDITOR_ROLE_NAME)
                        .contains("already holds"));
    }

    /**
     * The catalogue the role is derived from is the one the auth service just accepted. If that sync did not happen,
     * the auth service does not know the resources and actions yet and would reject the permission save outright.
     */
    @Test
    void doesNotReconcileWhenTheResourceSyncFailed() {
        when(resourceApiClient.syncResources(any())).thenThrow(unreachableAuthService());

        assertThatCode(() -> synchronizer.register()).doesNotThrowAnyException();

        verifyNoInteractions(roleManagementApiClient);
    }

    /**
     * A reachable auth service that rejects the sync fails with something other than a connection error, so narrowing
     * this to {@code WebClientRequestException} would make an unexpected response abort startup.
     */
    @Test
    void completesStartupWhenTheResourceSyncIsRejectedRatherThanUnreachable() {
        when(resourceApiClient.syncResources(any()))
                .thenThrow(new AuthenticationServiceException("Request was not matched"));

        assertThatCode(() -> synchronizer.register()).doesNotThrowAnyException();

        verifyNoInteractions(roleManagementApiClient);
    }

    @Test
    void completesStartupWhenTheAuthServiceRejectsThePermissionSave() {
        auditorRoleExists(true);
        when(roleManagementApiClient.getPermissions(AUDITOR_ROLE_UUID)).thenReturn(storedPermissions());
        when(roleManagementApiClient.savePermissions(any(), any()))
                .thenThrow(new AuthenticationServiceException("Unknown action 'ANY'"));

        assertThatCode(() -> synchronizer.register()).doesNotThrowAnyException();
    }

    @Test
    void completesStartupWhenTheRoleLookupFails() {
        when(roleManagementApiClient.getRoles()).thenThrow(unreachableAuthService());

        assertThatCode(() -> synchronizer.register()).doesNotThrowAnyException();

        verify(roleManagementApiClient, never()).savePermissions(any(), any());
    }

    /**
     * The derived set is large and reprinting it on every boot buries the one thing worth noticing - that it moved.
     * Counts say that; the payload does not.
     */
    @Test
    void logsACountSummaryOfTheChangeRatherThanThePayload() {
        auditorRoleExists(true);
        when(roleManagementApiClient.getPermissions(AUDITOR_ROLE_UUID)).thenReturn(storedPermissions());

        ListAppender<ILoggingEvent> logged = captureLogsOfSynchronizer();
        synchronizer.register();

        assertThat(logged.list)
                .filteredOn(event -> event.getLevel() == Level.INFO)
                .extracting(ILoggingEvent::getFormattedMessage)
                .anySatisfy(message -> assertThat(message)
                        .contains(AuthHelper.AUDITOR_ROLE_NAME)
                        .contains("1 resources")
                        .contains("2 actions")
                        .doesNotContain(ResourceAction.DETAIL.getCode()));
    }

    private ListAppender<ILoggingEvent> captureLogsOfSynchronizer() {
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        Logger logger = (Logger) LoggerFactory.getLogger(AuthResourceSynchronizer.class);
        // The "nothing to do" verdict is a debug line, and the surrounding configuration need not be emitting those.
        logger.setLevel(Level.DEBUG);
        logger.addAppender(appender);
        return appender;
    }

    private static List<String> messagesLoggedAt(ListAppender<ILoggingEvent> logged, Level level) {
        return logged.list
                .stream()
                .filter(event -> event.getLevel() == level)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    private void auditorRoleExists(boolean systemRole) {
        RoleDto auditor = role(AuthHelper.AUDITOR_ROLE_NAME, systemRole);
        auditor.setUuid(AUDITOR_ROLE_UUID);
        when(roleManagementApiClient.getRoles()).thenReturn(roles(role("superadmin", true), auditor));
    }

    private void noRoleNamedAuditorExists() {
        when(roleManagementApiClient.getRoles()).thenReturn(roles(role("superadmin", true)));
    }

    private static RoleDetailDto createdRole() {
        RoleDetailDto dto = new RoleDetailDto();
        dto.setUuid(AUDITOR_ROLE_UUID);
        dto.setName(AuthHelper.AUDITOR_ROLE_NAME);
        dto.setSystemRole(true);
        return dto;
    }

    private static WebClientRequestException unreachableAuthService() {
        return new WebClientRequestException(new ConnectException("Connection refused"), HttpMethod.POST,
                URI.create("http://localhost:8080/auth/resources/sync"), new HttpHeaders());
    }

    private static RoleWithPaginationDto roles(RoleDto... roles) {
        RoleWithPaginationDto dto = new RoleWithPaginationDto();
        dto.setData(List.of(roles));
        return dto;
    }

    private static RoleDto role(String name, boolean systemRole) {
        RoleDto dto = new RoleDto();
        dto.setUuid(UUID.randomUUID().toString());
        dto.setName(name);
        dto.setSystemRole(systemRole);
        return dto;
    }

    private static SubjectPermissionsDto storedPermissions(ResourcePermissionsDto... resources) {
        SubjectPermissionsDto dto = new SubjectPermissionsDto();
        dto.setAllowAllResources(false);
        dto.setResources(List.of(resources));
        return dto;
    }

    private static ResourcePermissionsDto storedResource(Resource resource, String... actions) {
        ResourcePermissionsDto dto = new ResourcePermissionsDto();
        dto.setName(resource.getCode());
        dto.setAllowAllActions(false);
        dto.setActions(List.of(actions));
        dto.setObjects(List.of());
        return dto;
    }

    private static ResourceSyncRequestDto resource(Resource resource, ResourceAction... actions) {
        ResourceSyncRequestDto dto = new ResourceSyncRequestDto();
        dto.setName(resource);
        dto.setActions(Arrays.stream(actions).map(ResourceAction::getCode).toList());
        return dto;
    }
}
