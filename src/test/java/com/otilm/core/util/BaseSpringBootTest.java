package com.otilm.core.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.messaging.jms.producers.AuditLogsProducer;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.SettingInternalService;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
@TestPropertySource(properties = {
        WireMockPorts.AUTH_SERVICE_URL_PROPERTY,
        WireMockPorts.SCHEDULER_URL_PROPERTY,
        WireMockPorts.PROVISIONING_API_URL_PROPERTY})
@TestExecutionListeners(value = MockBeanResetListener.class, mergeMode = MergeMode.MERGE_WITH_DEFAULTS)
public class BaseSpringBootTest {

    @MockitoBean
    protected OpaClient opaClient;

    @MockitoBean
    protected AuditLogsProducer auditLogsProducer;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private SettingInternalService settingService;

    @Value("${spring.jpa.properties.hibernate.default_schema:core}")
    protected String dbSchema;

    @BeforeEach
    public void setupAuth() throws SQLException {
        mockSuccessfulCheckResourceAccess();
        mockSuccessfulCheckObjectAccess();
        injectAuthentication();

        TestDatabaseCleaner.clear(dataSource, dbSchema);
        // re-seed the settings cache from the now-empty DB so settings cannot leak into the next context
        settingService.refreshCache();
        MDC.clear();
    }

    protected void mockSuccessfulCheckResourceAccess() {
        OpaResourceAccessResult accessAllowed = new OpaResourceAccessResult();
        accessAllowed.setAuthorized(true);
        accessAllowed.setAllow(List.of());

        when(opaClient.checkResourceAccess(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(accessAllowed);
    }

    protected void mockSuccessfulCheckObjectAccess() {
        OpaObjectAccessResult objectAccessAllowed = new OpaObjectAccessResult();
        objectAccessAllowed.setActionAllowedForGroupOfObjects(true);
        objectAccessAllowed.setAllowedObjects(List.of());
        objectAccessAllowed.setForbiddenObjects(List.of());

        when(opaClient.checkObjectAccess(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(objectAccessAllowed);
    }

    protected void denyResourceAccess(Resource resource, ResourceAction action) {
        OpaResourceAccessResult denied = new OpaResourceAccessResult();
        denied.setAuthorized(false);
        when(opaClient
                .checkResourceAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && resource.getCode().equals(req.getProperties().get("name"))
                                        && action.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenReturn(denied);
    }

    /**
     * Every resource-access request submitted to OPA so far, in submission order.
     */
    protected List<OpaRequestedResource> captureOpaRequests() {
        ArgumentCaptor<OpaRequestedResource> captor = ArgumentCaptor.forClass(OpaRequestedResource.class);
        verify(opaClient, Mockito.atLeastOnce())
                .checkResourceAccess(Mockito.any(), captor.capture(), Mockito.any(), Mockito.any());
        return captor.getAllValues();
    }

    /**
     * Restricts object-level access for one (resource, action) pair to an allow-list, so
     * {@code AuthHelper.loadObjectPermissions} reports the user as restricted. Everything else keeps the default
     * allow-all stub.
     */
    protected void restrictObjectAccess(Resource resource, ResourceAction action) {
        OpaObjectAccessResult restricted = new OpaObjectAccessResult();
        restricted.setActionAllowedForGroupOfObjects(false);
        restricted.setAllowedObjects(List.of(UUID.randomUUID().toString()));
        restricted.setForbiddenObjects(List.of());
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && resource.getCode().equals(req.getProperties().get("name"))
                                        && action.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenReturn(restricted);
    }

    protected void allowResourceAccess(Resource resource, ResourceAction action) {
        OpaResourceAccessResult allowed = new OpaResourceAccessResult();
        allowed.setAuthorized(true);
        allowed.setAllow(List.of());
        when(opaClient
                .checkResourceAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && resource.getCode().equals(req.getProperties().get("name"))
                                        && action.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenReturn(allowed);
    }

    protected void injectAuthentication() {
        SecurityContextHolder.getContext().setAuthentication(getAuthentication());
    }

    protected Authentication getAuthentication() {
        UserProfileDto userProfileDto = new UserProfileDto();
        UserDto userDto = new UserDto();
        userDto.setUuid(UUID.randomUUID().toString());
        userDto.setUsername("tst-user");
        userDto.setFirstName("Test");
        userDto.setLastName("Tester");
        userDto.setSystemUser(true);
        userProfileDto.setUser(userDto);

        String rawData;
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            rawData = objectMapper.writeValueAsString(userProfileDto);
        } catch (JsonProcessingException e) {
            rawData = String
                    .format("{\"user\":{\"uuid\":\"%s\", \"uuid\":\"%s\"}}", userDto.getUuid(), userDto.getUsername());
        }

        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, userDto.getUuid(),
                userDto.getUsername(), List.of(), rawData);
        return new PlatformAuthenticationToken(new PlatformUserDetails(info));
    }
}
