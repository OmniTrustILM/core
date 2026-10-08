package com.otilm.core.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.config.cache.CacheConfig;
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
import java.util.Objects;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
@Import(MockMvcSecurityContextConfig.class)
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

    @Autowired
    private CacheManager cacheManager;

    @Value("${spring.jpa.properties.hibernate.default_schema:core}")
    protected String dbSchema;

    @BeforeEach
    public void setupAuth() throws SQLException {
        mockSuccessfulCheckResourceAccess();
        mockSuccessfulCheckObjectAccess();
        injectAuthentication();

        TestDatabaseCleaner.clear(dataSource, dbSchema);
        // The catalogue cache outlives the rows it was read from, and every test starts from an empty database.
        Objects.requireNonNull(cacheManager.getCache(CacheConfig.ATTRIBUTE_SEARCH_FIELDS_CACHE)).clear();
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
     * Denies the OBJECT-access vote for one resource+action -- the vote {@code ObjectFilterAspect} turns into a
     * security filter -- while {@link #denyResourceAccess} denies the method-security resource vote. A path that scopes
     * data by a populated filter (rather than refusing the call) is exercised through this one: the filter comes back
     * "only specific objects, none allowed", so the scoped query returns nothing instead of everything.
     */
    protected void denyObjectAccess(Resource resource, ResourceAction action) {
        OpaObjectAccessResult noObjects = new OpaObjectAccessResult();
        noObjects.setActionAllowedForGroupOfObjects(false);
        noObjects.setAllowedObjects(List.of());
        noObjects.setForbiddenObjects(List.of());
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && resource.getCode().equals(req.getProperties().get("name"))
                                        && action.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenReturn(noObjects);
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
        restrictObjectAccess(resource, action, List.of(UUID.randomUUID()));
    }

    /**
     * Restricts object-level access for one (resource, action) pair to exactly the given objects, for tests that need a
     * restricted user who can still see something.
     */
    protected void restrictObjectAccess(Resource resource, ResourceAction action, List<UUID> allowed) {
        OpaObjectAccessResult restricted = new OpaObjectAccessResult();
        restricted.setActionAllowedForGroupOfObjects(false);
        restricted.setAllowedObjects(allowed.stream().map(UUID::toString).toList());
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

    /**
     * Grants the action on the resource but withholds it on the given objects, which is what a role's object-level row
     * with no action granted resolves to.
     */
    protected void forbidObjectAccess(Resource resource, ResourceAction action, List<UUID> forbidden) {
        OpaObjectAccessResult result = new OpaObjectAccessResult();
        result.setActionAllowedForGroupOfObjects(true);
        result.setAllowedObjects(List.of());
        result.setForbiddenObjects(forbidden.stream().map(UUID::toString).toList());
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && resource.getCode().equals(req.getProperties().get("name"))
                                        && action.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenReturn(result);
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
