package com.otilm.core.util;

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
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mockito;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@SpringBootTest
public class BaseSpringBootTest {

    @MockitoBean
    protected OpaClient opaClient;

    @MockitoBean
    protected AuditLogsProducer auditLogsProducer;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    public void setupAuth() throws SQLException {
        mockSuccessfulCheckResourceAccess();
        mockSuccessfulCheckObjectAccess();
        injectAuthentication();

        // clean DB tables data before each test
        truncateTables();
        // clean context
        MDC.clear();
    }

    private void truncateTables() throws SQLException {
        if (jdbcTemplate.getDataSource() == null) {
            throw new SQLException("JDBCTemplate does not have initialized data source");
        }

        try (Connection connection = jdbcTemplate.getDataSource().getConnection()) {
            List<String> tableNames = new ArrayList<>();
            try (var tables = connection.getMetaData().getTables(
                    connection.getCatalog(),
                    "core",
                    null,
                    new String[]{"TABLE"}
            )) {
                while (tables.next()) {
                    tableNames.add("core.\"%s\"".formatted(tables.getString("TABLE_NAME")));
                }
            }
            if (!tableNames.isEmpty()) {
                String truncateSql = "TRUNCATE " + String.join(", ", tableNames);
                try (var statement = connection.prepareStatement(truncateSql)) {
                    statement.execute();
                }
            }
        }
    }

    protected void mockSuccessfulCheckResourceAccess() {
        OpaResourceAccessResult accessAllowed = new OpaResourceAccessResult();
        accessAllowed.setAuthorized(true);
        accessAllowed.setAllow(List.of());

        Mockito.when(
                opaClient.checkResourceAccess(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())
        ).thenReturn(accessAllowed);
    }

    protected void mockSuccessfulCheckObjectAccess() {
        OpaObjectAccessResult objectAccessAllowed = new OpaObjectAccessResult();
        objectAccessAllowed.setActionAllowedForGroupOfObjects(true);
        objectAccessAllowed.setAllowedObjects(List.of());
        objectAccessAllowed.setForbiddenObjects(List.of());

        Mockito.when(
                opaClient.checkObjectAccess(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any())
        ).thenReturn(objectAccessAllowed);
    }

    protected void denyResourceAccess(Resource resource, ResourceAction action) {
        OpaResourceAccessResult denied = new OpaResourceAccessResult();
        denied.setAuthorized(false);
        Mockito.when(opaClient.checkResourceAccess(
                Mockito.any(),
                Mockito.argThat(req -> req != null
                        && req.getProperties() != null
                        && resource.getCode().equals(req.getProperties().get("name"))
                        && action.getCode().equals(req.getProperties().get("action"))),
                Mockito.any(), Mockito.any())
        ).thenReturn(denied);
    }

    protected void allowResourceAccess(Resource resource, ResourceAction action) {
        OpaResourceAccessResult allowed = new OpaResourceAccessResult();
        allowed.setAuthorized(true);
        allowed.setAllow(List.of());
        Mockito.when(opaClient.checkResourceAccess(
                Mockito.any(),
                Mockito.argThat(req -> req != null
                        && req.getProperties() != null
                        && resource.getCode().equals(req.getProperties().get("name"))
                        && action.getCode().equals(req.getProperties().get("action"))),
                Mockito.any(), Mockito.any())
        ).thenReturn(allowed);
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
            rawData = String.format("{\"user\":{\"uuid\":\"%s\", \"uuid\":\"%s\"}}", userDto.getUuid(), userDto.getUsername());
        }

        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, userDto.getUuid(), userDto.getUsername(), List.of(), rawData);
        return new PlatformAuthenticationToken(new PlatformUserDetails(info));
    }
}
