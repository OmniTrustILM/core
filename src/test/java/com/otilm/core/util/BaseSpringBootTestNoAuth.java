package com.otilm.core.util;

import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
@TestPropertySource(properties = {
        WireMockPorts.AUTH_SERVICE_URL_PROPERTY,
        WireMockPorts.SCHEDULER_URL_PROPERTY,
        WireMockPorts.PROVISIONING_API_URL_PROPERTY})
public class BaseSpringBootTestNoAuth {

    @MockitoBean
    OpaClient opaClient;

    @BeforeEach
    public void setupAuth() {
        mockSuccessfulCheckResourceAccess();
        mockSuccessfulCheckObjectAccess();
    }

    protected void mockSuccessfulCheckResourceAccess() {
        OpaResourceAccessResult accessAllowed = new OpaResourceAccessResult();
        accessAllowed.setAuthorized(true);
        accessAllowed.setAllow(List.of());

        Mockito
                .when(opaClient.checkResourceAccess(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(accessAllowed);
    }

    protected void mockSuccessfulCheckObjectAccess() {
        OpaObjectAccessResult objectAccessAllowed = new OpaObjectAccessResult();
        objectAccessAllowed.setActionAllowedForGroupOfObjects(true);
        objectAccessAllowed.setAllowedObjects(List.of());
        objectAccessAllowed.setForbiddenObjects(List.of());

        Mockito
                .when(opaClient.checkObjectAccess(Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any()))
                .thenReturn(objectAccessAllowed);
    }
}
