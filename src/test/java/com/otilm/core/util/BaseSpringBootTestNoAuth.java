package com.otilm.core.util;

import com.otilm.core.security.authz.opa.OpaClient;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;

@SpringBootTest
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
}
