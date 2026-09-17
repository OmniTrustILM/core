package com.otilm.core.integration.service;

import com.otilm.core.security.authz.opa.AuthorizationCache;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.RoleManagementExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mockbeans.ManagementApiMocks;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

@Import(ManagementApiMocks.class)
class AuthorizationCacheITest extends BaseSpringBootTest {

    private static final String PRINCIPAL = """
            {"user":{"uuid":"1111","username":"alice"},"roles":[],"permissions":\
            {"allowAllResources":false,"resources":[]}}""";

    @Autowired
    private AuthorizationCache authorizationCache;

    @Autowired
    private RoleManagementExternalService roleManagementService;

    private AtomicInteger loads;

    @BeforeEach
    void startFromAnEmptyCache() {
        authorizationCache.evictAll();
        loads = new AtomicInteger();
    }

    private void decide() {
        authorizationCache
                .getOrCheckResourceAccess("method",
                        new OpaRequestedResource(Map.of("name", "certificates", "action", "detail")), PRINCIPAL,
                        new OpaRequestDetails(null), () -> {
                            loads.incrementAndGet();
                            return new OpaResourceAccessResult(true, List.of("ActionAllowedOnResource"));
                        });
    }

    @Test
    void repeatedDecisionIsServedFromCache() {
        decide();
        decide();

        assertThat(loads).hasValue(1);
    }

    @Test
    void roleDeletionEvictsTheDecision() {
        decide();

        roleManagementService.deleteRole(UUID.randomUUID().toString());
        decide();

        assertThat(loads).hasValue(2);
    }
}
