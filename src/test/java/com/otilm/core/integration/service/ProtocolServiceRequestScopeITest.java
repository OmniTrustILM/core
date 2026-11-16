package com.otilm.core.integration.service;

import com.otilm.core.service.cmp.CmpExternalService;
import com.otilm.core.service.scep.ScepExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.AopTestUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;

class ProtocolServiceRequestScopeITest extends BaseSpringBootTest {

    @Autowired
    private CmpExternalService cmpService;
    @Autowired
    private ScepExternalService scepService;

    @Test
    void createsAnotherCmpServiceInstance_whenAnotherRequestIsBound() {
        // given — the service proxy the controllers are injected with

        // when
        Object first = resolveInstanceForANewRequest(cmpService);
        Object second = resolveInstanceForANewRequest(cmpService);

        // then
        assertThat(first).isNotSameAs(second);
    }

    @Test
    void createsAnotherScepServiceInstance_whenAnotherRequestIsBound() {
        // given — the service proxy the controllers are injected with

        // when
        Object first = resolveInstanceForANewRequest(scepService);
        Object second = resolveInstanceForANewRequest(scepService);

        // then
        assertThat(first).isNotSameAs(second);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Binds a request of its own and returns the service instance that would serve it. */
    private static Object resolveInstanceForANewRequest(Object service) {
        RequestAttributes testRequest = RequestContextHolder.getRequestAttributes();
        ServletRequestAttributes request = new ServletRequestAttributes(new MockHttpServletRequest());
        RequestContextHolder.setRequestAttributes(request);
        try {
            return AopTestUtils.getUltimateTargetObject(service);
        } finally {
            request.requestCompleted();
            RequestContextHolder.setRequestAttributes(testRequest);
        }
    }
}
