package com.otilm.core.integration.config;

import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class MockMvcSecurityContextITest extends BaseSpringBootTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void requestCarriesTheTestsSecurityContext() throws Exception {
        mockMvc.perform(get("/v1/proxies")).andExpect(status().isOk());
    }

    @Test
    void contextOutlivesTheFirstRequest() throws Exception {
        mockMvc.perform(get("/v1/proxies")).andExpect(status().isOk());
        mockMvc.perform(get("/v1/proxies")).andExpect(status().isOk());
    }

    @Test
    void requestWithoutContextIsRejected() throws Exception {
        SecurityContextHolder.clearContext();
        mockMvc.perform(get("/v1/proxies")).andExpect(status().isUnauthorized());
    }
}
