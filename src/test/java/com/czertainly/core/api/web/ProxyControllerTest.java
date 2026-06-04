package com.czertainly.core.api.web;

import com.czertainly.api.model.core.proxy.ProxyStatus;
import com.czertainly.core.dao.entity.Proxy;
import com.czertainly.core.dao.repository.ProxyRepository;
import com.czertainly.core.provisioning.ProxyProvisioningService;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class ProxyControllerTest extends BaseSpringBootTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ProxyRepository proxyRepository;

    @MockitoBean
    private ProxyProvisioningService proxyProvisioningService;

    @BeforeEach
    void setUp() {
        String command = "helm install test-proxy ...";
        doNothing().when(proxyProvisioningService).provisionProxy(anyString());
        when(proxyProvisioningService.getProxyInstallationInstructions(anyString())).thenReturn(command);
        doNothing().when(proxyProvisioningService).decommissionProxy(anyString());
    }

    @Test
    void listProxies_empty() throws Exception {
        mockMvc.perform(get("/v1/proxies"))
            .andExpectAll(status().isOk());
    }

    @Test
    void listProxies_emptyWithFilter() throws Exception {
        mockMvc.perform(get("/v1/proxies")
                .param("status", "connected"))
            .andExpectAll(status().isOk());
    }

    @Test
    void getProxy_notFound() throws Exception {
        mockMvc.perform(get("/v1/proxies/{uuid}", "00000000-0000-0000-0000-000000000000"))
            .andExpectAll(status().isNotFound());
    }

    @Test
    void getProxy() throws Exception {
        Proxy proxy = new Proxy();
        proxy.setName("testProxy1");
        proxy.setDescription("Test Proxy 1");
        proxy.setCode("TEST_PROXY_1");
        proxy.setStatus(ProxyStatus.CONNECTED);
        proxy = proxyRepository.save(proxy);

        mockMvc.perform(get("/v1/proxies/{uuid}", proxy.getUuid()))
            .andExpectAll(status().isOk(),
                jsonPath("$.uuid").value(proxy.getUuid().toString()),
                jsonPath("$.name").value(proxy.getName()),
                jsonPath("$.description").value(proxy.getDescription()),
                jsonPath("$.code").value(proxy.getCode()),
                jsonPath("$.status").value(proxy.getStatus().getCode()));
    }

    @Test
    void createProxy() throws Exception {
        String requestBody = """
            {
                "name": "testProxy2",
                "description": "Test Proxy 2"
            }
            """;

        mockMvc.perform(post("/v1/proxies")
                .contentType("application/json")
                .content(requestBody))
            .andExpectAll(status().isCreated(),
                jsonPath("$.uuid").exists());
    }

    @Test
    void editProxy() throws Exception {
        Proxy proxy = new Proxy();
        proxy.setName("testProxy3");
        proxy.setDescription("Test Proxy 3");
        proxy.setCode("TEST_PROXY_3");
        proxy.setStatus(ProxyStatus.CONNECTED);
        proxy = proxyRepository.save(proxy);

        String requestBody = """
            {
                "description": "Updated Test Proxy 3"
            }
            """;

        mockMvc.perform(put("/v1/proxies/{uuid}", proxy.getUuid())
                .contentType("application/json")
                .content(requestBody))
            .andExpectAll(status().isOk(),
                jsonPath("$.uuid").value(proxy.getUuid().toString()),
                jsonPath("$.name").value(proxy.getName()),
                jsonPath("$.description").value("Updated Test Proxy 3"));
    }

    @Test
    void editProxy_notFound() throws Exception {
        String requestBody = """
            {
                "description": "Updated Description"
            }
            """;

        mockMvc.perform(put("/v1/proxies/{uuid}", "00000000-0000-0000-0000-000000000000")
                .contentType("application/json")
                .content(requestBody))
            .andExpectAll(status().isNotFound());
    }

    @Test
    void deleteProxy() throws Exception {
        Proxy proxy = new Proxy();
        proxy.setName("testProxy4");
        proxy.setDescription("Test Proxy 4");
        proxy.setCode("TEST_PROXY_4");
        proxy.setStatus(ProxyStatus.CONNECTED);
        proxy = proxyRepository.save(proxy);

        mockMvc.perform(delete("/v1/proxies/{uuid}", proxy.getUuid()))
            .andExpectAll(status().isNoContent());
    }

    @Test
    void deleteProxy_notFound() throws Exception {
        mockMvc.perform(delete("/v1/proxies/{uuid}", "00000000-0000-0000-0000-000000000000"))
            .andExpectAll(status().isNotFound());
    }
}
