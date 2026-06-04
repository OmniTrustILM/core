package com.czertainly.core.provisioning;

import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.*;

class ProxyProvisioningServiceTest extends BaseSpringBootTest {

    private static final String PROXY_CODE = "TEST_PROXY";
    private static final String INSTALLATION_INSTRUCTIONS_JSON = """
        {
            "command": {
                "shell": "helm install test-proxy oci://registry.example.com/charts/proxy --version 1.0.0"
            }
        }
        """;

    @RegisterExtension
    static WireMockExtension wireMockServer = WireMockExtension.newInstance()
        .options(wireMockConfig().dynamicPort())
        .build();

    @Autowired
    private ProxyProvisioningService proxyProvisioningService;

    @DynamicPropertySource
    static void proxyProvisioningTestProperties(@NonNull DynamicPropertyRegistry registry) {
        registry.add("provisioning.api.url", wireMockServer::baseUrl);
    }

    @Test
    void testProvisionProxy_success() {
        wireMockServer.stubFor(post(urlPathEqualTo("/api/v1/proxies"))
            .willReturn(aResponse().withStatus(201)));

        proxyProvisioningService.provisionProxy(PROXY_CODE);

        wireMockServer.verify(postRequestedFor(urlPathEqualTo("/api/v1/proxies"))
            .withRequestBody(matchingJsonPath("$.proxyCode", equalTo(PROXY_CODE))));
    }

    @Test
    void testProvisionProxy_apiFails() {
        wireMockServer.stubFor(post(urlPathEqualTo("/api/v1/proxies"))
            .willReturn(aResponse()
                .withStatus(500)
                .withBody("Internal Server Error")));

        ProvisioningException exception = assertThrows(ProvisioningException.class,
            () -> proxyProvisioningService.provisionProxy(PROXY_CODE));

        assertTrue(exception.getMessage().contains("Failed to provision proxy"));
        assertTrue(exception.getMessage().contains(PROXY_CODE));
    }

    @Test
    void testGetProxyInstallationInstructions_success() {
        wireMockServer.stubFor(get(urlPathEqualTo("/api/v1/proxies/" + PROXY_CODE + "/installation"))
            .withQueryParam("format", equalTo("helm"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(INSTALLATION_INSTRUCTIONS_JSON)));

        String result = proxyProvisioningService.getProxyInstallationInstructions(PROXY_CODE);

        assertNotNull(result);
        assertEquals("helm install test-proxy oci://registry.example.com/charts/proxy --version 1.0.0", result);
    }

    @Test
    void testGetProxyInstallationInstructions_apiFails() {
        wireMockServer.stubFor(get(urlPathEqualTo("/api/v1/proxies/" + PROXY_CODE + "/installation"))
            .withQueryParam("format", equalTo("helm"))
            .willReturn(aResponse()
                .withStatus(404)
                .withBody("Not Found")));

        ProvisioningException exception = assertThrows(ProvisioningException.class,
            () -> proxyProvisioningService.getProxyInstallationInstructions(PROXY_CODE));

        assertTrue(exception.getMessage().contains("Failed to get proxy installation instructions"));
        assertTrue(exception.getMessage().contains(PROXY_CODE));
    }

    @Test
    void testDecommissionProxy_success() {
        wireMockServer.stubFor(delete(urlPathEqualTo("/api/v1/proxies/" + PROXY_CODE))
            .willReturn(aResponse().withStatus(204)));

        assertDoesNotThrow(() -> proxyProvisioningService.decommissionProxy(PROXY_CODE));

        wireMockServer.verify(deleteRequestedFor(urlPathEqualTo("/api/v1/proxies/" + PROXY_CODE)));
    }

    @Test
    void testDecommissionProxy_apiFails() {
        wireMockServer.stubFor(delete(urlPathEqualTo("/api/v1/proxies/" + PROXY_CODE))
            .willReturn(aResponse()
                .withStatus(500)
                .withBody("Internal Server Error")));

        ProvisioningException exception = assertThrows(ProvisioningException.class,
            () -> proxyProvisioningService.decommissionProxy(PROXY_CODE));

        assertTrue(exception.getMessage().contains("Failed to decommission proxy"));
        assertTrue(exception.getMessage().contains(PROXY_CODE));
    }
}
