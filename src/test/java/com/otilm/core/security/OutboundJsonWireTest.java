package com.otilm.core.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import com.otilm.api.clients.BaseApiClient;
import com.otilm.core.provisioning.ProvisioningApiConfig;
import com.otilm.core.provisioning.ProvisioningApiProperties;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.security.authz.opa.OpaClient;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Every outbound HTTP client in core writes JSON with Jackson 2, which honours the DTOs' Jackson 2 annotations. */
class OutboundJsonWireTest {

    /** Jackson 3 ignores the Jackson 2 serializer and sorts properties, and writes {"a":1,"b":7}. */
    private static final String JACKSON_2_WIRE = "{\"b\":\"7\",\"a\":1}";

    private MockWebServer server;

    @BeforeEach
    void start() throws IOException {
        server = new MockWebServer();
        server.start();
        server.enqueue(new MockResponse().setResponseCode(204));
    }

    @AfterEach
    void stop() throws IOException {
        server.shutdown();
    }

    @Test
    void opaClientWritesJackson2() throws InterruptedException {
        assertEquals(JACKSON_2_WIRE, sentBy(new OpaClient(new ObjectMapper(), baseUrl(), null).getClient()));
    }

    @Test
    void authServiceClientWritesJackson2() throws InterruptedException {
        assertEquals(JACKSON_2_WIRE, sentBy(new UserManagementApiClient(baseUrl(), null).getClient(null)));
    }

    @Test
    void mutatedConnectorClientKeepsJackson2() throws InterruptedException {
        WebClient cbomStyle = BaseApiClient
                .prepareWebClient()
                .mutate()
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(1024))
                .baseUrl(baseUrl())
                .build();
        assertEquals(JACKSON_2_WIRE, sentBy(cbomStyle));
    }

    @Test
    void provisioningClientWritesJackson2() throws InterruptedException {
        ProvisioningApiProperties properties = new ProvisioningApiProperties(baseUrl(), "key", Duration.ofSeconds(5),
                Duration.ofSeconds(5), "shell");
        RestClient client = new ProvisioningApiConfig(properties)
                .provisioningRestClient((request, body, execution) -> execution.execute(request, body));
        client
                .post()
                .uri("/probe")
                .contentType(MediaType.APPLICATION_JSON)
                .body(new Probe())
                .retrieve()
                .toBodilessEntity();
        assertEquals(JACKSON_2_WIRE, server.takeRequest(5, TimeUnit.SECONDS).getBody().readUtf8());
    }

    private String baseUrl() {
        return server.url("/").toString();
    }

    private String sentBy(WebClient client) throws InterruptedException {
        client
                .post()
                .uri("/probe")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new Probe())
                .retrieve()
                .toBodilessEntity()
                .block();
        return server.takeRequest(5, TimeUnit.SECONDS).getBody().readUtf8();
    }

    static class Probe {
        @JsonSerialize(using = ToStringSerializer.class)
        public long b = 7;
        public int a = 1;
    }
}
