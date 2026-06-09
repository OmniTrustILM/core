package com.otilm.core.security.authz.opa;

import com.otilm.core.security.authz.OpaPolicy;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpaClientTest {
    private static MockWebServer opaMock;

    private static OpaClient opaClient;

    @BeforeAll
    static void setup() throws IOException {
        opaMock = new MockWebServer();
        opaMock.start();

        String opaBaseUrl = "http://%s:%d".formatted(opaMock.getHostName(), opaMock.getPort());
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        opaClient = new OpaClient(objectMapper, opaBaseUrl);
    }

    @AfterAll
    static void tearDown() throws IOException {
        opaMock.close();
        opaMock.shutdown();
    }

    @AfterEach
    void cleanup() {
        try {
            // Clear the last request by reading it
            opaMock.takeRequest(50, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            // No request found, no cleanup needed
        }
    }

    @Test
    void retrievesResourceAccessFromOpa() {
        // given
        setUpSuccessfulResourceAccessResponse();

        // when
        OpaResourceAccessResult result = opaClient.checkResourceAccess(OpaPolicy.METHOD.policyName, getResource(), getPrincipal(), null);

        // then
        assertTrue(result.isAuthorized());
        assertEquals(List.of("SomeOpaRule"), result.getAllow());
    }

    @Test
    void retrievesObjectAccessFromOpa() {
        // given
        setUpSuccessfulObjectAccessResponse();

        // when
        OpaObjectAccessResult result = opaClient.checkObjectAccess(OpaPolicy.OBJECTS.policyName, getResource(), getPrincipal(), null);

        // then
        assertTrue(result.isActionAllowedForGroupOfObjects());
        assertEquals(List.of("f258cb3c-17b5-11ed-861d-0242ac120002"), result.getForbiddenObjects());
        assertEquals(List.of("f258cdda-17b5-11ed-861d-0242ac120002"), result.getAllowedObjects());
    }

    @Test
    void sendsDataToOpa() throws InterruptedException {
        // given
        setUpSuccessfulObjectAccessResponse();

        // when
        opaClient.checkObjectAccess(OpaPolicy.OBJECTS.policyName, getResource(), getPrincipal(), null);

        // then
        RecordedRequest request = getLastRequest();
        assertEquals(MediaType.APPLICATION_JSON.toString(), request.getHeader(HttpHeaders.CONTENT_TYPE));
        assertEquals(MediaType.APPLICATION_JSON.toString(), request.getHeader(HttpHeaders.ACCEPT));
        //@formatter:off
        assertEquals("{" +
                    "\"input\":{" +
                        "\"requestedResource\":{" +
                            "\"uuids\":[\"f258cb3c-17b5-11ed-861d-0242ac120002\"]," +
                            "\"name\":\"GROUPS\"," +
                            "\"action\":\"DETAIL\"" +
                        "}," +
                        "\"details\":null," +
                        "\"principal\":{" +
                            "\"user\":{" +
                                "\"username\":\"FrantisekJednicka\"," +
                                "\"enabled\":true" +
                            "}," +
                            "\"roles\":[" +
                                "\"ROLE_ADMINISTRATOR\"," +
                                "\"ROLE_AUTH_MANAGER\"" +
                            "]" +
                        "}" +
                    "}" +
                "}", request.getBody().readUtf8());
        //@formatter:on
    }

    @Test
    void throwsExceptionWhenResponseIsEmpty() {
        // given
        setUpEmptyResponse();

        // when
        Executable shouldThrow = () -> opaClient.checkResourceAccess(OpaPolicy.METHOD.policyName, getResource(), getPrincipal(), null);

        // then
        assertThrows(AccessDeniedException.class, shouldThrow);
    }

    @Test
    void throwsExceptionWhenRequestToOpaFails() {
        // given
        setUpFaultyResponse();

        // when
        Executable shouldThrow = () -> opaClient.checkResourceAccess(OpaPolicy.METHOD.policyName, getResource(), getPrincipal(), null);

        // then
        assertThrows(AccessDeniedException.class, shouldThrow);
    }


    OpaRequestedResource getResource() {
        Map<String, String> properties = new HashMap<>();
        properties.put("name", "GROUPS");
        properties.put("action", "DETAIL");

        OpaRequestedResource resource = new OpaRequestedResource(properties);
        resource.setObjectUUIDs(List.of("f258cb3c-17b5-11ed-861d-0242ac120002"));

        return resource;
    }

    String getPrincipal() {
        //@formatter:off
        return "{" +
                    "\"user\":{" +
                        "\"username\":\"FrantisekJednicka\"," +
                        "\"enabled\":true" +
                    "}," +
                    "\"roles\":[" +
                        "\"ROLE_ADMINISTRATOR\"," +
                        "\"ROLE_AUTH_MANAGER\"" +
                    "]" +
                "}";
        //@formatter:on
    }

    RecordedRequest getLastRequest() throws InterruptedException {
        return opaMock.takeRequest(500, TimeUnit.MILLISECONDS);
    }

    void setUpSuccessfulResourceAccessResponse() {
        opaMock.enqueue(
                new MockResponse()
                        .setResponseCode(200)
                        .setHeader("content-type", "application/json")
                        //@formatter:off
                        .setBody("{" +
                                    "\"result\": {" +
                                        "\"allow\": [\"SomeOpaRule\"]," +
                                        "\"authorized\": true" +
                                    "}" +
                                "}")
                        //@formatter:on
        );
    }

    void setUpSuccessfulObjectAccessResponse() {
        opaMock.enqueue(
                new MockResponse()
                        .setResponseCode(200)
                        .setHeader("content-type", "application/json")
                        //@formatter:off
                        .setBody("{" +
                                    "\"result\": {" +
                                        "\"forbiddenObjects\": [\"f258cb3c-17b5-11ed-861d-0242ac120002\"]," +
                                        "\"allowedObjects\": [\"f258cdda-17b5-11ed-861d-0242ac120002\"]," +
                                        "\"actionAllowedForGroupOfObjects\": true" +
                                    "}" +
                                "}")
                        //@formatter:on
        );
    }

    void setUpEmptyResponse() {
        opaMock.enqueue(
                new MockResponse()
                        .setResponseCode(200)
                        .setHeader("content-type", "application/json")
        );
    }

    void setUpFaultyResponse() {
        opaMock.enqueue(
                new MockResponse()
                        .setResponseCode(500)
        );
    }
}