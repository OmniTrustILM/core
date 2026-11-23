package com.otilm.ai.gateway;

import com.otilm.ai.runtime.protocol.PayloadFingerprint;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChatCompletionsTransportTest {
    private static final byte[] REQUEST = "{\"model\":\"f04-test\",\"messages\":[{\"role\":\"user\",\"content\":\"synthetic\"}],\"max_tokens\":32,\"stream\":false}"
            .getBytes(StandardCharsets.UTF_8);
    private static final byte[] REPLY = "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"bounded synthetic reply\"}}]}"
            .getBytes(StandardCharsets.UTF_8);
    private final ChatCompletionsTransport transport = new ChatCompletionsTransport();

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(ints = {101, 301, 302, 303, 307, 308, 401, 407, 408, 421, 503})
    void rawFailureStatusesNeverTriggerASecondProviderRequest(int status) throws Exception {
        try (var server = new HttpsFixture(status, new byte[]{1})) {
            failure(GatewayFailure.Code.UPSTREAM_FAILURE, () -> transport
                    .post(server.endpoint(), REQUEST, PayloadFingerprint.sha256(REQUEST), "synthetic-token"));
            assertEquals(1, server.requests.get());
        }
    }

    @Test
    void resetAfterTheActualProviderPostCannotTriggerAResend() throws Exception {
        try (var server = new HttpsFixture(200, REPLY)) {
            server.reset = true;
            failure(GatewayFailure.Code.UPSTREAM_FAILURE, () -> transport
                    .post(server.endpoint(), REQUEST, PayloadFingerprint.sha256(REQUEST), "synthetic-token"));
            assertEquals(1, server.requests.get());
            assertArrayEquals(REQUEST, server.received.get());
        }
    }

    @Test
    void actualHttpsUsesPinnedAddressOriginalHostnameExactPayloadAndFixedHeaders() throws Exception {
        try (var server = new HttpsFixture(200, REPLY)) {
            assertArrayEquals(REPLY,
                    transport.post(server.endpoint(), REQUEST, PayloadFingerprint.sha256(REQUEST), "test-only-token"));
            assertEquals(1, server.requests.get());
            assertArrayEquals(REQUEST, server.received.get());
            assertEquals("/v1/chat/completions", server.path.get());
            assertEquals("Bearer test-only-token", server.authorization.get());
            assertTrue(server.contentType.get().startsWith("application/json"));
            assertEquals("identity", server.acceptEncoding.get());
        }
    }

    @Test
    void changedBytesAreRejectedBeforeAnySocketRequest() throws Exception {
        try (var server = new HttpsFixture(200, REPLY)) {
            failure(GatewayFailure.Code.INVALID_REQUEST,
                    () -> transport.post(server.endpoint(), REQUEST, "0".repeat(64), "test-only-token"));
            assertEquals(0, server.requests.get());
        }
    }

    @Test
    void redirectDoesNotForwardCredentialOrCreateSecondRequest() throws Exception {
        try (var target = new HttpsFixture(200, REPLY); var source = new HttpsFixture(307, new byte[0])) {
            source.redirect = target.endpoint().origin().toString() + "/v1/chat/completions";
            failure(GatewayFailure.Code.UPSTREAM_FAILURE, () -> transport
                    .post(source.endpoint(), REQUEST, PayloadFingerprint.sha256(REQUEST), "test-only-token"));
            assertEquals(1, source.requests.get());
            assertEquals(0, target.requests.get());
        }
    }

    @Test
    void wrongHostnameFailsBeforeHttpEvenWithTrustedCaAndPinnedAddress() throws Exception {
        try (var server = new HttpsFixture(200, REPLY)) {
            var endpoint = server.endpoint("wrong.invalid", server.endpoint().trust());
            failure(GatewayFailure.Code.UPSTREAM_FAILURE,
                    () -> transport.post(endpoint, REQUEST, PayloadFingerprint.sha256(REQUEST), "test-only-token"));
            assertEquals(0, server.requests.get());
        }
    }

    @Test
    void untrustedCaFailsBeforeHttp() throws Exception {
        try (var trusted = new HttpsFixture(200, REPLY); var foreign = new HttpsFixture(200, REPLY)) {
            var endpoint = trusted.endpoint("provider.invalid", foreign.endpoint().trust());
            failure(GatewayFailure.Code.UPSTREAM_FAILURE,
                    () -> transport.post(endpoint, REQUEST, PayloadFingerprint.sha256(REQUEST), "test-only-token"));
            assertEquals(0, trusted.requests.get());
        }
    }

    @Test
    void contentEncodingIsRejectedWithoutDecompression() throws Exception {
        try (var server = new HttpsFixture(200, new byte[]{31, -117, 0})) {
            server.encoding = "gzip";
            failure(GatewayFailure.Code.UNSUPPORTED_ENCODING, () -> transport
                    .post(server.endpoint(), REQUEST, PayloadFingerprint.sha256(REQUEST), "test-only-token"));
            assertEquals(1, server.requests.get());
        }
    }

    @Test
    void oversizedResponseIsBounded() throws Exception {
        try (var server = new HttpsFixture(200, new byte[1048577])) {
            failure(GatewayFailure.Code.RESPONSE_LIMIT, () -> transport
                    .post(server.endpoint(), REQUEST, PayloadFingerprint.sha256(REQUEST), "test-only-token"));
            assertEquals(1, server.requests.get());
        }
    }

    @Test
    void transportFailureRetainsOnlyControlledCode() throws Exception {
        try (var server = new HttpsFixture(500, "private-provider-error-body".getBytes(StandardCharsets.UTF_8))) {
            var rejected = failure(GatewayFailure.Code.UPSTREAM_FAILURE, () -> transport
                    .post(server.endpoint(), REQUEST, PayloadFingerprint.sha256(REQUEST), "private-credential-canary"));
            assertEquals("UPSTREAM_FAILURE", rejected.getMessage());
            assertNull(rejected.getCause());
            assertEquals(0, rejected.getStackTrace().length);
        }
    }

    @Test
    void unsafeOriginIsRejectedBeforeClientCreation() throws Exception {
        try (var server = new HttpsFixture(200, REPLY)) {
            var endpoint = server.endpoint();
            failure(GatewayFailure.Code.INVALID_REQUEST,
                    () -> new PinnedEndpoint(URI.create("http://provider.invalid:8443"), endpoint.addresses(),
                            endpoint.trust()));
            failure(GatewayFailure.Code.INVALID_REQUEST,
                    () -> new PinnedEndpoint(URI.create("https://user:pass@provider.invalid:8443"),
                            endpoint.addresses(), endpoint.trust()));
            failure(GatewayFailure.Code.INVALID_REQUEST,
                    () -> new PinnedEndpoint(URI.create("https://provider.invalid:8443/other"), endpoint.addresses(),
                            endpoint.trust()));
            assertEquals(0, server.requests.get());
        }
    }

    @Test
    void oversizedChunkedBodyAbortsSocketInsteadOfDrainingUpstream() throws Exception {
        try (var server = new HttpsFixture(200, new byte[0])) {
            server.hostileChunked = true;
            failure(GatewayFailure.Code.RESPONSE_LIMIT, () -> transport
                    .post(server.endpoint(), REQUEST, PayloadFingerprint.sha256(REQUEST), "test-only-token"));
            assertTrue(server.responseEnded.await(3, TimeUnit.SECONDS));
            assertTrue(server.responseAborted.get());
            assertTrue(server.chunksWritten.get() < 192);
        }
    }

    @Test
    void malformedTrustedTransportInputsCannotStartARequest() throws Exception {
        try (var server = new HttpsFixture(200, REPLY)) {
            var endpoint = server.endpoint();
            String digest = PayloadFingerprint.sha256(REQUEST);
            failure(GatewayFailure.Code.INVALID_REQUEST, () -> transport.post(null, REQUEST, digest, "token"));
            failure(GatewayFailure.Code.INVALID_REQUEST, () -> transport.post(endpoint, null, digest, "token"));
            failure(GatewayFailure.Code.INVALID_REQUEST, () -> transport.post(endpoint, new byte[0], digest, "token"));
            failure(GatewayFailure.Code.INVALID_REQUEST,
                    () -> transport.post(endpoint, new byte[1048577], digest, "token"));
            failure(GatewayFailure.Code.INVALID_REQUEST, () -> transport.post(endpoint, REQUEST, null, "token"));
            failure(GatewayFailure.Code.INVALID_REQUEST,
                    () -> transport.post(endpoint, REQUEST, "A".repeat(64), "token"));
            failure(GatewayFailure.Code.INVALID_REQUEST, () -> transport.post(endpoint, REQUEST, digest, null));
            for (String token : java.util.List.of("", "token with space", "token\r\ninjected: yes", "a".repeat(4097))) {
                failure(GatewayFailure.Code.INVALID_REQUEST, () -> transport.post(endpoint, REQUEST, digest, token));
            }
            for (String origin : java.util.List
                    .of("https:/no-host", "https://provider.invalid:8443?query=bad",
                            "https://provider.invalid:8443#fragment", "https://provider.invalid",
                            "https://provider.invalid:0", "https://provider.invalid:65536")) {
                failure(GatewayFailure.Code.INVALID_REQUEST,
                        () -> new PinnedEndpoint(URI.create(origin), endpoint.addresses(), endpoint.trust()));
            }
            failure(GatewayFailure.Code.INVALID_REQUEST,
                    () -> new PinnedEndpoint(endpoint.origin(), java.util.List.of(), endpoint.trust()));
            var endpointOrigin = endpoint.origin();
            var endpointAddresses = endpoint.addresses();
            var endpointTrust = endpoint.trust();
            assertThrows(NullPointerException.class, () -> new PinnedEndpoint(null, endpointAddresses, endpointTrust));
            assertThrows(NullPointerException.class, () -> new PinnedEndpoint(endpointOrigin, endpointAddresses, null));
            assertThrows(NullPointerException.class, () -> new PinnedEndpoint(endpointOrigin, null, endpointTrust));
            assertEquals(endpoint.addresses(),
                    new PinnedEndpoint(URI.create(endpoint.origin() + "/"), endpoint.addresses(), endpoint.trust())
                            .addresses());
            assertEquals(0, server.requests.get());
        }
    }

    @Test
    void interruptionBeforeExchangeCannotSend() throws Exception {
        try (var server = new HttpsFixture(200, REPLY)) {
            Thread.currentThread().interrupt();
            try {
                failure(GatewayFailure.Code.UPSTREAM_FAILURE,
                        () -> transport.post(server.endpoint(), REQUEST, PayloadFingerprint.sha256(REQUEST), "token"));
                assertTrue(Thread.currentThread().isInterrupted());
            } finally {
                Thread.interrupted();
            }
            assertEquals(0, server.requests.get());
        }
    }

    @Test
    void refusedConnectionReturnsOnlyControlledFailure() throws Exception {
        var server = new HttpsFixture(200, REPLY);
        var endpoint = server.endpoint();
        server.close();
        failure(GatewayFailure.Code.UPSTREAM_FAILURE,
                () -> transport.post(endpoint, REQUEST, PayloadFingerprint.sha256(REQUEST), "token"));
        assertEquals(0, server.requests.get());
    }

    @Test
    void postSendBadTlsRecordIsUncertain() throws Exception {
        try (var ca = new HttpsFixture(200, REPLY); var hostile = new PostSendTlsFaultFixture(ca)) {
            var rejected = assertThrows(GatewayFailure.class,
                    () -> transport.post(hostile.endpoint(), REQUEST, PayloadFingerprint.sha256(REQUEST), "token"));
            assertTrue(hostile.finished.await(3, TimeUnit.SECONDS));
            assertNull(hostile.fixtureFailure.get());
            assertTrue(hostile.faultInjected.get());
            assertArrayEquals(REQUEST, hostile.received.get());
            System.out.println("F04_POSTSEND_TLS_CONTROL fullPostObserved=true faultInjected=true");
            assertEquals(GatewayFailure.Code.UPSTREAM_FAILURE, rejected.code());
            assertTrue(rejected.mayHaveSent());
        }
    }

    private static GatewayFailure failure(GatewayFailure.Code code, org.junit.jupiter.api.function.Executable action) {
        var failure = assertThrows(GatewayFailure.class, action);
        assertEquals(code, failure.code());
        assertEquals(code != GatewayFailure.Code.INVALID_REQUEST, failure.mayHaveSent());
        return failure;
    }
}
