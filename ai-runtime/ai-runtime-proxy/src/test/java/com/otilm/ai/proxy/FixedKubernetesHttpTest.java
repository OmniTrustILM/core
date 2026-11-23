package com.otilm.ai.proxy;

import java.net.URI;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The named API grammar extends transport only; the existing Core grammar remains closed. */
class FixedKubernetesHttpTest {
    @TempDir
    Path directory;

    @Test
    void actualTlsGetSupportsTheLiteralKubernetesGroupWhileCoreEntryStillRejectsIt() throws Exception {
        try (var server = new LocalTlsFixture(directory)) {
            var c = server.configuration();
            var endpoint = new CoreEndpoint(c.coreOrigin(), c.coreAddress());
            var tls = IdentityFiles.load(c.certificateFile(), c.privateKeyFile(), c.serverCaFile());
            String path = "/apis/node.k8s.io/v1/runtimeclasses/ilm-runsc";
            try (var client = FixedCoreHttp.openKubernetes(endpoint, tls, TimeUnit.SECONDS.toNanos(2))) {
                assertDoesNotThrow(() -> {
                    try (var response = client.executeOpen(null, new HttpGet(c.coreOrigin() + path), null)) {
                        assertEquals(200, response.getCode());
                        response.getEntity().getContent().readAllBytes();
                    }
                });
            }
            assertEquals(1, server.requests.get());
            assertTrue(server.requestHeaders.startsWith("GET " + path + " HTTP/1.1\r\n"));
            try (var core = FixedCoreHttp.open(endpoint, tls, TimeUnit.SECONDS.toNanos(2))) {
                assertThrows(Exception.class, () -> core.executeOpen(null, new HttpGet(c.coreOrigin() + path), null));
            }
            assertEquals(1, server.connections.get());
            assertEquals(1, server.requests.get());
        }
    }

    @Test
    void emptyDotDotdotEscapedQueryFragmentAndForeignAuthorityCannotOpenASocket() throws Exception {
        try (var server = new LocalTlsFixture(directory)) {
            var c = server.configuration();
            var endpoint = new CoreEndpoint(c.coreOrigin(), c.coreAddress());
            var tls = IdentityFiles.load(c.certificateFile(), c.privateKeyFile(), c.serverCaFile());
            for (String path : new String[]{
                    "/",
                    "/api//v1",
                    "/api/./v1",
                    "/api/../v1",
                    "/api/a..b/v1",
                    "/apis/node%2ek8s.io/v1",
                    "/api/v1?watch=true"}) {
                try (var client = FixedCoreHttp.openKubernetes(endpoint, tls, TimeUnit.SECONDS.toNanos(1))) {
                    assertThrows(Exception.class,
                            () -> client.executeOpen(null, new HttpGet(c.coreOrigin() + path), null));
                }
            }
            try (var client = FixedCoreHttp.openKubernetes(endpoint, tls, TimeUnit.SECONDS.toNanos(1))) {
                assertThrows(Exception.class,
                        () -> client.executeOpen(null, new HttpGet("https://foreign.invalid/api/v1"), null));
            }
            assertEquals(0, server.connections.get());
        }
    }

    @Test
    void kubernetesEntryRequiresRootBaseAndKeepsTheFixedHostGuard() throws Exception {
        try (var server = new LocalTlsFixture(directory)) {
            var c = server.configuration();
            var endpoint = new CoreEndpoint(c.coreOrigin(), c.coreAddress());
            var tls = IdentityFiles.load(c.certificateFile(), c.privateKeyFile(), c.serverCaFile());
            assertThrows(IllegalArgumentException.class,
                    () -> FixedCoreHttp
                            .openKubernetes(new CoreEndpoint(URI.create(c.coreOrigin() + "/api"), c.coreAddress()), tls,
                                    TimeUnit.SECONDS.toNanos(1)));
            try (var client = FixedCoreHttp.openKubernetes(endpoint, tls, TimeUnit.SECONDS.toNanos(1))) {
                var request = new HttpGet(c.coreOrigin() + "/apis/node.k8s.io/v1/runtimeclasses/fixed");
                request.setHeader("Host", "foreign.invalid");
                assertThrows(Exception.class, () -> client.executeOpen(null, request, null));
            }
            assertEquals(0, server.connections.get());
        }
    }

    @Test
    void retainedLiteralFragmentIsRejectedBeforeCanonicalization() throws Exception {
        try (var server = new LocalTlsFixture(directory)) {
            var c = server.configuration();
            var tls = IdentityFiles.load(c.certificateFile(), c.privateKeyFile(), c.serverCaFile());
            try (var client = FixedCoreHttp
                    .open(new CoreEndpoint(c.coreOrigin(), c.coreAddress()), tls, TimeUnit.SECONDS.toNanos(1))) {
                var request = new HttpGet(c.coreOrigin() + "/fixed");
                request.setPath("/fixed#fragment");
                assertThrows(Exception.class, () -> client.executeOpen(null, request, null));
            }
            assertEquals(0, server.connections.get());
        }
    }
}
