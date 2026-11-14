package com.otilm.ai.proxy;

import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FixedCoreHttpTest {
    @TempDir
    Path directory;

    @Test
    void callerSuppliedAddressCannotReplaceTheAdministratorPin() throws Exception {
        try (var server = new LocalTlsFixture(directory)) {
            var c = server.configuration();
            var endpoint = new CoreEndpoint(c.coreOrigin(), InetAddress.getByAddress(new byte[]{127, 0, 0, 2}));
            try (var client = FixedCoreHttp
                    .open(endpoint, IdentityFiles.load(c.certificateFile(), c.privateKeyFile(), c.serverCaFile()),
                            TimeUnit.SECONDS.toNanos(1))) {
                var target = new org.apache.hc.core5.http.HttpHost("https", c.coreAddress(), c.coreOrigin().getHost(),
                        c.coreOrigin().getPort());
                var post = new HttpPost(c.coreOrigin() + "/fixed");
                assertThrows(Exception.class, () -> {
                    try (var response = client.executeOpen(target, post, null)) {
                        response.getEntity().getContent().readAllBytes();
                    }
                });
            }
            assertEquals(0, server.connections.get());
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"uri", "scheme", "host", "userinfo"})
    void explicitTargetCannotHideAConflictingRequestAuthority(String kind) throws Exception {
        try (var server = new LocalTlsFixture(directory)) {
            var c = server.configuration();
            try (var client = FixedCoreHttp
                    .open(new CoreEndpoint(c.coreOrigin(), c.coreAddress()),
                            IdentityFiles.load(c.certificateFile(), c.privateKeyFile(), c.serverCaFile()),
                            TimeUnit.SECONDS.toNanos(1))) {
                var post = new HttpPost(switch (kind) {
                    case "uri" -> "https://other.test:1/fixed";
                    case "scheme" -> c.coreOrigin().toString().replace("https:", "http:") + "/fixed";
                    case "userinfo" ->
                        c.coreOrigin().toString().replace("https://", "https://synthetic-user@") + "/fixed";
                    default -> c.coreOrigin() + "/fixed";
                });
                if (kind.equals("host")) {
                    post.setHeader("Host", "other.test:1");
                }
                assertThrows(Exception.class, () -> {
                    try (var response = client
                            .executeOpen(org.apache.hc.core5.http.HttpHost.create(c.coreOrigin()), post, null)) {
                        response.getEntity().getContent().readAllBytes();
                    }
                });
            }
            assertEquals(0, server.connections.get());
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"127.0.0.1", "core.test"})
    void requestProxyCannotOpenAConnectToAnotherDestination(String proxyHost) throws Exception {
        try (var server = new LocalTlsFixture(directory.resolve("core"));
                var proxy = new LocalTlsFixture(directory.resolve("proxy"))) {
            var c = server.configuration();
            try (var client = FixedCoreHttp
                    .open(new CoreEndpoint(c.coreOrigin(), c.coreAddress()),
                            IdentityFiles.load(c.certificateFile(), c.privateKeyFile(), c.serverCaFile()),
                            TimeUnit.SECONDS.toNanos(1))) {
                var post = new HttpPost(c.coreOrigin() + "/fixed");
                post
                        .setConfig(org.apache.hc.client5.http.config.RequestConfig
                                .custom()
                                .setProxy(new org.apache.hc.core5.http.HttpHost("http", proxyHost,
                                        proxy.listener.getLocalPort()))
                                .build());
                assertThrows(Exception.class, () -> client.executeOpen(null, post, null));
            }
            assertEquals(0, server.connections.get());
            assertEquals(0, proxy.connections.get());
        }
    }

    @Test
    void servletContextCannotBeEscapedBeforeOpeningAnySocket() throws Exception {
        try (var server = new LocalTlsFixture(directory)) {
            var c = server.configuration();
            var endpoint = new CoreEndpoint(URI.create(c.coreOrigin() + "/api"), c.coreAddress());
            var identity = IdentityFiles.load(c.certificateFile(), c.privateKeyFile(), c.serverCaFile());
            for (String path : new String[]{
                    "/internal/fixed",
                    "/apix/fixed",
                    "/api/../fixed",
                    "/api/%66ixed",
                    "/api/fixed?selector=x"}) {
                try (var client = FixedCoreHttp.open(endpoint, identity, TimeUnit.SECONDS.toNanos(1))) {
                    var request = new HttpPost(URI.create(c.coreOrigin() + path));
                    assertThrows(Exception.class, () -> {
                        try (var response = client.executeOpen(null, request, null)) {
                            response.getEntity().getContent().readAllBytes();
                        }
                    });
                }
                assertEquals(0, server.connections.get());
                assertEquals(0, server.requests.get());
            }
        }
    }

    @Test
    void independentCallerUsesThePinnedCoreIdentityAddressAndOneHttpRequest() throws Exception {
        try (var server = new LocalTlsFixture(directory)) {
            var configuration = server.configuration();
            var context = IdentityFiles
                    .load(configuration.certificateFile(), configuration.privateKeyFile(),
                            configuration.serverCaFile());
            var endpoint = new CoreEndpoint(configuration.coreOrigin(), configuration.coreAddress());
            assertDoesNotThrow(() -> {
                try (var client = FixedCoreHttp.open(endpoint, context, TimeUnit.SECONDS.toNanos(2))) {
                    var post = new HttpPost(endpoint.origin().resolve("/fixed"));
                    post.setEntity(new ByteArrayEntity(WireBodies.bootstrap().payload(), ContentType.APPLICATION_JSON));
                    try (var response = client.executeOpen(null, post, null)) {
                        assertEquals(200, response.getCode());
                        response.getEntity().getContent().readAllBytes();
                    }
                }
            });
            assertEquals(1, server.requests.get());
            assertEquals(configuration.coreOrigin().getHost(), endpoint.origin().getHost());
        }
    }

    @Test
    void endpointRejectsAlternateAuthoritiesAndUnspecifiedAddresses() throws Exception {
        for (String value : new String[]{
                "http://core.test",
                "https://core.test/",
                "https://core.test/%61pi",
                "https://core.test/a//b",
                "https://core.test/api/../x",
                "https://core.test/" + "a".repeat(128),
                "https://u@core.test",
                "https://core.test?a=b",
                "https://core.test#x",
                "https:opaque",
                "https://core.test:0",
                "https://core.test:65536"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> new CoreEndpoint(URI.create(value), InetAddress.getLoopbackAddress()));
        }
        assertThrows(IllegalArgumentException.class, () -> new CoreEndpoint(null, InetAddress.getLoopbackAddress()));
        assertThrows(IllegalArgumentException.class, () -> new CoreEndpoint(URI.create("https://core.test"), null));
        assertThrows(IllegalArgumentException.class,
                () -> new CoreEndpoint(URI.create("https://core.test"), InetAddress.getByName("0.0.0.0")));
        assertThrows(IllegalArgumentException.class,
                () -> new CoreEndpoint(URI.create("https://core.test"), InetAddress.getByName("224.0.0.1")));
    }

    @Test
    void fixedCoreFactoryRejectsAnotherPortBeforeOpeningAnySocket() throws Exception {
        try (var allowed = new LocalTlsFixture(directory.resolve("allowed"));
                var other = new LocalTlsFixture(directory.resolve("other"))) {
            var c = allowed.configuration();
            try (var client = FixedCoreHttp
                    .open(new CoreEndpoint(c.coreOrigin(), c.coreAddress()),
                            IdentityFiles.load(c.certificateFile(), c.privateKeyFile(), c.serverCaFile()),
                            TimeUnit.SECONDS.toNanos(1))) {
                var request = new HttpPost(other.configuration().coreOrigin().resolve("/forbidden"));
                request.setEntity(new ByteArrayEntity(new byte[]{1}, ContentType.APPLICATION_JSON));
                assertThrows(Exception.class, () -> client.executeOpen(null, request, null));
            }
            assertEquals(0, allowed.connections.get());
            assertEquals(0, other.connections.get());
        }
    }
}
