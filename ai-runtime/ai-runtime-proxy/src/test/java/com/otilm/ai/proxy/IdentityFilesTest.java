package com.otilm.ai.proxy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

class IdentityFilesTest {
    @TempDir
    Path directory;

    @Test
    void publicThreePathIdentitySupportsAnIndependentFixedCoreCaller() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var method = assertDoesNotThrow(
                    () -> IdentityFiles.class.getMethod("load", Path.class, Path.class, Path.class));
            var context = (javax.net.ssl.SSLContext) method
                    .invoke(null, directory.resolve("tls.crt"), directory.resolve("tls.key"),
                            directory.resolve("ca.pem"));
            try (var connection = new java.net.Socket(fixture.configuration().coreAddress(),
                    fixture.listener.getLocalPort());
                    var socket = (javax.net.ssl.SSLSocket) context
                            .getSocketFactory()
                            .createSocket(connection, "core.test", fixture.listener.getLocalPort(), true)) {
                socket.setSoTimeout(2000);
                var parameters = socket.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(parameters);
                socket.startHandshake();
                byte[] body = WireBodies.bootstrap().payload();
                socket
                        .getOutputStream()
                        .write(("POST /fixed HTTP/1.1\r\nHost: core.test\r\nContent-Length: " + body.length
                                + "\r\nConnection: close\r\n\r\n")
                                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                socket.getOutputStream().write(body);
                socket.getOutputStream().flush();
                assertEquals('H', socket.getInputStream().read());
            }
            assertEquals(1, fixture.requests.get());
            assertEquals(fixture.client.certificate().getSerialNumber(), fixture.peerSerial);
        }
    }

    @Test
    void rotationLoadsOnlyTheNewConsistentCsiRevision() throws Exception {
        try (var fixture = new LocalTlsFixture(directory.resolve("server"))) {
            Path mount = Files.createDirectories(directory.resolve("mount"));
            Path first = mount.resolve("revision-1");
            Path second = mount.resolve("revision-2");
            LocalTlsFixture.writeClient(first, fixture.client);
            var rotated = LocalTlsFixture.material("rotated", fixture.ca, false, null, false, "secp256r1");
            LocalTlsFixture.writeClient(second, rotated);
            Files.createSymbolicLink(mount.resolve("..data"), first.getFileName());
            Files.createSymbolicLink(mount.resolve("tls.crt"), Path.of("..data/tls.crt"));
            Files.createSymbolicLink(mount.resolve("tls.key"), Path.of("..data/tls.key"));
            var old = fixture.configuration();
            var configuration = new ProxyConfiguration(old.coreOrigin(), old.coreAddress(), mount.resolve("tls.crt"),
                    mount.resolve("tls.key"), old.serverCaFile());
            CoreRpcClient client = new CoreRpcClient(configuration);
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY, client.execute(WireBodies.bootstrap()).outcome());
            assertEquals(fixture.client.certificate().getSerialNumber(), fixture.peerSerial);
            Files.createSymbolicLink(mount.resolve("..next"), second.getFileName());
            Files
                    .move(mount.resolve("..next"), mount.resolve("..data"), StandardCopyOption.ATOMIC_MOVE,
                            StandardCopyOption.REPLACE_EXISTING);
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY, client.execute(WireBodies.bootstrap()).outcome());
            assertEquals(rotated.certificate().getSerialNumber(), fixture.peerSerial);
            Files.delete(second.resolve("tls.key"));
            assertEquals(ProxyReply.Outcome.NOT_SENT, client.execute(WireBodies.bootstrap()).outcome());
            assertEquals(2, fixture.requests.get());
        }
    }

    @Test
    void acceptsAConsistentExplicitClientCertificateChain() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            Files
                    .writeString(directory.resolve("tls.crt"), Files.readString(directory.resolve("tls.crt"))
                            + Files.readString(directory.resolve("ca.pem")));
            assertEquals(ProxyReply.Outcome.UPSTREAM_REPLY,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(1, fixture.requests.get());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "curve",
            "expired-client",
            "malformed-key",
            "extra-key",
            "too-large-key",
            "nonca",
            "split-revision",
            "empty-ca",
            "missing-footer",
            "bad-base64",
            "too-many-certificates",
            "directory-key"})
    void rejectsUnsupportedOrIncompleteIdentityBeforeOpeningConnection(String failure) throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            switch (failure) {
                case "curve" -> LocalTlsFixture
                        .writeClient(directory,
                                LocalTlsFixture.material("wrong-curve", fixture.ca, false, null, false, "secp384r1"));
                case "expired-client" -> LocalTlsFixture
                        .writeClient(directory,
                                LocalTlsFixture.material("expired-client", fixture.ca, false, null, true, "secp256r1"));
                case "malformed-key" -> Files.writeString(directory.resolve("tls.key"), "PRIVATE_CANARY");
                case "extra-key" -> Files
                        .writeString(directory.resolve("tls.key"), Files.readString(directory.resolve("tls.key"))
                                + Files.readString(directory.resolve("tls.key")));
                case "too-large-key" -> Files.write(directory.resolve("tls.key"), new byte[65537]);
                case "nonca" -> LocalTlsFixture
                        .writePem(directory.resolve("ca.pem"), "CERTIFICATE",
                                fixture.client.certificate().getEncoded());
                case "split-revision" -> {
                    Path revision = Files.createDirectory(directory.resolve("revision"));
                    Files.move(directory.resolve("tls.key"), revision.resolve("tls.key"));
                    Files.createSymbolicLink(directory.resolve("tls.key"), Path.of("revision/tls.key"));
                }
                case "empty-ca" -> Files.write(directory.resolve("ca.pem"), new byte[0]);
                case "missing-footer" ->
                    Files.writeString(directory.resolve("tls.key"), "-----BEGIN PRIVATE KEY-----\nAAAA");
                case "bad-base64" -> Files
                        .writeString(directory.resolve("tls.key"),
                                "-----BEGIN PRIVATE KEY-----\n%%%\n-----END PRIVATE KEY-----");
                case "too-many-certificates" -> Files
                        .writeString(directory.resolve("tls.crt"),
                                Files.readString(directory.resolve("tls.crt")).repeat(17));
                case "directory-key" -> {
                    Files.delete(directory.resolve("tls.key"));
                    Files.createDirectory(directory.resolve("tls.key"));
                }
                default -> throw new AssertionError(failure);
            }
            assertEquals(ProxyReply.Outcome.NOT_SENT,
                    new CoreRpcClient(fixture.configuration()).execute(WireBodies.bootstrap()).outcome());
            assertEquals(0, fixture.connections.get());
        }
    }
}
