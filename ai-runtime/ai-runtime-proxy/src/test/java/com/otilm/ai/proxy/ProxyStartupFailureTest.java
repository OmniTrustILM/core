package com.otilm.ai.proxy;

import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(5)
class ProxyStartupFailureTest {
    @Test
    void anActualUnixBindFailureHasAControlledReasonAndLeavesThePrivateDirectoryReusable() throws Exception {
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-bind-");
        Path tooLong = directory.resolve("s".repeat(200));
        var configuration = new ProxyConfiguration(URI.create("https://core.test"), InetAddress.getLoopbackAddress(),
                directory.resolve("tls.crt"), directory.resolve("tls.key"), directory.resolve("ca.pem"));
        var self = new com.sun.security.auth.module.UnixSystem();
        var lookup = directory.getFileSystem().getUserPrincipalLookupService();
        var peer = new PeerPolicy(lookup.lookupPrincipalByName(Long.toString(self.getUid())),
                lookup.lookupPrincipalByGroupName(Long.toString(self.getGid())));
        try {
            var failure = assertThrows(java.io.IOException.class,
                    () -> new ProxyServer(tooLong, configuration, peer, () -> new WorkerProcess(configuration)));
            assertEquals("SOCKET_PROFILE", failure.getMessage());
            assertFalse(Files.exists(tooLong));
            try (var recovered = new ProxyServer(directory.resolve("s"), configuration, peer,
                    () -> new WorkerProcess(configuration))) {
                assertTrue(recovered.healthy());
                assertTrue(Files.exists(directory.resolve("s")));
            }
            assertFalse(Files.exists(directory.resolve("s")));
        } finally {
            Files.deleteIfExists(tooLong);
            Files.deleteIfExists(directory.resolve("s"));
            Files.deleteIfExists(directory);
        }
    }
}
