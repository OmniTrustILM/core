package com.otilm.ai.proxy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Timeout(5)
class ProxyStartupFailureTest {
    @Test
    void leavesDirectoryReusable_whenUnixBindFails() throws Exception {
        // given
        Path directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-bind-");
        Path tooLongSocket = directory.resolve("s".repeat(200));
        Path reusableSocket = directory.resolve("s");
        var configuration = new ProxyConfiguration(URI.create("https://core.test"), InetAddress.getLoopbackAddress(),
                directory.resolve("tls.crt"), directory.resolve("tls.key"), directory.resolve("ca.pem"));
        var self = new com.sun.security.auth.module.UnixSystem();
        var lookup = directory.getFileSystem().getUserPrincipalLookupService();
        var peer = new PeerPolicy(lookup.lookupPrincipalByName(Long.toString(self.getUid())),
                lookup.lookupPrincipalByGroupName(Long.toString(self.getGid())));
        try {
            // when
            ThrowingCallable bindTooLongSocket = () -> new ProxyServer(tooLongSocket, configuration, peer,
                    () -> new WorkerProcess(configuration));

            // then
            assertThatThrownBy(bindTooLongSocket)
                    .isInstanceOfSatisfying(IOException.class, e -> assertThat(e).hasMessage("SOCKET_PROFILE"));
            assertThat(tooLongSocket).doesNotExist();

            // when
            try (ProxyServer recovered = new ProxyServer(reusableSocket, configuration, peer,
                    () -> new WorkerProcess(configuration))) {
                // then
                assertThat(recovered.healthy()).isTrue();
                assertThat(reusableSocket).exists();
            }
            assertThat(reusableSocket).doesNotExist();
        } finally {
            Files.deleteIfExists(tooLongSocket);
            Files.deleteIfExists(reusableSocket);
            Files.deleteIfExists(directory);
        }
    }
}
