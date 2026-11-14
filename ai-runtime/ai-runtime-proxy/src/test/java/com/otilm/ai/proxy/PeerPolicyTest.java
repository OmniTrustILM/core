package com.otilm.ai.proxy;

import com.sun.security.auth.module.UnixSystem;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(5)
class PeerPolicyTest {
    private final UnixSystem self = new UnixSystem();
    private final UserPrincipalLookupService lookup = FileSystems.getDefault().getUserPrincipalLookupService();
    private Path directory;

    @BeforeEach
    void createShortSocketDirectory() throws IOException {
        directory = Files.createTempDirectory(Path.of("/tmp").toRealPath(), "ilm-peer-");
    }

    @AfterEach
    void removeSocketDirectory() throws IOException {
        Files.deleteIfExists(directory.resolve("s"));
        Files.deleteIfExists(directory);
    }

    @Test
    void acceptsTheActualLocalUserAndPrimaryGroupFromTheKernel() throws Exception {
        try (var pair = SocketPair.open(directory.resolve("s"))) {
            assertTrue(new PeerPolicy(selfUser(), selfGroup()).allowed(pair.peer()));
        }
    }

    @Test
    void deniesADifferentExpectedUserEvenWhenTheGroupMatches() throws Exception {
        UserPrincipal other = lookup.lookupPrincipalByName(Long.toString(self.getUid() == 0 ? 65532 : 0));
        try (var pair = SocketPair.open(directory.resolve("s"))) {
            assertFalse(new PeerPolicy(other, selfGroup()).allowed(pair.peer()));
        }
    }

    @Test
    void deniesADifferentExpectedGroupEvenWhenTheUserMatches() throws Exception {
        GroupPrincipal other = lookup.lookupPrincipalByGroupName(Long.toString(self.getGid() == 0 ? 65532 : 0));
        try (var pair = SocketPair.open(directory.resolve("s"))) {
            assertFalse(new PeerPolicy(selfUser(), other).allowed(pair.peer()));
        }
    }

    @Test
    void fixedRunnerDeniesThisProcessUnlessBothActualIdsAreTheFixedRunnerIds() throws Exception {
        try (var pair = SocketPair.open(directory.resolve("s"))) {
            assertEquals(self.getUid() == 65532 && self.getGid() == 65532,
                    PeerPolicy.fixedRunner().allowed(pair.peer()));
        }
    }

    @Test
    void closedOrUnconnectedUnixSocketsNeverSatisfyThePeerCheck() throws Exception {
        PeerPolicy policy = new PeerPolicy(selfUser(), selfGroup());
        try (var channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            assertFalse(policy.allowed(channel));
            channel.close();
            assertFalse(policy.allowed(channel));
        }
    }

    @Test
    void unsupportedSocketFamilyAndMissingChannelFailClosed() throws Exception {
        PeerPolicy policy = new PeerPolicy(selfUser(), selfGroup());
        try (var listener = ServerSocketChannel.open(StandardProtocolFamily.INET)) {
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 1);
            try (var client = SocketChannel.open(listener.getLocalAddress()); var peer = listener.accept()) {
                assertFalse(policy.allowed(peer));
            }
        }
        assertFalse(policy.allowed(null));
    }

    @Test
    void missingExpectedIdentityFailsAtConfigurationTime() throws Exception {
        UserPrincipal user = selfUser();
        GroupPrincipal group = selfGroup();
        assertThrows(NullPointerException.class, () -> new PeerPolicy(null, group));
        assertThrows(NullPointerException.class, () -> new PeerPolicy(user, null));
    }

    private UserPrincipal selfUser() throws IOException {
        return lookup.lookupPrincipalByName(Long.toString(self.getUid()));
    }

    private GroupPrincipal selfGroup() throws IOException {
        return lookup.lookupPrincipalByGroupName(Long.toString(self.getGid()));
    }

    private record SocketPair(Path path, ServerSocketChannel listener, SocketChannel client,
            SocketChannel peer) implements AutoCloseable {
        static SocketPair open(Path path) throws IOException {
            var listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
            var client = SocketChannel.open(StandardProtocolFamily.UNIX);
            try {
                listener.bind(UnixDomainSocketAddress.of(path), 1);
                client.connect(UnixDomainSocketAddress.of(path));
                return new SocketPair(path, listener, client, listener.accept());
            } catch (IOException failure) {
                client.close();
                listener.close();
                throw failure;
            }
        }

        @Override
        public void close() throws IOException {
            try (listener; client; peer) {
                // Each descriptor has one test owner.
            } finally {
                Files.deleteIfExists(path);
            }
        }
    }
}
